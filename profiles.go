package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

func collectProfiles() (map[string]Item, error) {
	args := []string{"show", "-output", "stdout-xml"}
	if isRoot() {
		args = append([]string{"show", "-all"}, args[1:]...)
	}
	out, err := run("/usr/bin/profiles", args...)
	if err != nil {
		return nil, err
	}
	return parseProfiles([]byte(out))
}

// parseProfiles finds every dictionary carrying a ProfileIdentifier, wherever it sits
// (computer level or per user), so it does not depend on the exact top-level layout.
func parseProfiles(data []byte) (map[string]Item, error) {
	var root any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	m := map[string]Item{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if id, ok := t["ProfileIdentifier"].(string); ok {
				m[id] = describeProfile(id, t)
				return
			}
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(root)
	return m, nil
}

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case time.Time:
		return v.Local().Format("2006-01-02 15:04")
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func describeProfile(id string, p map[string]any) Item {
	name := str(p, "ProfileDisplayName")
	if name == "" {
		name = id
	}
	items, _ := p["ProfileItems"].([]any)
	raw, _ := json.Marshal(items)

	var b strings.Builder
	fmt.Fprintf(&b, "Profile: %s\nIdentifier: %s\n", name, id)
	if org := str(p, "ProfileOrganization"); org != "" {
		fmt.Fprintf(&b, "Organization: %s\n", org)
	}
	if d := str(p, "ProfileInstallDate"); d != "" {
		fmt.Fprintf(&b, "Installed: %s\n", d)
	}
	if desc := str(p, "ProfileDescription"); desc != "" {
		fmt.Fprintf(&b, "Description: %s\n", desc)
	}

	sev := "info"
	var notes []string
	b.WriteString("\nWhat it contains:\n")
	for _, it := range items {
		pl, ok := it.(map[string]any)
		if !ok {
			continue
		}
		ptype := str(pl, "PayloadType")
		inf, known := payloadTypes[ptype]
		if !known {
			inf = info{"Settings for " + ptype, "info"}
		}
		sev = maxSev(sev, inf.Sev)
		fmt.Fprintf(&b, "\n• %s\n  %s\n", inf.Desc, ptype)
		content := pl["PayloadContent"]
		if ptype == "com.apple.TCC.configuration-profile-policy" {
			grants := tccGrants(content)
			for _, g := range grants {
				fmt.Fprintf(&b, "  %s\n", g.text)
				sev = maxSev(sev, g.sev)
				if g.sev == "alert" {
					notes = append(notes, g.short)
				}
			}
		}
		if ptype == "com.apple.security.root" {
			notes = append(notes, "trusted root certificate")
		}
		for _, line := range flatten("", content, 15) {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	return Item{Name: name, Value: shortHash(raw), Detail: strings.TrimSpace(b.String()), Sev: sev, Note: strings.Join(notes, ", ")}
}

type grant struct {
	text, short, sev string
}

// tccGrants lists the privacy permissions a PPPC payload grants or denies.
func tccGrants(content any) []grant {
	var services map[string]any
	var find func(v any)
	find = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if s, ok := t["Services"].(map[string]any); ok && services == nil {
				services = s
				return
			}
			for _, e := range t {
				find(e)
			}
		case []any:
			for _, e := range t {
				find(e)
			}
		}
	}
	find(content)
	var out []grant
	names := make([]string, 0, len(services))
	for k := range services {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, svc := range names {
		inf, ok := tccServices[svc]
		if !ok {
			inf = info{svc, "notice"}
		}
		entries, _ := services[svc].([]any)
		for _, e := range entries {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			who := str(em, "Identifier")
			auth := str(em, "Authorization")
			if auth == "" {
				if allowed, ok := em["Allowed"].(bool); ok && allowed {
					auth = "Allow"
				} else if ok {
					auth = "Deny"
				}
			}
			switch auth {
			case "Allow":
				out = append(out, grant{fmt.Sprintf("GRANTS %s to %s", inf.Desc, who), fmt.Sprintf("%s → %s", shortService(svc), who), inf.Sev})
			case "AllowStandardUserToSetSystemService":
				out = append(out, grant{fmt.Sprintf("Lets a standard user approve %s for %s", inf.Desc, who), "", "info"})
			default:
				out = append(out, grant{fmt.Sprintf("Blocks %s for %s", inf.Desc, who), "", "info"})
			}
		}
	}
	return out
}

func shortService(svc string) string {
	if inf, ok := tccServices[svc]; ok {
		if i := strings.Index(inf.Desc, " ("); i > 0 {
			return inf.Desc[:i]
		}
		return inf.Desc
	}
	return svc
}
