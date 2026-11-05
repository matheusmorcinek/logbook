package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

type Item struct {
	Name      string    `json:"name,omitempty"`
	Value     string    `json:"value"`
	Detail    string    `json:"detail,omitempty"`
	Sev       string    `json:"sev,omitempty"`
	Note      string    `json:"note,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

type State struct {
	Baseline time.Time                  `json:"baseline"`
	Updated  time.Time                  `json:"updated"`
	Sections map[string]map[string]Item `json:"sections"`
}

type Section struct {
	Name    string
	Label   string
	Noun    string
	Collect func() (map[string]Item, error)
	// Severity for added / removed / changed items.
	Add, Remove, Change string
}

var sections = []Section{
	{"enrollment", "MDM status", "MDM enrollment", collectEnrollment, "alert", "alert", "alert"},
	{"profiles", "Profiles", "Profile", collectProfiles, "notice", "notice", "notice"},
	{"users", "Users", "User account", collectUsers, "alert", "alert", "notice"},
	{"admins", "Admins", "Admin", collectAdmins, "alert", "notice", "notice"},
	{"certificates", "Certificates", "Certificate", collectCertificates, "notice", "info", "info"},
	{"system_extensions", "Extensions", "System extension", collectSystemExtensions, "notice", "notice", "info"},
	{"background_items", "Background", "Background service", collectLaunchd, "notice", "notice", "notice"},
	{"managed_preferences", "Managed prefs", "Managed setting", collectManagedPrefs, "info", "info", "info"},
	{"apps", "Apps", "App", collectApps, "notice", "notice", "info"},
	{"packages", "Packages", "Package", collectPackages, "notice", "info", "info"},
}

func sectionByName(name string) *Section {
	for i := range sections {
		if sections[i].Name == name {
			return &sections[i]
		}
	}
	return nil
}

func (it Item) display(key string) string {
	if it.Name != "" {
		return it.Name
	}
	return key
}

// diffSection compares a fresh collection against the previous one and returns events.
func diffSection(sec Section, old, cur map[string]Item, now time.Time) []Event {
	var evs []Event
	keys := make([]string, 0, len(cur)+len(old))
	for k := range cur {
		keys = append(keys, k)
	}
	for k := range old {
		if _, ok := cur[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		o, had := old[k]
		c, has := cur[k]
		var ev Event
		switch {
		case has && !had:
			ev = Event{Action: "added", Severity: maxSev(sec.Add, c.Sev),
				Title:  fmt.Sprintf("%s added: %s", sec.Noun, withValue(c.display(k), c.Value, sec)),
				Detail: itemDetail(sec, k, c)}
			if c.Note != "" {
				ev.Title += " (" + c.Note + ")"
			}
		case had && !has:
			ev = Event{Action: "removed", Severity: sec.Remove,
				Title:  fmt.Sprintf("%s removed: %s", sec.Noun, withValue(o.display(k), o.Value, sec)),
				Detail: itemDetail(sec, k, o)}
		case had && has && o.Value != c.Value:
			ev = Event{Action: "changed", Severity: maxSev(sec.Change, c.Sev),
				Title:  fmt.Sprintf("%s changed: %s", sec.Noun, changeText(k, o, c, sec)),
				Detail: itemDetail(sec, k, c) + "\n\nBefore:\n" + o.Detail}
			if c.Note != "" && c.Note != o.Note {
				ev.Title += " (" + c.Note + ")"
			}
		default:
			continue
		}
		ev.Time, ev.Source, ev.Kind = now, "inventory", sec.Name
		evs = append(evs, ev)
	}
	return evs
}

// Sections whose value is a content hash: showing it in titles would be noise.
func hashValued(sec Section) bool {
	switch sec.Name {
	case "profiles", "background_items", "managed_preferences", "admins", "certificates":
		return true
	}
	return false
}

func withValue(name, value string, sec Section) string {
	if sec.Name == "enrollment" {
		return value
	}
	if hashValued(sec) || value == "" || value == "?" {
		return name
	}
	return name + " " + value
}

func changeText(key string, o, c Item, sec Section) string {
	if sec.Name == "enrollment" {
		return fmt.Sprintf("%s → %s", o.Value, c.Value)
	}
	if hashValued(sec) {
		return c.display(key) + " (content changed)"
	}
	return fmt.Sprintf("%s %s → %s", c.display(key), o.Value, c.Value)
}

func itemDetail(sec Section, key string, it Item) string {
	var lines []string
	if !strings.Contains(it.Detail, key) {
		lines = append(lines, key)
	}
	// Hash values only detect changes; they mean nothing to a reader.
	if !hashValued(sec) && it.Value != "" && it.Value != key && !strings.Contains(it.Detail, it.Value) {
		lines = append(lines, "Value: "+it.Value)
	}
	if it.Detail != "" {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, it.Detail)
	}
	return strings.Join(lines, "\n")
}

// runSnapshot collects every section, records changes as events and updates the state.
func runSnapshot(st *State, now time.Time) (evs []Event, errs []string) {
	if st.Sections == nil {
		st.Sections = map[string]map[string]Item{}
	}
	first := st.Baseline.IsZero()
	if first {
		st.Baseline = now
	}
	var baselined []string
	for _, sec := range sections {
		cur, err := sec.Collect()
		if err != nil {
			// Keep the previous data: a failed collection must not look like "everything removed".
			errs = append(errs, fmt.Sprintf("%s: %v", sec.Name, err))
			continue
		}
		old, seen := st.Sections[sec.Name]
		for k, it := range cur {
			if o, ok := old[k]; ok {
				it.FirstSeen = o.FirstSeen
			} else {
				it.FirstSeen = now
			}
			cur[k] = it
		}
		if !seen {
			baselined = append(baselined, fmt.Sprintf("%d %s", len(cur), strings.ToLower(sec.Label)))
		} else {
			evs = append(evs, diffSection(sec, old, cur, now)...)
		}
		st.Sections[sec.Name] = cur
	}
	st.Updated = now
	if len(baselined) > 0 {
		title := "Initial snapshot saved"
		if !first {
			title = "Initial snapshot saved for new sections"
		}
		evs = append([]Event{{Time: now, Source: "logbook", Kind: "snapshot", Action: "info", Severity: "info",
			Title: title, Detail: "Current state saved as the starting point: " + strings.Join(baselined, ", ") +
				".\nFrom now on, anything added, removed or changed is logged."}}, evs...)
	}
	return evs, errs
}

func shortHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:12]
}

func run(name string, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s: %v %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func isRoot() bool { return os.Geteuid() == 0 }

// ---- collectors ----

func collectEnrollment() (map[string]Item, error) {
	out, err := run("/usr/bin/profiles", "status", "-type", "enrollment")
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	return map[string]Item{"status": {Name: "MDM status", Value: strings.Join(parts, " · ")}}, nil
}

func collectUsers() (map[string]Item, error) {
	out, err := run("/usr/bin/dscl", ".", "list", "/Users", "UniqueID")
	if err != nil {
		return nil, err
	}
	m := map[string]Item{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(f[0], "_") {
			continue
		}
		m[f[0]] = Item{Value: "uid " + f[1]}
	}
	return m, nil
}

func collectAdmins() (map[string]Item, error) {
	out, err := run("/usr/bin/dscl", ".", "read", "/Groups/admin", "GroupMembership")
	if err != nil {
		return nil, err
	}
	m := map[string]Item{}
	for _, u := range strings.Fields(strings.TrimPrefix(strings.TrimSpace(out), "GroupMembership:")) {
		m[u] = Item{Value: "admin"}
	}
	return m, nil
}

func collectCertificates() (map[string]Item, error) {
	out, err := run("/usr/bin/security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	if err != nil {
		return nil, err
	}
	return parseCertificates(out), nil
}

var labelRe = regexp.MustCompile(`"labl"<blob>="(.*)"`)

func parseCertificates(out string) map[string]Item {
	m := map[string]Item{}
	var hash string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "SHA-1 hash:") {
			hash = strings.TrimSpace(strings.TrimPrefix(line, "SHA-1 hash:"))
			m[hash] = Item{Name: hash, Value: hash}
		} else if mm := labelRe.FindStringSubmatch(line); mm != nil && hash != "" {
			m[hash] = Item{Name: mm[1], Value: hash, Detail: "SHA-1 " + hash}
		}
	}
	return m
}

func collectSystemExtensions() (map[string]Item, error) {
	out, err := run("/usr/bin/systemextensionsctl", "list")
	if err != nil {
		return nil, err
	}
	return parseSystemExtensions(out), nil
}

var bundleVerRe = regexp.MustCompile(`^(\S+) \((.*)\)$`)

func parseSystemExtensions(out string) map[string]Item {
	m := map[string]Item{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 6 || f[0] == "enabled" {
			continue
		}
		team, bundle, name, state := f[2], f[3], f[4], f[5]
		ver := ""
		if mm := bundleVerRe.FindStringSubmatch(bundle); mm != nil {
			bundle, ver = mm[1], mm[2]
		}
		m[team+" "+bundle] = Item{Name: name, Value: ver + " " + state,
			Detail: fmt.Sprintf("Bundle: %s\nVersion: %s\nTeam ID: %s\nState: %s", bundle, ver, team, state)}
	}
	return m
}

func collectLaunchd() (map[string]Item, error) {
	var files []string
	for _, pat := range []string{"/Library/LaunchDaemons/*.plist", "/Library/LaunchAgents/*.plist", "/Users/*/Library/LaunchAgents/*.plist"} {
		g, _ := filepath.Glob(pat)
		files = append(files, g...)
	}
	m := map[string]Item{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		m[f] = Item{Name: f, Value: shortHash(data), Detail: describeLaunchd(data)}
	}
	return m, nil
}

func describeLaunchd(data []byte) string {
	var p map[string]any
	if _, err := plist.Unmarshal(data, &p); err != nil {
		return ""
	}
	var b strings.Builder
	if v, ok := p["Label"].(string); ok {
		fmt.Fprintf(&b, "Label: %s\n", v)
	}
	if v, ok := p["Program"].(string); ok {
		fmt.Fprintf(&b, "Program: %s\n", v)
	}
	if args, ok := p["ProgramArguments"].([]any); ok {
		parts := make([]string, 0, len(args))
		for _, a := range args {
			parts = append(parts, fmt.Sprint(a))
		}
		fmt.Fprintf(&b, "Runs: %s\n", redact(strings.Join(parts, " ")))
	}
	for _, k := range []string{"RunAtLoad", "KeepAlive", "StartInterval", "UserName"} {
		if v, ok := p[k]; ok {
			fmt.Fprintf(&b, "%s: %v\n", k, v)
		}
	}
	return strings.TrimSpace(b.String())
}

func collectManagedPrefs() (map[string]Item, error) {
	m := map[string]Item{}
	root := "/Library/Managed Preferences"
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".plist") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var v any
		detail := ""
		if _, err := plist.Unmarshal(data, &v); err == nil {
			detail = strings.Join(flatten("", v, 40), "\n")
		}
		m[path] = Item{Name: strings.TrimPrefix(path, root+"/"), Value: shortHash(data), Detail: detail}
		return nil
	})
	return m, nil
}

var appSkip = map[string]bool{
	"/Library/Caches": true, "/Library/Logs": true, "/Library/Developer": true, "/Library/Updates": true,
	"/opt/homebrew": true, "/usr/local/Homebrew": true, "/usr/local/Cellar": true,
}

func collectApps() (map[string]Item, error) {
	roots := []string{"/Applications", "/Library", "/usr/local", "/opt"}
	userApps, _ := filepath.Glob("/Users/*/Applications")
	roots = append(roots, userApps...)
	m := map[string]Item{}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if appSkip[path] {
				return filepath.SkipDir
			}
			if strings.HasSuffix(path, ".app") {
				v := appVersion(path)
				m[path] = Item{Name: strings.TrimSuffix(filepath.Base(path), ".app"), Value: v, Detail: "Path: " + path + "\nVersion: " + v}
				return filepath.SkipDir
			}
			return nil
		})
	}
	return m, nil
}

func appVersion(app string) string {
	data, err := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	if err != nil {
		return "?"
	}
	var p struct {
		Short string `plist:"CFBundleShortVersionString"`
	}
	if _, err := plist.Unmarshal(data, &p); err != nil || p.Short == "" {
		return "?"
	}
	return p.Short
}

// Apple's automatic malware-definition updates churn constantly and are not MDM activity.
var pkgNoise = regexp.MustCompile(`^com\.apple\.pkg\.(XProtect|MRTConfigData)`)

func collectPackages() (map[string]Item, error) {
	var files []string
	for _, dir := range []string{"/var/db/receipts", "/Library/Apple/System/Library/Receipts", "/System/Library/Receipts"} {
		g, _ := filepath.Glob(dir + "/*.plist")
		files = append(files, g...)
	}
	m := map[string]Item{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r struct {
			ID      string    `plist:"PackageIdentifier"`
			Version string    `plist:"PackageVersion"`
			Date    time.Time `plist:"InstallDate"`
		}
		if _, err := plist.Unmarshal(data, &r); err != nil || r.ID == "" || pkgNoise.MatchString(r.ID) {
			continue
		}
		m[r.ID] = Item{Name: r.ID, Value: r.Version, Detail: fmt.Sprintf("Package: %s\nVersion: %s\nInstalled: %s", r.ID, r.Version, r.Date.Local().Format("2006-01-02 15:04"))}
	}
	return m, nil
}

// flatten turns nested plist data into "path = value" lines, capped at limit lines.
func flatten(prefix string, v any, limit int) []string {
	var out []string
	var walk func(p string, v any)
	walk = func(p string, v any) {
		if len(out) >= limit {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				np := k
				if p != "" {
					np = p + "." + k
				}
				walk(np, t[k])
			}
		case []any:
			for i, e := range t {
				walk(fmt.Sprintf("%s[%d]", p, i), e)
			}
		case []byte:
			out = append(out, fmt.Sprintf("%s = <%d bytes>", p, len(t)))
		default:
			val := redact(truncate(fmt.Sprint(t), 120))
			if isSecretKey(p) {
				val = masked
			}
			out = append(out, fmt.Sprintf("%s = %s", p, val))
		}
	}
	walk(prefix, v)
	if len(out) >= limit {
		out = append(out, "…")
	}
	return out
}
