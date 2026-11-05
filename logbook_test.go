package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const profileXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>_computerlevel</key>
	<array>
		<dict>
			<key>ProfileDisplayName</key><string>Rippling Agent Permissions</string>
			<key>ProfileIdentifier</key><string>com.rippling.pppc</string>
			<key>ProfileOrganization</key><string>Acme Inc</string>
			<key>ProfileInstallDate</key><date>2026-11-05T12:00:00Z</date>
			<key>ProfileItems</key>
			<array>
				<dict>
					<key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string>
					<key>PayloadContent</key>
					<dict>
						<key>Services</key>
						<dict>
							<key>SystemPolicyAllFiles</key>
							<array><dict>
								<key>Identifier</key><string>com.rippling.agent</string>
								<key>Authorization</key><string>Allow</string>
							</dict></array>
							<key>ScreenCapture</key>
							<array><dict>
								<key>Identifier</key><string>com.rippling.agent</string>
								<key>Authorization</key><string>AllowStandardUserToSetSystemService</string>
							</dict></array>
						</dict>
					</dict>
				</dict>
			</array>
		</dict>
		<dict>
			<key>ProfileDisplayName</key><string>FileVault</string>
			<key>ProfileIdentifier</key><string>com.rippling.filevault</string>
			<key>ProfileItems</key>
			<array><dict><key>PayloadType</key><string>com.apple.MCX.FileVault2</string>
				<key>PayloadContent</key><dict><key>Enable</key><string>On</string></dict></dict></array>
		</dict>
	</array>
</dict>
</plist>`

func TestParseProfiles(t *testing.T) {
	m, err := parseProfiles([]byte(profileXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(m))
	}
	p := m["com.rippling.pppc"]
	if p.Sev != "alert" || p.Note != "Full Disk Access → com.rippling.agent" {
		t.Errorf("pppc: sev=%q note=%q", p.Sev, p.Note)
	}
	for _, want := range []string{"GRANTS Full Disk Access", "Lets a standard user approve Screen Recording", "Organization: Acme Inc"} {
		if !strings.Contains(p.Detail, want) {
			t.Errorf("detail missing %q:\n%s", want, p.Detail)
		}
	}
	if fv := m["com.rippling.filevault"]; fv.Sev != "info" || fv.Note != "" {
		t.Errorf("filevault: sev=%q note=%q", fv.Sev, fv.Note)
	}
}

func TestDiffSection(t *testing.T) {
	sec := *sectionByName("apps")
	now := time.Now()
	old := map[string]Item{
		"/Applications/A.app": {Name: "A", Value: "1.0"},
		"/Applications/B.app": {Name: "B", Value: "2.0"},
	}
	cur := map[string]Item{
		"/Applications/A.app": {Name: "A", Value: "1.1"},
		"/Applications/C.app": {Name: "C", Value: "3.0"},
	}
	evs := diffSection(sec, old, cur, now)
	got := map[string]string{}
	for _, e := range evs {
		got[e.Title] = e.Severity
	}
	want := map[string]string{
		"App changed: A 1.0 → 1.1": "info",
		"App removed: B 2.0":       "notice",
		"App added: C 3.0":         "notice",
	}
	for title, sev := range want {
		if got[title] != sev {
			t.Errorf("%q: want sev %q, got %q (all: %v)", title, sev, got[title], got)
		}
	}
}

func TestEnrollmentChangeTitle(t *testing.T) {
	evs := diffSection(*sectionByName("enrollment"),
		map[string]Item{"status": {Name: "MDM status", Value: "Enrolled via DEP: No · MDM enrollment: No"}},
		map[string]Item{"status": {Name: "MDM status", Value: "Enrolled via DEP: No · MDM enrollment: Yes (User Approved)"}}, time.Now())
	want := "MDM enrollment changed: Enrolled via DEP: No · MDM enrollment: No → Enrolled via DEP: No · MDM enrollment: Yes (User Approved)"
	if len(evs) != 1 || evs[0].Title != want || evs[0].Severity != "alert" {
		t.Fatalf("got %+v", evs)
	}
}

func TestSnapshotKeepsDataWhenCollectionFails(t *testing.T) {
	saved := sections
	defer func() { sections = saved }()
	fail := false
	sections = []Section{{"apps", "Apps", "App", func() (map[string]Item, error) {
		if fail {
			return nil, os.ErrPermission
		}
		return map[string]Item{"/Applications/A.app": {Name: "A", Value: "1"}}, nil
	}, "notice", "notice", "info"}}

	var st State
	evs, _ := runSnapshot(&st, time.Now())
	if len(evs) != 1 || evs[0].Title != "Initial snapshot saved" {
		t.Fatalf("first run should only record a baseline, got %+v", evs)
	}
	fail = true
	evs, errs := runSnapshot(&st, time.Now())
	if len(evs) != 0 || len(errs) != 1 || len(st.Sections["apps"]) != 1 {
		t.Fatalf("failed collection must not report removals: evs=%v errs=%v", evs, errs)
	}
}

func esLine(t *testing.T, s string) esMessage {
	var m esMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTrackerFollowsAgentChildren(t *testing.T) {
	tr := newTracker([]string{"rippling"})
	now := time.Now()
	lines := []string{
		// launchd's child execs the agent
		`{"process":{"audit_token":{"pid":400},"ppid":1,"executable":{"path":"/sbin/launchd"}},"event":{"exec":{"target":{"audit_token":{"pid":400,"euid":0},"executable":{"path":"/Library/Application Support/Rippling/RipplingAgent"},"signing_id":"com.rippling.agent","team_id":"ABCDE12345"},"args":["/Library/Application Support/Rippling/RipplingAgent"]}}}`,
		// agent forks, child runs a shell script
		`{"process":{"audit_token":{"pid":400},"ppid":1,"executable":{"path":"/Library/Application Support/Rippling/RipplingAgent"},"signing_id":"com.rippling.agent"},"event":{"fork":{"child":{"audit_token":{"pid":401},"ppid":400}}}}`,
		`{"process":{"audit_token":{"pid":401},"ppid":400,"executable":{"path":"/Library/Application Support/Rippling/RipplingAgent"},"signing_id":"com.rippling.agent"},"event":{"exec":{"target":{"audit_token":{"pid":401,"euid":0},"executable":{"path":"/bin/bash"},"signing_id":"com.apple.bash"},"args":["/bin/bash","-c","sysadminctl -addUser rippling-admin"]}}}`,
		// the shell's child, two levels down
		`{"process":{"audit_token":{"pid":401},"ppid":400,"executable":{"path":"/bin/bash"}},"event":{"fork":{"child":{"audit_token":{"pid":402},"ppid":401}}}}`,
		`{"process":{"audit_token":{"pid":402},"ppid":401,"executable":{"path":"/bin/bash"}},"event":{"exec":{"target":{"audit_token":{"pid":402,"euid":0},"executable":{"path":"/usr/sbin/sysadminctl"}},"args":["sysadminctl","-addUser","rippling-admin"]}}}`,
		// an unrelated process must be ignored
		`{"process":{"audit_token":{"pid":900},"ppid":1,"executable":{"path":"/sbin/launchd"}},"event":{"exec":{"target":{"audit_token":{"pid":900},"executable":{"path":"/usr/bin/ls"}},"args":["ls"]}}}`,
		// repeated identical command within 10 minutes is collapsed
		`{"process":{"audit_token":{"pid":402},"ppid":401,"executable":{"path":"/bin/bash"}},"event":{"exec":{"target":{"audit_token":{"pid":402,"euid":0},"executable":{"path":"/usr/sbin/sysadminctl"}},"args":["sysadminctl","-addUser","rippling-admin"]}}}`,
	}
	var evs []*Event
	for _, l := range lines {
		if ev := tr.handle(esLine(t, l), now); ev != nil {
			evs = append(evs, ev)
		}
	}
	if len(evs) != 3 {
		for _, e := range evs {
			t.Log(e.Title)
		}
		t.Fatalf("want 3 events (agent start, bash, sysadminctl), got %d", len(evs))
	}
	if evs[0].Title != "Agent started: com.rippling.agent" {
		t.Errorf("start: %q", evs[0].Title)
	}
	if evs[1].Title != "rippling.agent ran: /bin/bash -c sysadminctl -addUser rippling-admin" {
		t.Errorf("bash: %q", evs[1].Title)
	}
	if evs[2].Severity != "notice" || !strings.Contains(evs[2].Detail, "manages user accounts") || !strings.Contains(evs[2].Detail, "Runs as: root") {
		t.Errorf("sysadminctl: sev=%q detail=%q", evs[2].Severity, evs[2].Detail)
	}
	tr.handle(esLine(t, `{"process":{"audit_token":{"pid":402}},"event":{"exit":{"stat":0}}}`), now)

	// An ad-hoc signed agent ("a.out") is named after its file instead.
	ev := tr.handle(esLine(t, `{"process":{"audit_token":{"pid":500},"ppid":1,"executable":{"path":"/sbin/launchd"}},"event":{"exec":{"target":{"audit_token":{"pid":500},"executable":{"path":"/opt/RipplingAgent"},"signing_id":"a.out"},"args":["RipplingAgent"]}}}`), now)
	if ev == nil || ev.Title != "Agent started: RipplingAgent" {
		t.Errorf("ad-hoc agent: %+v", ev)
	}
	if _, ok := tr.watched[402]; ok {
		t.Error("exited process should be forgotten")
	}
}

func TestMDMParser(t *testing.T) {
	p := &mdmParser{}
	ts := "2026-11-05 10:00:00.000000-0300"
	ev := p.parse(logLine{Timestamp: ts, Message: "Processing server request: DeviceLock  for: <Device>", Process: "/usr/libexec/mdmclient"})
	if ev == nil || ev.Severity != "alert" || !strings.Contains(ev.Title, "LOCKED") {
		t.Fatalf("DeviceLock not recognized: %+v", ev)
	}
	if p.parse(logLine{Timestamp: ts, Message: "Processing server request: DeviceLock  for: <Device>"}) != nil {
		t.Error("duplicate within 30s should be collapsed")
	}
	if p.parse(logLine{Timestamp: ts, Message: "Loaded Settings bundle"}) != nil {
		t.Error("command name without request/command context should be ignored")
	}
	ev = p.parse(logLine{Timestamp: ts, Message: "Received request InstallEnterpriseApplication"})
	if ev == nil || !strings.Contains(ev.Title, "InstallEnterpriseApplication") {
		t.Fatalf("longest command name should win: %+v", ev)
	}
}

// A real line captured from "log stream --style ndjson" on macOS 15.
const realLogLine = `{"timezoneName":"","messageType":"Default","eventType":"logEvent","subsystem":"","category":"","processImagePath":"\/usr\/bin\/logger","timestamp":"2026-11-04 22:30:56.505585-0300","eventMessage":"logbook test message InstallProfile request","processID":65775}`

func TestRealLogLine(t *testing.T) {
	var l logLine
	if err := json.Unmarshal([]byte(realLogLine), &l); err != nil {
		t.Fatal(err)
	}
	ev := (&mdmParser{}).parse(l)
	if ev == nil || !strings.HasPrefix(ev.Title, "MDM: InstallProfile") {
		t.Fatalf("got %+v", ev)
	}
	if want := time.Date(2026, 11, 5, 1, 30, 56, 505585000, time.UTC); !ev.Time.Equal(want) {
		t.Errorf("time %v, want %v", ev.Time, want)
	}
}

func TestParsers(t *testing.T) {
	sx := parseSystemExtensions("3 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.104.4/101.104.4)\tTailscale Network Extension\t[activated enabled]\n")
	it, ok := sx["W5364U7YZB io.tailscale.ipn.macsys.network-extension"]
	if !ok || it.Name != "Tailscale Network Extension" || it.Value != "1.104.4/101.104.4 [activated enabled]" || !strings.Contains(it.Detail, "Version: 1.104.4/101.104.4") {
		t.Errorf("sysext: %+v", sx)
	}
	certs := parseCertificates("keychain: \"/Library/Keychains/System.keychain\"\nSHA-1 hash: ABC123\n    \"labl\"<blob>=\"Corp Root CA\"\n")
	if certs["ABC123"].Name != "Corp Root CA" {
		t.Errorf("certs: %+v", certs)
	}
}

func TestLaunchdPlistIsValid(t *testing.T) {
	path := t.TempDir() + "/test.plist"
	if err := os.WriteFile(path, []byte(fmt.Sprintf(plistTmpl, label, binPath, "/tmp/c.log", "/tmp/c.log")), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestPromptsAreNeutral(t *testing.T) {
	r := row{t: time.Now(), sev: "info", kind: "Process", title: "x ran: ls"}
	for _, p := range []string{explainPrompt(r, nil), summaryPrompt(time.Now(), []row{r})} {
		for _, word := range []string{"MDM", "Rippling", "employer", "owner"} {
			if strings.Contains(p, word) {
				t.Errorf("prompt mentions %q:\n%s", word, p)
			}
		}
	}
}
