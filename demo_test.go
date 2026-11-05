package main

import (
	"os"
	"testing"
	"time"
)

// TestWriteDemoData builds a realistic dataset for trying the UI without an enrolled Mac:
//
//	LOGBOOK_DEMO_DIR=/tmp/lb-demo go test -run TestWriteDemoData && LOGBOOK_DIR=/tmp/lb-demo ./logbook
func TestWriteDemoData(t *testing.T) {
	dir := os.Getenv("LOGBOOK_DEMO_DIR")
	if dir == "" {
		t.Skip("set LOGBOOK_DEMO_DIR")
	}
	t.Setenv("LOGBOOK_DIR", dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-28 * time.Hour)
	at := func(h, m int) time.Time { return base.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }

	profiles, err := parseProfiles([]byte(profileXML))
	if err != nil {
		t.Fatal(err)
	}
	for k, it := range profiles {
		it.FirstSeen = at(25, 4)
		profiles[k] = it
	}
	apps := map[string]Item{
		"/Applications/Slack.app":         {Name: "Slack", Value: "4.42.120", Detail: "Path: /Applications/Slack.app", FirstSeen: base},
		"/Applications/Google Chrome.app": {Name: "Google Chrome", Value: "157.0.8089.12", Detail: "Path: /Applications/Google Chrome.app", FirstSeen: at(25, 10)},
		"/Applications/Rippling.app":      {Name: "Rippling", Value: "3.18.2", Detail: "Path: /Applications/Rippling.app", FirstSeen: at(25, 2)},
	}
	users := map[string]Item{
		"matheus":        {Value: "uid 501", FirstSeen: base},
		"rippling-admin": {Value: "uid 499", FirstSeen: at(25, 6)},
	}
	state := State{Baseline: base, Updated: time.Now(), Sections: map[string]map[string]Item{
		"enrollment": {"status": {Name: "MDM status", Value: "Enrolled via DEP: No · MDM enrollment: Yes (User Approved)", FirstSeen: at(25, 1)}},
		"profiles":   profiles,
		"apps":       apps,
		"users":      users,
		"admins":     {"root": {Value: "admin", FirstSeen: base}, "matheus": {Value: "admin", FirstSeen: base}, "rippling-admin": {Value: "admin", FirstSeen: at(25, 6)}},
	}}
	if err := writeJSONAtomic(dataPath(stateFile), state); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(dataPath(eventsFile))

	var evs []Event
	add := func(ts time.Time, list ...Event) {
		for _, e := range list {
			e.Time = ts
			evs = append(evs, e)
		}
	}
	add(base, Event{Source: "logbook", Kind: "snapshot", Action: "info", Severity: "info", Title: "Initial snapshot saved",
		Detail: "Current state saved as the starting point: 1 mdm status, 0 profiles, 1 users, 2 admins, 41 apps, 38 packages.\nFrom now on, anything added, removed or changed is logged."})
	add(at(25, 1), diffSection(*sectionByName("enrollment"),
		map[string]Item{"status": {Name: "MDM status", Value: "Enrolled via DEP: No · MDM enrollment: No"}},
		state.Sections["enrollment"], at(25, 1))...)
	p := &mdmParser{}
	for i, c := range []string{"InstallProfile", "DeviceInformation", "SecurityInfo", "InstalledApplicationList", "InstallEnterpriseApplication", "InstallProfile", "ProfileList"} {
		ts := at(25, 1+i)
		if ev := p.parse(logLine{Timestamp: ts.Format("2006-01-02 15:04:05.000000-0700"), Message: "Processing server request: " + c + "  for: <Device>", Process: "/usr/libexec/mdmclient"}); ev != nil {
			add(ts, *ev)
		}
	}
	add(at(25, 4), diffSection(*sectionByName("profiles"), map[string]Item{}, profiles, at(25, 4))...)
	add(at(25, 2), diffSection(*sectionByName("apps"), map[string]Item{}, map[string]Item{"/Applications/Rippling.app": apps["/Applications/Rippling.app"]}, at(25, 2))...)

	tr := newTracker([]string{"rippling"})
	for i, l := range []string{
		`{"process":{"audit_token":{"pid":400},"ppid":1,"executable":{"path":"/sbin/launchd"}},"event":{"exec":{"target":{"audit_token":{"pid":400,"euid":0},"executable":{"path":"/Applications/Rippling.app/Contents/MacOS/RipplingAgent"},"signing_id":"com.rippling.agent","team_id":"ABCDE12345"},"args":["RipplingAgent"]}}}`,
		`{"process":{"audit_token":{"pid":401},"ppid":400,"executable":{"path":"/Applications/Rippling.app/Contents/MacOS/RipplingAgent"},"signing_id":"com.rippling.agent"},"event":{"exec":{"target":{"audit_token":{"pid":401,"euid":0},"executable":{"path":"/usr/sbin/sysadminctl"}},"args":["sysadminctl","-addUser","rippling-admin","-admin"]}}}`,
		`{"process":{"audit_token":{"pid":402},"ppid":400,"executable":{"path":"/Applications/Rippling.app/Contents/MacOS/RipplingAgent"},"signing_id":"com.rippling.agent"},"event":{"exec":{"target":{"audit_token":{"pid":402,"euid":0},"executable":{"path":"/usr/bin/fdesetup"}},"args":["fdesetup","status"]}}}`,
		`{"process":{"audit_token":{"pid":403},"ppid":400,"executable":{"path":"/Applications/Rippling.app/Contents/MacOS/RipplingAgent"},"signing_id":"com.rippling.agent"},"event":{"exec":{"target":{"audit_token":{"pid":403,"euid":0},"executable":{"path":"/usr/sbin/system_profiler"}},"args":["system_profiler","SPHardwareDataType","-json"]}}}`,
		`{"process":{"audit_token":{"pid":404},"ppid":400,"executable":{"path":"/Applications/Rippling.app/Contents/MacOS/RipplingAgent"},"signing_id":"com.rippling.agent"},"event":{"exec":{"target":{"audit_token":{"pid":404,"euid":0},"executable":{"path":"/usr/sbin/installer"}},"args":["installer","-pkg","/tmp/GoogleChrome.pkg","-target","/"]}}}`,
	} {
		if ev := tr.handle(esLine(t, l), at(25, 2+i*2)); ev != nil {
			add(ev.Time, *ev)
		}
	}
	add(at(25, 6), diffSection(*sectionByName("users"), map[string]Item{"matheus": users["matheus"]}, users, at(25, 6))...)
	add(at(25, 10), diffSection(*sectionByName("apps"), map[string]Item{}, map[string]Item{"/Applications/Google Chrome.app": apps["/Applications/Google Chrome.app"]}, at(25, 10))...)
	for i := 0; i < 6; i++ {
		ts := at(25, 30+i*20)
		add(ts, Event{Source: "mdm", Kind: "command", Action: "received", Severity: "info", Title: "MDM: DeviceInformation - " + mdmCommands["DeviceInformation"].Desc,
			Detail: "Command: DeviceInformation\nMeaning: " + mdmCommands["DeviceInformation"].Desc})
	}
	store := &Store{}
	for i := range evs {
		store.Emit(evs[i])
	}
	if err := writeJSONAtomic(dataPath(statusFile), Status{PID: 1, Version: version, Root: true, Started: base, Heartbeat: time.Now(), LastSnapshot: time.Now(), Process: "running", MDMLog: "running"}); err != nil {
		t.Fatal(err)
	}
	// Pretend the last visit was before the enrollment so it shows up as new.
	t.Setenv("LOGBOOK_CACHE_DIR", dir+"/cache")
	saveSeen(at(25, 5))
}
