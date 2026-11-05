package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

func runService() {
	if err := prepareDataDir(); err != nil {
		log.Fatal(err)
	}
	cfg := loadConfig()
	store := &Store{}
	store.prune(cfg.RetentionDays, time.Now())

	var prev Status
	_ = readJSON(dataPath(statusFile), &prev)
	st := &statusTracker{}
	now := time.Now()
	st.update(func(s *Status) {
		*s = Status{PID: os.Getpid(), Version: version, Root: isRoot(), Started: now, Heartbeat: now}
	})

	start := Event{Source: "logbook", Kind: "service", Action: "started", Severity: "info", Title: "logbook started",
		Detail: fmt.Sprintf("Running as root: %v\nWatching processes matching: %s", isRoot(), strings.Join(cfg.Watch, ", "))}
	// A gap without a clean stop means logbook was killed or the Mac lost power.
	if !prev.Heartbeat.IsZero() && !prev.Stopped && now.Sub(prev.Heartbeat) > 5*time.Minute {
		start.Severity = "notice"
		start.Title = "logbook started after a gap"
		start.Detail += fmt.Sprintf("\n\nNothing was recorded from %s to %s. This happens when the Mac shuts down "+
			"without a clean stop, or when logbook was stopped by something else.",
			prev.Heartbeat.Local().Format("Jan 2 15:04"), now.Format("Jan 2 15:04"))
	}
	store.Emit(start)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	var wg sync.WaitGroup
	for _, f := range []func(context.Context, Config, *Store, *statusTracker){heartbeatLoop, snapshotLoop, mdmLogLoop, processLoop} {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx, cfg, store, st) }()
	}
	<-ctx.Done()
	wg.Wait()
	store.Emit(Event{Source: "logbook", Kind: "service", Action: "stopped", Severity: "info", Title: "logbook stopped"})
	st.update(func(s *Status) { s.Stopped = true; s.Heartbeat = time.Now() })
}

func heartbeatLoop(ctx context.Context, cfg Config, store *Store, st *statusTracker) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	lastPrune := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			st.update(func(s *Status) { s.Heartbeat = now })
			if now.Sub(lastPrune) >= time.Hour {
				store.prune(cfg.RetentionDays, now)
				lastPrune = now
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// ---- inventory snapshots ----

// Directories whose modification time changes when something is installed; checked often
// so new apps and services show up within a minute instead of at the next full snapshot.
var quickWatch = []string{"/Applications", "/Library/LaunchDaemons", "/Library/LaunchAgents", "/Library/Managed Preferences", "/var/db/receipts", "/Library/Apple/System/Library/Receipts", "/var/db/ConfigurationProfiles/Store"}

func dirStamp() string {
	var b strings.Builder
	for _, d := range quickWatch {
		if fi, err := os.Stat(d); err == nil {
			fmt.Fprintf(&b, "%s=%d;", d, fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

func snapshotLoop(ctx context.Context, cfg Config, store *Store, st *statusTracker) {
	var state State
	_ = readJSON(dataPath(stateFile), &state)
	snap := func() {
		evs, errs := runSnapshot(&state, time.Now())
		if err := writeJSONAtomic(dataPath(stateFile), state); err != nil {
			log.Printf("state: %v", err)
		}
		store.Emit(evs...)
		for _, e := range errs {
			log.Printf("snapshot: %s", e)
		}
		st.update(func(s *Status) { s.LastSnapshot = state.Updated })
	}
	snap()
	stamp := dirStamp()
	full := time.Duration(cfg.SnapshotMinutes) * time.Minute
	last := time.Now()
	for sleepCtx(ctx, 30*time.Second) {
		if s := dirStamp(); s != stamp || time.Since(last) >= full {
			// Give installers a moment to finish writing before looking.
			if s != stamp && !sleepCtx(ctx, 10*time.Second) {
				return
			}
			snap()
			stamp, last = dirStamp(), time.Now()
		}
	}
}

func runSnapshotOnce() {
	if err := prepareDataDir(); err != nil {
		log.Fatal(err)
	}
	var state State
	_ = readJSON(dataPath(stateFile), &state)
	evs, errs := runSnapshot(&state, time.Now())
	if err := writeJSONAtomic(dataPath(stateFile), state); err != nil {
		log.Fatal(err)
	}
	(&Store{}).Emit(evs...)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "warning:", e)
	}
	if len(evs) == 0 {
		fmt.Println("no changes since last snapshot")
	}
	for _, ev := range evs {
		fmt.Printf("[%s] %s\n", ev.Severity, ev.Title)
	}
	if !isRoot() {
		fmt.Fprintln(os.Stderr, "note: not running as root, so system-wide profiles are not visible")
	}
}

// ---- MDM command log ----

var mdmCmdRe *regexp.Regexp

func init() {
	names := make([]string, 0, len(mdmCommands))
	for k := range mdmCommands {
		names = append(names, regexp.QuoteMeta(k))
	}
	// Longest first so "InstallEnterpriseApplication" wins over "InstallApplication"-like prefixes.
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	mdmCmdRe = regexp.MustCompile(`\b(` + strings.Join(names, "|") + `)\b`)
}

var mdmContextRe = regexp.MustCompile(`(?i)request|command`)

type logLine struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"eventMessage"`
	Process   string `json:"processImagePath"`
	Subsystem string `json:"subsystem"`
	Category  string `json:"category"`
}

type mdmParser struct {
	last map[string]time.Time
}

// parse turns one unified-log line from mdmclient into an event when it names an MDM command.
// The exact wording macOS uses is not documented, so this matches any known command name
// that appears next to "request" or "command".
func (p *mdmParser) parse(l logLine) *Event {
	m := mdmCmdRe.FindStringSubmatch(l.Message)
	if m == nil || !mdmContextRe.MatchString(l.Message) {
		return nil
	}
	cmd := m[1]
	t, err := time.Parse("2006-01-02 15:04:05.000000-0700", l.Timestamp)
	if err != nil {
		t = time.Now()
	}
	if p.last == nil {
		p.last = map[string]time.Time{}
	}
	if prev, ok := p.last[cmd]; ok && t.Sub(prev) < 30*time.Second {
		return nil
	}
	p.last[cmd] = t
	inf := mdmCommands[cmd]
	return &Event{Time: t, Source: "mdm", Kind: "command", Action: "received", Severity: inf.Sev,
		Title:  fmt.Sprintf("MDM: %s - %s", cmd, inf.Desc),
		Detail: fmt.Sprintf("Command: %s\nMeaning: %s\n\nLog message (%s):\n%s", cmd, inf.Desc, filepath.Base(l.Process), redact(l.Message))}
}

func mdmLogLoop(ctx context.Context, cfg Config, store *Store, st *statusTracker) {
	p := &mdmParser{}
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "/usr/bin/log", "stream", "--style", "ndjson", "--level", "info",
			"--predicate", `process == "mdmclient" OR subsystem == "com.apple.ManagedClient"`)
		out, err := cmd.StdoutPipe()
		var errb bytes.Buffer
		cmd.Stderr = &errb
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			st.update(func(s *Status) { s.MDMLog = "error: " + err.Error() })
			if !sleepCtx(ctx, time.Minute) {
				return
			}
			continue
		}
		st.update(func(s *Status) { s.MDMLog = "running" })
		var raw io.WriteCloser
		if cfg.KeepRawMDMLog {
			raw = openRaw()
		}
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var l logLine
			if json.Unmarshal(sc.Bytes(), &l) != nil || l.Message == "" {
				continue
			}
			if raw != nil {
				fmt.Fprintf(raw, "%s %s: %s\n", l.Timestamp, filepath.Base(l.Process), redact(l.Message))
			}
			if ev := p.parse(l); ev != nil {
				store.Emit(*ev)
			}
		}
		_ = cmd.Wait()
		if raw != nil {
			raw.Close()
		}
		if ctx.Err() != nil {
			return
		}
		msg := strings.TrimSpace(errb.String())
		st.update(func(s *Status) { s.MDMLog = "restarting: " + truncate(msg, 200) })
		if !sleepCtx(ctx, 10*time.Second) {
			return
		}
	}
}

// The raw mdmclient log (opt-in) helps tune command matching against real output.
func openRaw() io.WriteCloser {
	path := dataPath(mdmRawFile)
	rotateIfLarge(path, 20<<20)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil
	}
	return f
}

// ---- processes started by the MDM agent (eslogger) ----

type esToken struct {
	PID  int `json:"pid"`
	EUID int `json:"euid"`
}

type esProcess struct {
	AuditToken  esToken `json:"audit_token"`
	PPID        int     `json:"ppid"`
	Responsible esToken `json:"responsible_audit_token"`
	Executable  struct {
		Path string `json:"path"`
	} `json:"executable"`
	SigningID string `json:"signing_id"`
	TeamID    string `json:"team_id"`
}

type esMessage struct {
	Time    string    `json:"time"`
	Process esProcess `json:"process"`
	Event   struct {
		Exec *struct {
			Target esProcess `json:"target"`
			Args   []string  `json:"args"`
			Cwd    *struct {
				Path string `json:"path"`
			} `json:"cwd"`
		} `json:"exec"`
		Fork *struct {
			Child esProcess `json:"child"`
		} `json:"fork"`
		Exit *struct{} `json:"exit"`
	} `json:"event"`
}

type tracker struct {
	patterns []string
	watched  map[int]string // pid -> name of the agent it descends from
	lastCmd  map[string]time.Time
}

func newTracker(patterns []string) *tracker {
	lower := make([]string, len(patterns))
	for i, p := range patterns {
		lower[i] = strings.ToLower(p)
	}
	return &tracker{patterns: lower, watched: map[int]string{}, lastCmd: map[string]time.Time{}}
}

// Paths under these folders belong to users, not to installed agents, so a folder that happens to
// be called "rippling" is not mistaken for one.
var userPathPrefixes = []string{"/Users/", "/private/tmp/", "/tmp/", "/private/var/folders/", "/Volumes/"}

func (t *tracker) matches(p esProcess) bool {
	id := strings.ToLower(p.SigningID)
	path := strings.ToLower(p.Executable.Path)
	for _, pre := range userPathPrefixes {
		if strings.HasPrefix(path, strings.ToLower(pre)) {
			path = ""
			break
		}
	}
	for _, pat := range t.patterns {
		if pat != "" && (strings.Contains(id, pat) || strings.Contains(path, pat)) {
			return true
		}
	}
	return false
}

// agentName prefers the signing ID, unless it is generic (ad-hoc builds are "a.out") or does not
// contain the watched pattern, in which case the file name explains the match better.
func (t *tracker) agentName(p esProcess) string {
	id := strings.ToLower(p.SigningID)
	for _, pat := range t.patterns {
		if pat != "" && strings.Contains(id, pat) {
			return p.SigningID
		}
	}
	return filepath.Base(p.Executable.Path)
}

// root returns the agent a process belongs to, if any.
func (t *tracker) root(p esProcess) (string, bool) {
	if r, ok := t.watched[p.AuditToken.PID]; ok {
		return r, true
	}
	if t.matches(p) {
		return t.agentName(p), true
	}
	if r, ok := t.watched[p.PPID]; ok {
		return r, true
	}
	if r, ok := t.watched[p.Responsible.PID]; ok && p.Responsible.PID != p.AuditToken.PID {
		return r, true
	}
	return "", false
}

func (t *tracker) handle(m esMessage, now time.Time) *Event {
	switch {
	case m.Event.Fork != nil:
		if r, ok := t.root(m.Process); ok {
			t.watched[m.Event.Fork.Child.AuditToken.PID] = r
		}
	case m.Event.Exit != nil:
		delete(t.watched, m.Process.AuditToken.PID)
	case m.Event.Exec != nil:
		x := m.Event.Exec
		pid := m.Process.AuditToken.PID
		r, ok := t.root(m.Process)
		if !ok {
			if !t.matches(x.Target) {
				return nil
			}
			name := t.agentName(x.Target)
			t.watched[pid] = name
			return &Event{Time: now, Source: "process", Kind: "agent", Action: "started", Severity: "info",
				Title: "Agent started: " + name, Detail: processDetail(m, name)}
		}
		t.watched[pid] = r
		cmdline := redact(strings.Join(x.Args, " "))
		if cmdline == "" {
			cmdline = x.Target.Executable.Path
		}
		// Agents poll the same commands constantly; one entry per command per 10 minutes is enough.
		key := r + "\x00" + cmdline
		if prev, seen := t.lastCmd[key]; seen && now.Sub(prev) < 10*time.Minute {
			return nil
		}
		t.lastCmd[key] = now
		if len(t.lastCmd) > 5000 {
			for k, at := range t.lastCmd {
				if now.Sub(at) >= 10*time.Minute {
					delete(t.lastCmd, k)
				}
			}
		}
		sev, why := "info", ""
		if inf, ok := notableCommands[filepath.Base(x.Target.Executable.Path)]; ok {
			sev, why = inf.Sev, inf.Desc
		}
		title := fmt.Sprintf("%s ran: %s", shortAgent(r), truncate(cmdline, 160))
		detail := processDetail(m, r)
		if why != "" {
			detail = "This command " + why + ".\n\n" + detail
		}
		return &Event{Time: now, Source: "process", Kind: "exec", Action: "ran", Severity: sev, Title: title, Detail: detail}
	}
	return nil
}

// shortAgent drops the reverse-DNS prefix: "com.rippling.agent" -> "rippling.agent".
func shortAgent(name string) string {
	for _, p := range []string{"com.", "io.", "org.", "net.", "co."} {
		if strings.HasPrefix(name, p) && len(name) > len(p) {
			return name[len(p):]
		}
	}
	return name
}

func processDetail(m esMessage, root string) string {
	x := m.Event.Exec
	var b strings.Builder
	fmt.Fprintf(&b, "Started by: %s\n", root)
	fmt.Fprintf(&b, "Program: %s\n", x.Target.Executable.Path)
	if len(x.Args) > 0 {
		fmt.Fprintf(&b, "Command: %s\n", redact(strings.Join(x.Args, " ")))
	}
	user := fmt.Sprintf("uid %d", x.Target.AuditToken.EUID)
	if x.Target.AuditToken.EUID == 0 {
		user = "root"
	}
	fmt.Fprintf(&b, "Runs as: %s\n", user)
	if x.Cwd != nil && x.Cwd.Path != "" {
		fmt.Fprintf(&b, "Working dir: %s\n", x.Cwd.Path)
	}
	fmt.Fprintf(&b, "PID %d, parent PID %d\n", m.Process.AuditToken.PID, m.Process.PPID)
	if x.Target.SigningID != "" || x.Target.TeamID != "" {
		fmt.Fprintf(&b, "Signed as: %s (team %s)\n", x.Target.SigningID, x.Target.TeamID)
	}
	return strings.TrimSpace(b.String())
}

func processLoop(ctx context.Context, cfg Config, store *Store, st *statusTracker) {
	tr := newTracker(cfg.Watch)
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "/usr/bin/eslogger", "exec", "fork", "exit")
		out, err := cmd.StdoutPipe()
		var errb bytes.Buffer
		cmd.Stderr = &errb
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			st.update(func(s *Status) { s.Process = "error: " + err.Error() })
			if !sleepCtx(ctx, time.Minute) {
				return
			}
			continue
		}
		st.update(func(s *Status) { s.Process = "running" })
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 32<<20)
		for sc.Scan() {
			var m esMessage
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			if ev := tr.handle(m, time.Now()); ev != nil {
				store.Emit(*ev)
			}
		}
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		msg := strings.TrimSpace(errb.String())
		if strings.Contains(strings.ToLower(msg), "not permitted") || strings.Contains(msg, "TCC") || strings.Contains(msg, "Full Disk") {
			msg = "needs Full Disk Access (System Settings > Privacy & Security > Full Disk Access > add /usr/local/bin/logbook)"
		} else if !isRoot() {
			msg = "needs root (run through the installed service)"
		}
		st.update(func(s *Status) { s.Process = "stopped: " + truncate(msg, 200) })
		if !sleepCtx(ctx, 30*time.Second) {
			return
		}
	}
}
