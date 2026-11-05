package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Set at release build time with -ldflags "-X main.version=..."
var version = "dev"

const (
	eventsFile = "events.jsonl"
	stateFile  = "state.json"
	statusFile = "status.json"
	configFile = "config.json"
	mdmRawFile = "mdm-raw.log"
)

type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Source   string    `json:"source"` // inventory | mdm | process | logbook
	Kind     string    `json:"kind"`
	Action   string    `json:"action"`
	Severity string    `json:"severity"` // info | notice | alert
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
}

func sevRank(s string) int {
	switch s {
	case "alert":
		return 2
	case "notice":
		return 1
	}
	return 0
}

func maxSev(a, b string) string {
	if sevRank(b) > sevRank(a) {
		return b
	}
	return a
}

func dataDir() string {
	if d := os.Getenv("LOGBOOK_DIR"); d != "" {
		return d
	}
	return "/Library/Application Support/logbook"
}

func dataPath(name string) string { return filepath.Join(dataDir(), name) }

// prepareDataDir creates the data directory. When running as root the data is made readable by
// admin users only (group admin, gid 80); files created inside inherit the directory's group.
// Symlinks are refused so root never changes ownership of something else.
func prepareDataDir() error {
	dir := dataDir()
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it", dir)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if !isRoot() {
		return nil
	}
	if err := os.Chown(dir, 0, 80); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		_ = os.Lchown(p, 0, 80)
		_ = os.Chmod(p, 0o640)
	}
	return nil
}

type Config struct {
	// Substrings matched case-insensitively against executable paths and signing IDs
	// to decide which processes are "the MDM agent".
	Watch           []string `json:"watch"`
	SnapshotMinutes int      `json:"snapshot_minutes"`
	RetentionDays   int      `json:"retention_days"`
	KeepRawMDMLog   bool     `json:"keep_raw_mdm_log"`
}

// Common MDM agents, matched against executable paths and signing IDs. Edit config.json to change.
var defaultWatch = []string{"rippling", "jamf", "kandji", "mosyle", "intune", "addigy", "hexnode", "air-watch",
	"workspace one", "simplemdm", "fleetdm", "meraki"}

func defaultConfig() Config {
	return Config{
		Watch:           defaultWatch,
		SnapshotMinutes: 10,
		RetentionDays:   30,
	}
}

func loadConfig() Config {
	cfg := defaultConfig()
	data, err := os.ReadFile(dataPath(configFile))
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("config: %v (using defaults)", err)
		return defaultConfig()
	}
	if len(cfg.Watch) == 0 {
		cfg.Watch = defaultWatch
	}
	if cfg.SnapshotMinutes <= 0 {
		cfg.SnapshotMinutes = 10
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	return cfg
}

type Store struct {
	mu  sync.Mutex
	seq uint64
}

func (s *Store) Emit(evs ...Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(dataPath(eventsFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("events: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range evs {
		ev := &evs[i]
		if ev.Time.IsZero() {
			ev.Time = time.Now()
		}
		s.seq++
		ev.ID = fmt.Sprintf("%d-%d", ev.Time.UnixNano(), s.seq)
		if err := enc.Encode(ev); err != nil {
			log.Printf("events: %v", err)
		}
	}
}

// prune drops events older than the retention period.
func (s *Store) prune(days int, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := dataPath(eventsFile)
	evs, err := readEvents(path)
	if err != nil {
		return
	}
	cutoff := now.AddDate(0, 0, -days)
	keep := evs[:0]
	for _, ev := range evs {
		if ev.Time.After(cutoff) {
			keep = append(keep, ev)
		}
	}
	if len(keep) == len(evs) {
		return
	}
	var b strings.Builder
	for _, ev := range keep {
		data, _ := json.Marshal(ev)
		b.Write(data)
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		log.Printf("prune: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("prune: %v", err)
	}
}

func readEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, sc.Err()
}

func rotateIfLarge(path string, limit int64) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > limit {
		_ = os.Rename(path, path+".1")
	}
}

func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

type Status struct {
	PID          int       `json:"pid"`
	Version      string    `json:"version"`
	Root         bool      `json:"root"`
	Started      time.Time `json:"started"`
	Heartbeat    time.Time `json:"heartbeat"`
	Stopped      bool      `json:"stopped"`
	LastSnapshot time.Time `json:"last_snapshot"`
	Process      string    `json:"process"`
	MDMLog       string    `json:"mdm_log"`
}

type statusTracker struct {
	mu sync.Mutex
	s  Status
}

func (t *statusTracker) update(f func(*Status)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(&t.s)
	if err := writeJSONAtomic(dataPath(statusFile), t.s); err != nil {
		log.Printf("status: %v", err)
	}
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
