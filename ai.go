package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func userCachePath(name string) string {
	dir := os.Getenv("LOGBOOK_CACHE_DIR")
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "logbook")
	}
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, name)
}

func findClaude() (string, error) {
	if p, err := exec.LookPath("claude"); err == nil {
		return p, nil
	}
	home, _ := os.UserHomeDir()
	for _, p := range []string{filepath.Join(home, ".local/bin/claude"), filepath.Join(home, ".claude/local/claude"), "/opt/homebrew/bin/claude", "/usr/local/bin/claude"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("Claude Code (`claude`) is not installed or not on PATH")
}

// askClaude runs the Claude Code CLI with the signed-in (company) account, text only, no tools.
func askClaude(prompt, model string) (string, error) {
	bin, err := findClaude()
	if err != nil {
		return "", err
	}
	args := []string{"-p", "--tools", "", "--no-session-persistence"}
	if model != "" {
		args = append(args, "--model", model)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(prompt)
	// Run outside any project so no project instructions get mixed in.
	cmd.Dir = os.TempDir()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("claude failed: %s", truncate(msg, 300))
	}
	return strings.TrimSpace(out.String()), nil
}

const aiRules = `Write plain text only: no markdown, no headings, no bold. Never use em dashes. Be concrete and calm; do not speculate beyond the data.`

func explainPrompt(r row, context []row) string {
	var b strings.Builder
	b.WriteString(`Below is one entry from a local log that records process activity and settings changes on this Mac. Explain in plain language what it is, what most likely started or caused it (use the details and the nearby entries), and whether it looks routine or worth a closer look. Use 3 to 6 short sentences. ` + aiRules + `
End with a final line that is exactly one of: "Risk: low", "Risk: medium", "Risk: high".

Entry:
`)
	fmt.Fprintf(&b, "Time: %s\nCategory: %s\nSeverity: %s\nTitle: %s\nDetails:\n%s\n", r.when(), r.kind, r.sev, r.title, truncate2(r.detail, 6000))
	if len(context) > 0 {
		b.WriteString("\nOther entries around the same time, for context:\n")
		for _, c := range context {
			fmt.Fprintf(&b, "- %s [%s] %s\n", c.when(), c.sev, c.title)
		}
	}
	return b.String()
}

func summaryPrompt(day time.Time, rows []row) string {
	var b strings.Builder
	fmt.Fprintf(&b, `Below is everything a local log of process activity and settings changes recorded on this Mac on %s. Summarize the day in 5 to 12 short lines starting with "- ": what changed, what was installed or removed, which processes ran and what started them, and anything unusual or worth a closer look. If nothing notable happened, say so. `+aiRules+`

Entries (oldest first):
`, day.Format("Monday, January 2"))
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		fmt.Fprintf(&b, "- %s [%s] %s\n", r.t.Format("15:04"), r.sev, r.title)
	}
	return b.String()
}

func truncate2(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…"
}

type aiCache map[string]string

func loadAICache() aiCache {
	c := aiCache{}
	_ = readJSON(userCachePath("ai.json"), &c)
	return c
}

func (c aiCache) save() { _ = writeJSONAtomic(userCachePath("ai.json"), c) }

type seenState struct {
	LastVisit time.Time `json:"last_visit"`
}

func loadSeen() seenState {
	var s seenState
	_ = readJSON(userCachePath("seen.json"), &s)
	return s
}

func saveSeen(t time.Time) { _ = writeJSONAtomic(userCachePath("seen.json"), seenState{LastVisit: t}) }
