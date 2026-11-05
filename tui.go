package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var tabNames = []string{"Timeline", "MDM", "Processes", "Inventory", "Profiles"}

const (
	tabTimeline = iota
	tabMDM
	tabProcesses
	tabInventory
	tabProfiles
)

type row struct {
	t      time.Time
	sev    string
	kind   string
	title  string
	detail string
	key    string
	isNew  bool
	inv    bool
	evID   string
}

func (r row) when() string { return r.t.Local().Format("Mon Jan 2 15:04") }

var (
	cAccent = lipgloss.AdaptiveColor{Light: "#5A3FD9", Dark: "#A78BFA"}
	cAlert  = lipgloss.AdaptiveColor{Light: "#C62828", Dark: "#FF6B6B"}
	cNotice = lipgloss.AdaptiveColor{Light: "#A15C00", Dark: "#F5B942"}
	cInfo   = lipgloss.AdaptiveColor{Light: "#7A7A85", Dark: "#7C7C8A"}
	cOK     = lipgloss.AdaptiveColor{Light: "#1B7F3B", Dark: "#5BD68A"}
	cNew    = lipgloss.AdaptiveColor{Light: "#00728F", Dark: "#4FD1E8"}
	cSelBg  = lipgloss.AdaptiveColor{Light: "#E6E1FA", Dark: "#2E2A45"}
	cFaint  = lipgloss.AdaptiveColor{Light: "#9A9AA5", Dark: "#5C5C68"}

	sTitle   = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sFaint   = lipgloss.NewStyle().Foreground(cFaint)
	sDim     = lipgloss.NewStyle().Foreground(cInfo)
	sBold    = lipgloss.NewStyle().Bold(true)
	sTabOn   = lipgloss.NewStyle().Bold(true).Foreground(cAccent).Underline(true)
	sTabOff  = lipgloss.NewStyle().Foreground(cInfo)
	sNew     = lipgloss.NewStyle().Bold(true).Foreground(cNew)
	sSel     = lipgloss.NewStyle().Background(cSelBg)
	sSection = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
)

func sevStyle(sev string) lipgloss.Style {
	switch sev {
	case "alert":
		return lipgloss.NewStyle().Foreground(cAlert)
	case "notice":
		return lipgloss.NewStyle().Foreground(cNotice)
	}
	return lipgloss.NewStyle().Foreground(cInfo)
}

type model struct {
	w, h        int
	tab         int
	events      []Event
	state       State
	status      Status
	rows        []row
	cursor, top int
	filter      textinput.Model
	filtering   bool
	important   bool
	expanded    bool
	dscroll     int
	help        bool
	ai          aiCache
	busy        map[string]time.Time
	aiErr       map[string]string
	summary     string
	lastVisit   time.Time
	newCount    int
	stamps      map[string]string
	aiModel     string
	host        string
	loadErr     string
}

type tickMsg time.Time
type aiMsg struct {
	key, text string
	err       error
}

func newModel() *model {
	ti := textinput.New()
	ti.Prompt = "/ "
	ti.Placeholder = "filter"
	ti.CharLimit = 80
	m := &model{filter: ti, ai: loadAICache(), busy: map[string]time.Time{}, aiErr: map[string]string{},
		lastVisit: loadSeen().LastVisit, stamps: map[string]string{}, aiModel: loadConfig().AIModel,
		host: computerName(), w: 100, h: 30}
	if _, err := os.ReadDir(dataDir()); err != nil && os.IsPermission(err) {
		m.loadErr = "No permission to read " + dataDir() + ". Recorded data is readable by admin users only."
	}
	m.reload()
	m.buildRows()
	return m
}

func computerName() string {
	if out, err := run("/usr/sbin/scutil", "--get", "ComputerName"); err == nil && strings.TrimSpace(out) != "" {
		return strings.TrimSpace(out)
	}
	h, _ := os.Hostname()
	return strings.TrimSuffix(h, ".local")
}

func runTUI() {
	m := newModel()
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func tick() tea.Cmd { return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }

func (m *model) Init() tea.Cmd { return tick() }

func fileStamp(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d-%d", fi.Size(), fi.ModTime().UnixNano())
}

// reload re-reads the data files that changed and reports whether anything did.
func (m *model) reload() bool {
	changed := false
	if s := fileStamp(dataPath(eventsFile)); s != m.stamps["ev"] {
		m.stamps["ev"] = s
		evs, err := readEvents(dataPath(eventsFile))
		m.loadErr = ""
		if err != nil && !os.IsNotExist(err) {
			m.loadErr = err.Error()
		}
		m.events = evs
		changed = true
	}
	if s := fileStamp(dataPath(stateFile)); s != m.stamps["st"] {
		m.stamps["st"] = s
		m.state = State{}
		_ = readJSON(dataPath(stateFile), &m.state)
		changed = true
	}
	if s := fileStamp(dataPath(statusFile)); s != m.stamps["status"] {
		m.stamps["status"] = s
		m.status = Status{}
		_ = readJSON(dataPath(statusFile), &m.status)
		changed = true
	}
	return changed
}

func eventKind(ev Event) string {
	switch ev.Source {
	case "inventory":
		if s := sectionByName(ev.Kind); s != nil {
			return s.Label
		}
		return ev.Kind
	case "mdm":
		return "MDM"
	case "process":
		return "Process"
	}
	return "logbook"
}

func (m *model) eventRow(ev Event) row {
	return row{t: ev.Time, sev: ev.Severity, kind: eventKind(ev), title: ev.Title, detail: ev.Detail,
		key: "ev:" + ev.ID, evID: ev.ID, isNew: !m.lastVisit.IsZero() && ev.Time.After(m.lastVisit)}
}

func (m *model) buildRows() {
	var keep string
	if m.cursor < len(m.rows) {
		keep = m.rows[m.cursor].key
	}
	var rows []row
	switch m.tab {
	case tabTimeline, tabMDM, tabProcesses:
		src := map[int]string{tabMDM: "mdm", tabProcesses: "process"}[m.tab]
		for i := len(m.events) - 1; i >= 0; i-- {
			if ev := m.events[i]; src == "" || ev.Source == src {
				rows = append(rows, m.eventRow(ev))
			}
		}
		// Log lines carry their own timestamps and can arrive slightly out of order.
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].t.After(rows[j].t) })
	case tabInventory:
		for _, sec := range sections {
			if sec.Name == "profiles" {
				continue
			}
			rows = append(rows, m.itemRows(sec)...)
		}
	case tabProfiles:
		rows = m.itemRows(*sectionByName("profiles"))
	}
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	out := rows[:0]
	for _, r := range rows {
		if m.important && sevRank(r.sev) == 0 && !r.isNew {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(r.title+" "+r.kind+" "+r.detail), q) {
			continue
		}
		out = append(out, r)
	}
	m.rows = out
	m.newCount = 0
	if !m.lastVisit.IsZero() {
		for _, ev := range m.events {
			if ev.Time.After(m.lastVisit) && ev.Source != "logbook" {
				m.newCount++
			}
		}
	}
	m.cursor = 0
	for i, r := range m.rows {
		if r.key == keep {
			m.cursor = i
			break
		}
	}
	m.clamp()
}

func (m *model) itemRows(sec Section) []row {
	items := m.state.Sections[sec.Name]
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(items[keys[i]].display(keys[i])) < strings.ToLower(items[keys[j]].display(keys[j]))
	})
	var rows []row
	for _, k := range keys {
		it := items[k]
		isNew := it.FirstSeen.After(m.state.Baseline)
		sev := it.Sev
		if sev == "" {
			sev = "info"
		}
		if isNew {
			sev = maxSev(sev, "notice")
		}
		title := withValue(it.display(k), it.Value, sec)
		if it.Note != "" {
			title += "  (" + it.Note + ")"
		}
		rows = append(rows, row{t: it.FirstSeen, sev: sev, kind: sec.Label, title: title, detail: itemDetail(sec, k, it),
			key: "inv:" + sec.Name + ":" + k + ":" + it.Value, isNew: isNew, inv: true})
	}
	return rows
}

func (m *model) layout() (listH, detailH int) {
	// header, tabs, details separator and footer take one line each
	avail := m.h - 3
	if m.filtering || m.filter.Value() != "" {
		avail--
	}
	detailH = avail / 3
	if m.expanded || m.help || m.summary != "" {
		detailH = avail * 2 / 3
	}
	if detailH < 5 {
		detailH = 5
	}
	listH = avail - detailH
	if listH < 3 {
		listH = 3
		detailH = avail - listH
	}
	// Few rows: give the unused list space to the details.
	if need := max(len(m.rows), 3); need < listH {
		detailH += listH - need
		listH = need
	}
	return
}

func (m *model) clamp() {
	listH, _ := m.layout()
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+listH {
		m.top = m.cursor - listH + 1
	}
	if m.top < 0 {
		m.top = 0
	}
}

func (m *model) move(n int) {
	m.cursor += n
	m.dscroll = 0
	m.summary = ""
	m.clamp()
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.clamp()
	case tickMsg:
		if m.reload() {
			m.buildRows()
		}
		return m, tick()
	case aiMsg:
		delete(m.busy, msg.key)
		if msg.err != nil {
			m.aiErr[msg.key] = msg.err.Error()
		} else {
			delete(m.aiErr, msg.key)
			m.ai[msg.key] = msg.text
			m.ai.save()
		}
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *model) key(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.filtering {
		switch msg.String() {
		case "enter":
			m.filtering = false
			m.filter.Blur()
		case "esc":
			m.filtering = false
			m.filter.Blur()
			m.filter.SetValue("")
			m.buildRows()
		default:
			var cmd tea.Cmd
			m.filter, cmd = m.filter.Update(msg)
			m.buildRows()
			return m, cmd
		}
		m.clamp()
		return m, nil
	}
	listH, _ := m.layout()
	switch k := msg.String(); k {
	case "q", "ctrl+c":
		saveSeen(time.Now())
		return m, tea.Quit
	case "1", "2", "3", "4", "5":
		m.setTab(int(k[0] - '1'))
	case "tab", "right", "l":
		m.setTab((m.tab + 1) % len(tabNames))
	case "shift+tab", "left", "h":
		m.setTab((m.tab + len(tabNames) - 1) % len(tabNames))
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup", "ctrl+b", "ctrl+u":
		m.move(-listH)
	case "pgdown", "ctrl+f", "ctrl+d", " ":
		m.move(listH)
	case "g", "home":
		m.move(-len(m.rows))
	case "G", "end":
		m.move(len(m.rows))
	case "enter":
		m.expanded = !m.expanded
		m.dscroll = 0
		m.clamp()
	case "J", "shift+down":
		m.dscroll++
	case "K", "shift+up":
		if m.dscroll > 0 {
			m.dscroll--
		}
	case "esc":
		switch {
		case m.help:
			m.help = false
		case m.summary != "":
			m.summary = ""
		case m.expanded:
			m.expanded = false
		case m.filter.Value() != "":
			m.filter.SetValue("")
			m.buildRows()
		}
		m.clamp()
	case "/":
		m.filtering = true
		m.clamp()
		return m, m.filter.Focus()
	case "!":
		m.important = !m.important
		m.buildRows()
	case "?":
		m.help = !m.help
		m.clamp()
	case "r":
		m.stamps = map[string]string{}
		m.reload()
		m.buildRows()
	case "s":
		return m, m.explain()
	case "d":
		return m, m.daySummary()
	}
	return m, nil
}

func (m *model) setTab(t int) {
	m.tab, m.cursor, m.top, m.dscroll, m.summary = t, 0, 0, 0, ""
	m.buildRows()
}

func (m *model) explain() tea.Cmd {
	if m.cursor >= len(m.rows) {
		return nil
	}
	r := m.rows[m.cursor]
	m.summary, m.help = "", false
	delete(m.aiErr, r.key)
	if _, ok := m.ai[r.key]; ok {
		return nil
	}
	if _, ok := m.busy[r.key]; ok {
		return nil
	}
	m.busy[r.key] = time.Now()
	prompt, model := explainPrompt(r, m.contextFor(r)), m.aiModel
	return func() tea.Msg {
		text, err := askClaude(prompt, model)
		return aiMsg{r.key, text, err}
	}
}

// contextFor returns up to 10 other events close in time to an event row.
func (m *model) contextFor(r row) []row {
	if r.evID == "" {
		return nil
	}
	var near []Event
	for _, ev := range m.events {
		d := ev.Time.Sub(r.t)
		if ev.ID != r.evID && d > -30*time.Minute && d < 30*time.Minute {
			near = append(near, ev)
		}
	}
	sort.Slice(near, func(i, j int) bool { return absDur(near[i].Time.Sub(r.t)) < absDur(near[j].Time.Sub(r.t)) })
	if len(near) > 10 {
		near = near[:10]
	}
	sort.Slice(near, func(i, j int) bool { return near[i].Time.Before(near[j].Time) })
	out := make([]row, len(near))
	for i, ev := range near {
		out[i] = m.eventRow(ev)
	}
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (m *model) daySummary() tea.Cmd {
	now := time.Now()
	y, mo, d := now.Date()
	start := time.Date(y, mo, d, 0, 0, 0, 0, now.Location())
	var rows []row
	for i := len(m.events) - 1; i >= 0 && len(rows) < 400; i-- {
		if ev := m.events[i]; ev.Time.After(start) && ev.Source != "logbook" {
			rows = append(rows, m.eventRow(ev))
		}
	}
	key := fmt.Sprintf("day:%s:%d", start.Format("2006-01-02"), len(rows))
	m.summary, m.help = key, false
	m.clamp()
	delete(m.aiErr, key)
	if len(rows) == 0 {
		m.ai[key] = "Nothing was recorded today yet."
		return nil
	}
	if _, ok := m.ai[key]; ok {
		return nil
	}
	if _, ok := m.busy[key]; ok {
		return nil
	}
	m.busy[key] = now
	prompt, model := summaryPrompt(start, rows), m.aiModel
	return func() tea.Msg {
		text, err := askClaude(prompt, model)
		return aiMsg{key, text, err}
	}
}

// ---- view ----

func pad(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	if n := lipgloss.Width(s); n < w {
		s += strings.Repeat(" ", w-n)
	}
	return s
}

func (m *model) View() string {
	if m.w < 40 || m.h < 12 {
		return "logbook: window too small"
	}
	var b strings.Builder
	b.WriteString(m.viewHeader() + "\n")
	b.WriteString(m.viewTabs() + "\n")
	if m.filtering || m.filter.Value() != "" {
		b.WriteString(pad(" "+m.filter.View(), m.w) + "\n")
	}
	listH, detailH := m.layout()
	b.WriteString(m.viewList(listH))
	b.WriteString(m.viewDetail(detailH))
	b.WriteString(m.viewFooter())
	return b.String()
}

func (m *model) viewHeader() string {
	right := ""
	if m.newCount > 0 {
		right = sNew.Render(fmt.Sprintf("%d new", m.newCount)) + sDim.Render(" since "+m.lastVisit.Local().Format("Mon 15:04")) + " "
	} else if !m.lastVisit.IsZero() {
		right = sDim.Render("nothing new since "+m.lastVisit.Local().Format("Mon 15:04")) + " "
	}
	// Drop the computer name before anything else when the window is narrow.
	for _, host := range []string{m.host, ""} {
		left := m.headerLeft(host)
		if gap := m.w - lipgloss.Width(left) - lipgloss.Width(right); gap >= 1 {
			return left + strings.Repeat(" ", gap) + right
		}
	}
	return pad(m.headerLeft(""), m.w)
}

func (m *model) headerLeft(host string) string {
	left := sTitle.Render(" logbook")
	if host != "" {
		left += sFaint.Render(" · ") + host
	}
	if v := m.state.Sections["enrollment"]["status"].Value; v != "" {
		if strings.Contains(v, "MDM enrollment: Yes") {
			left += sFaint.Render(" · ") + lipgloss.NewStyle().Foreground(cNotice).Render("MDM enrolled")
		} else {
			left += sFaint.Render(" · ") + sDim.Render("no MDM")
		}
	}
	return left + sFaint.Render(" · ") + m.serviceState()
}

func (m *model) serviceState() string {
	st := m.status
	switch {
	case st.Heartbeat.IsZero():
		return lipgloss.NewStyle().Foreground(cAlert).Render("logbook not running")
	case st.Stopped:
		return lipgloss.NewStyle().Foreground(cAlert).Render("logbook stopped " + st.Heartbeat.Local().Format("Jan 2 15:04"))
	case time.Since(st.Heartbeat) > 2*time.Minute:
		return lipgloss.NewStyle().Foreground(cAlert).Render("no heartbeat since " + st.Heartbeat.Local().Format("Jan 2 15:04"))
	case !strings.HasPrefix(st.Process, "running"):
		return lipgloss.NewStyle().Foreground(cNotice).Render("● process tracking off")
	}
	return lipgloss.NewStyle().Foreground(cOK).Render("●")
}

func (m *model) viewTabs() string {
	var parts []string
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if i == m.tab {
			parts = append(parts, sTabOn.Render(label))
		} else {
			parts = append(parts, sTabOff.Render(label))
		}
	}
	left := " " + strings.Join(parts, "   ")
	noun := "items"
	if len(m.rows) == 1 {
		noun = "item"
	}
	right := sDim.Render(fmt.Sprintf("%d %s", len(m.rows), noun))
	if m.important {
		right = lipgloss.NewStyle().Foreground(cNotice).Render("important only") + sFaint.Render(" · ") + right
	}
	right += " "
	gap := m.w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return pad(left, m.w)
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m *model) viewList(h int) string {
	var b strings.Builder
	if len(m.rows) == 0 {
		msg := "Nothing here yet."
		switch {
		case m.loadErr != "":
			msg = m.loadErr
		case m.filter.Value() != "" || m.important:
			msg = "No entries match the current filter."
		case len(m.events) == 0 && m.state.Baseline.IsZero():
			msg = "No data yet. Install with `sudo logbook install`, then check `logbook status`."
		case m.tab == tabMDM:
			msg = "No MDM commands recorded yet. They appear here once the Mac is enrolled."
		case m.tab == tabProcesses:
			msg = "No processes from the MDM agent recorded yet."
		case m.tab == tabProfiles:
			msg = "No configuration profiles installed."
		}
		b.WriteString(pad("  "+sDim.Render(msg), m.w) + "\n")
		for i := 1; i < h; i++ {
			b.WriteString("\n")
		}
		return b.String()
	}
	kindW := 13
	for i := m.top; i < m.top+h; i++ {
		if i >= len(m.rows) {
			b.WriteString("\n")
			continue
		}
		r := m.rows[i]
		when := r.t.Local().Format("Jan 02 15:04")
		if r.inv && !r.isNew {
			when = "initial"
		}
		badge := "    "
		if r.isNew {
			badge = sNew.Render("NEW ")
		}
		dot := sevStyle(r.sev).Render("●")
		title := r.title
		if r.sev == "alert" {
			title = sevStyle("alert").Render(title)
		}
		line := fmt.Sprintf(" %s %s %s %s%s", sDim.Render(pad(when, 12)), dot, sDim.Render(pad(r.kind, kindW)), badge, title)
		if i == m.cursor {
			line = sSel.Render(pad(sBold.Render("›")+line, m.w))
		} else {
			line = pad(" "+line, m.w)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m *model) viewDetail(h int) string {
	label := " details "
	var body string
	switch {
	case m.help:
		label, body = " keys ", helpText
	case m.summary != "":
		label = " today's summary · Claude "
		body = m.aiBody(m.summary, "Summarizing today's activity with Claude…")
	case m.cursor < len(m.rows):
		r := m.rows[m.cursor]
		var b strings.Builder
		b.WriteString(sBold.Render(r.title) + "\n")
		meta := r.when() + " · " + r.kind + " · " + sevStyle(r.sev).Render(r.sev)
		if r.inv {
			meta = "first seen " + r.when() + " · " + r.kind
			if !r.isNew {
				meta = "present since the initial snapshot · " + r.kind
			}
		}
		if r.isNew {
			meta += " · " + sNew.Render("new")
		}
		b.WriteString(sDim.Render(meta) + "\n\n")
		_, asked := m.ai[r.key]
		_, busy := m.busy[r.key]
		_, failed := m.aiErr[r.key]
		if asked || busy || failed {
			b.WriteString(sSection.Render("Claude") + "\n")
			b.WriteString(m.aiBody(r.key, "Asking Claude to explain this entry…") + "\n\n")
			b.WriteString(sSection.Render("Details") + "\n")
			b.WriteString(r.detail)
		} else {
			b.WriteString(r.detail + "\n\n")
			b.WriteString(sDim.Render("Press s to ask Claude to explain this entry."))
		}
		body = b.String()
	default:
		body = sDim.Render("Select an entry to see its details.")
	}
	sepW := m.w - lipgloss.Width(label) - 2
	if sepW < 0 {
		sepW = 0
	}
	out := sFaint.Render("──") + sSection.Render(label) + sFaint.Render(strings.Repeat("─", sepW)) + "\n"

	wrapped := lipgloss.NewStyle().Width(m.w - 4).Render(body)
	lines := strings.Split(wrapped, "\n")
	maxScroll := len(lines) - (h - 1)
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.dscroll > maxScroll {
		m.dscroll = maxScroll
	}
	lines = lines[m.dscroll:]
	for i := 0; i < h-1; i++ {
		l := ""
		if i < len(lines) {
			l = "  " + lines[i]
		}
		if i == h-2 && len(lines) > h-1 {
			l = "  " + sFaint.Render("… more below (J / K to scroll, enter to expand)")
		}
		out += pad(l, m.w) + "\n"
	}
	return out
}

func (m *model) aiBody(key, waiting string) string {
	if text, ok := m.ai[key]; ok {
		return text
	}
	if started, ok := m.busy[key]; ok {
		return sDim.Render(fmt.Sprintf("%s %ds", waiting, int(time.Since(started).Seconds())))
	}
	if err, ok := m.aiErr[key]; ok {
		return lipgloss.NewStyle().Foreground(cAlert).Render(err)
	}
	return ""
}

func (m *model) viewFooter() string {
	keys := [][2]string{{"↑↓", "move"}, {"enter", "expand"}, {"s", "explain"}, {"d", "today"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"}, {"!", "important"}, {"1-5", "tabs"}}
	sep := sFaint.Render(" · ")
	line := ""
	for _, k := range keys {
		part := sBold.Render(k[0]) + " " + sDim.Render(k[1])
		if line != "" {
			part = sep + part
		}
		if lipgloss.Width(line+part)+1 > m.w {
			break
		}
		line += part
	}
	return pad(" "+line, m.w)
}

const helpText = `↑ ↓ / j k      move              enter      expand or shrink the details
pgup pgdn      page              J K        scroll the details
g G            first / last      esc        close / clear
1-5 tab ← →    switch tabs       /          filter (type, enter to keep, esc to clear)
!              important only    r          reload now
s              ask Claude to explain the selected entry (answers are cached)
d              ask Claude to summarize today's activity
q              quit (everything until now is marked as seen)

Tabs: Timeline is everything. MDM shows commands the server sent. Processes shows
what the MDM agent ran. Inventory is what is on the Mac now (NEW = appeared after
the initial snapshot). Profiles explains each installed configuration profile.

Colors: red = important to look at, yellow = worth knowing, gray = routine.`
