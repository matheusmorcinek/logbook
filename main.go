package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	label     = "com.local.logbook"
	binPath   = "/usr/local/bin/logbook"
	plistPath = "/Library/LaunchDaemons/" + label + ".plist"
	fdaPane   = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
)

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "":
		runTUI()
	case "service":
		runService()
	case "snapshot":
		runSnapshotOnce()
	case "install":
		runInstall()
	case "uninstall":
		runUninstall(len(os.Args) > 2 && os.Args[2] == "--purge")
	case "status":
		runStatus()
	case "version", "--version":
		fmt.Println("logbook", version)
	default:
		fmt.Print(`logbook - a read-only record of what happens on this Mac

Usage:
  logbook             open the terminal UI
  logbook status      show whether logbook is running and healthy
  sudo logbook install     install (or update) the background service
  sudo logbook uninstall   remove it (add --purge to also delete recorded data)
  logbook snapshot    take one inventory snapshot now and print the changes

Data: ` + dataDir() + "\n")
		if cmd != "help" && cmd != "-h" && cmd != "--help" {
			os.Exit(2)
		}
	}
}

func requireRoot() {
	if isRoot() {
		return
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "this command needs sudo")
		os.Exit(1)
	}
	args := append([]string{"sudo", self}, os.Args[1:]...)
	sudo, _ := exec.LookPath("sudo")
	if err := syscall.Exec(sudo, args, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "this command needs sudo:", err)
		os.Exit(1)
	}
}

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

const plistTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>service</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`

func runInstall() {
	requireRoot()
	self, err := os.Executable()
	must(err, "find executable")
	must(os.MkdirAll("/usr/local/bin", 0o755), "create /usr/local/bin")
	must(prepareDataDir(), "create data dir")

	_ = exec.Command("launchctl", "bootout", "system/"+label).Run()
	if self != binPath {
		must(copyFile(self, binPath, 0o755), "install binary")
	}
	_ = exec.Command("xattr", "-d", "com.apple.quarantine", binPath).Run()
	// A stable signing identifier makes the binary recognizable in the Full Disk Access list.
	_ = exec.Command("codesign", "-s", "-", "-f", "-i", label, binPath).Run()

	if _, err := os.Stat(dataPath(configFile)); os.IsNotExist(err) {
		must(writeJSONAtomic(dataPath(configFile), defaultConfig()), "write config")
	}
	logPath := dataPath("service.log")
	must(os.WriteFile(plistPath, []byte(fmt.Sprintf(plistTmpl, label, binPath, logPath, logPath)), 0o644), "write launchd plist")
	must(os.Chown(plistPath, 0, 0), "chown launchd plist")
	if out, err := exec.Command("launchctl", "bootstrap", "system", plistPath).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "launchctl bootstrap: %v %s\n", err, out)
		os.Exit(1)
	}

	fmt.Println("Installed. logbook is running and records to " + dataDir() + ".")
	fmt.Println()
	fmt.Println("One manual step: give logbook Full Disk Access, so it can see which processes the MDM agent starts.")
	fmt.Println("  1. In the window that opens, click + (you may need to unlock with your password)")
	fmt.Println("  2. Press Cmd+Shift+G, type /usr/local/bin/logbook, press Enter, then Open")
	fmt.Println("  3. Make sure the switch next to logbook is on")
	fmt.Println("Process tracking starts by itself within a minute. Check with: logbook status")
	if u := os.Getenv("SUDO_USER"); u != "" {
		_ = exec.Command("sudo", "-u", u, "open", fdaPane).Run()
	} else {
		_ = exec.Command("open", fdaPane).Run()
	}
}

func runUninstall(purge bool) {
	requireRoot()
	_ = exec.Command("launchctl", "bootout", "system/"+label).Run()
	_ = os.Remove(plistPath)
	_ = os.Remove(binPath)
	if purge {
		_ = os.RemoveAll(dataDir())
		fmt.Println("Removed logbook and all recorded data.")
		return
	}
	fmt.Println("Removed logbook. Recorded data is kept in " + dataDir() + " (use --purge to delete it).")
}

func runStatus() {
	ok := func(good bool, s string) string {
		if good {
			return "ok    " + s
		}
		return "WARN  " + s
	}
	loaded := exec.Command("launchctl", "print", "system/"+label).Run() == nil
	fmt.Println(ok(loaded, "background service loaded ("+label+")"))
	var st Status
	if err := readJSON(dataPath(statusFile), &st); err != nil {
		fmt.Println(ok(false, "no status yet: logbook has not run"))
	} else {
		age := time.Since(st.Heartbeat).Round(time.Second)
		fmt.Println(ok(!st.Stopped && age < 2*time.Minute, fmt.Sprintf("heartbeat %s ago (pid %d, version %s, root %v)", age, st.PID, st.Version, st.Root)))
		fmt.Println(ok(!st.LastSnapshot.IsZero(), "last inventory snapshot "+st.LastSnapshot.Local().Format("Jan 2 15:04")))
		fmt.Println(ok(st.MDMLog == "running", "MDM command log: "+st.MDMLog))
		fmt.Println(ok(st.Process == "running", "process tracking: "+st.Process))
	}
	if _, err := findClaude(); err != nil {
		fmt.Println("info  " + err.Error() + " (only needed for the s / d explanations)")
	} else {
		fmt.Println("ok    Claude Code found (used for s / d explanations)")
	}
	fmt.Println("data  " + dataDir())
}
