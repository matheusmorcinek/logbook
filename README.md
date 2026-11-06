# logbook

One command that shows what changed on a Mac since you last ran it: permissions granted by
configuration profiles, profiles, background services, system extensions and apps.

It is a single shell script with no dependencies and no background service. It doesn't need Full
Disk Access and makes no network connections. It only changes its own saved results.

```sh
git clone https://github.com/matheusmorcinek/logbook
cd logbook
sudo ./logbook
```

The first run saves the current state. Each later run shows the differences and saves the new
state as the starting point:

```
Compared with Nov 6, 10:42

NEW
  + Permission: Screen recording may be approved by a standard user for com.example.agent (Example Agent Profile)
  + Profile: Example Agent Profile (contains: trusted root certificate)
  + Background service: /Library/LaunchDaemons/com.example.agent.plist
  + App: Example Agent 2.1

REMOVED
  - App: Old Tool 1.0

CHANGED
  ~ Profile: FileVault (content changed)

4 new, 1 removed, 1 changed. Saved as the new starting point.
```

To run it from anywhere: `sudo install -m 755 logbook /usr/local/bin/logbook`

## What it can't show

- **Permissions approved on the Mac itself.** macOS protects that list, and reading it needs Full
  Disk Access. Check **System Settings > Privacy & Security** by hand, especially Screen & System
  Audio Recording and Input Monitoring.
- **What a program does with permissions it already has.** Only new or changed items appear.
- **When something happened, or anything that came and went between two checks.**
- **Software built to hide.** Anything running as root could conceal itself or edit the saved
  results. An empty report doesn't prove that nothing is monitoring the Mac.

## Saved data

Results are in `/Library/Application Support/logbook`, readable only by root. They contain names,
versions and content hashes, never setting values. Reports with changes are kept in `history/` for
30 days.

To remove it:

```sh
sudo rm -rf "/Library/Application Support/logbook"
```

## Develop

```sh
./test.sh
```

The tests run against a fake Mac in a temporary folder, so they need no `sudo`.

## License

[MIT](LICENSE)
