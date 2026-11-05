# logbook

A read-only log of process activity and settings changes on a Mac, with a terminal UI to browse it.

It is useful on a Mac enrolled in device management (MDM), or any Mac where you want to know what
changed and what ran: apps and packages installed or removed, configuration profiles and the
permissions they grant, new users and admins, certificates, background services, and every process
started by a device management agent.

logbook only observes. It never blocks, modifies or interferes with anything on the Mac.

## What it records

| Area | How |
| --- | --- |
| Apps, packages, users, admins, certificates, system extensions, background services, managed preferences, configuration profiles, MDM enrollment status | Snapshots every 10 minutes, and within a minute of an install. Each snapshot is compared with the previous one; additions, removals and changes are logged. |
| Commands the MDM server sends (install a profile, ask for the app list, lock, erase, ...) | Reads `mdmclient` messages from the unified log. |
| Every process a device management agent starts, including scripts and their children | macOS Endpoint Security, through Apple's built-in `eslogger`. Agents are matched by name (Rippling, Jamf, Kandji, Mosyle, Intune, Addigy, Hexnode, Workspace ONE, SimpleMDM, Fleet, Meraki by default). |

Configuration profiles are explained in plain language, including privacy permissions they grant
(for example "GRANTS Full Disk Access to com.example.agent").

## Privacy

- Everything stays on the Mac, in `/Users/Shared/logbook`, readable by admin users only.
- Nothing is sent anywhere unless you opt in:
  - pressing `s` or `d` in the UI sends the selected entries to Claude through your own
    [Claude Code](https://claude.com/claude-code) login, to explain them;
  - phone alerts send entry titles to the [ntfy](https://ntfy.sh) server you configure.

## Install

Requires macOS 13 or later and an admin account.

From source (needs Go 1.24+, for example `brew install go`):

```sh
git clone https://github.com/matheusmorcinek/logbook
cd logbook
go build -o logbook .
sudo ./logbook install
```

Or download a binary from [Releases](https://github.com/matheusmorcinek/logbook/releases) (built
by GitHub Actions from the tagged source, with checksums), then:

```sh
xattr -d com.apple.quarantine logbook-darwin-arm64   # downloaded files are quarantined by macOS
sudo ./logbook-darwin-arm64 install
```

`install` copies the binary to `/usr/local/bin/logbook`, starts a background service, and opens
System Settings at **Full Disk Access**. Add `/usr/local/bin/logbook` there (Cmd+Shift+G to type the
path) and turn it on; process tracking needs it. Re-grant it after installing a new build, since
macOS ties the permission to the exact binary.

Check that everything is healthy:

```sh
logbook status
```

## Use

```sh
logbook
```

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k` | move |
| `enter` | expand the details |
| `J` `K` | scroll the details |
| `1`-`5`, `tab` | Timeline, MDM, Processes, Inventory, Profiles |
| `/` | filter |
| `!` | important entries only |
| `s` | ask Claude to explain the selected entry |
| `d` | ask Claude to summarize today |
| `?` | help |
| `q` | quit |

Entries since your last visit are marked **NEW**. Colors: red is important to look at, yellow is
worth knowing, gray is routine. The service records continuously; the UI is only a viewer.

## Configure

`/Users/Shared/logbook/config.json` (edit with `sudo`, then `sudo logbook install` to restart):

| Key | Default | Meaning |
| --- | --- | --- |
| `watch` | common MDM agents | substrings matched against executable paths and signing IDs |
| `snapshot_minutes` | `10` | how often a full snapshot runs |
| `ntfy_topic` | empty (off) | ntfy topic for phone alerts; pick a long random name, topics are public |
| `ntfy_server` | `https://ntfy.sh` | ntfy server |
| `notify_min` | `alert` | lowest severity sent as an alert (`notice` or `alert`) |
| `ai_model` | empty | model passed to `claude --model`; empty uses your Claude Code default |

## Uninstall

```sh
sudo logbook uninstall           # keeps recorded data
sudo logbook uninstall --purge   # also deletes it
```

Then remove `logbook` from Full Disk Access in System Settings.

## Limitations

- macOS does not document the wording of `mdmclient` log messages, so commands are recognized by
  their protocol names (`InstallProfile`, `DeviceLock`, ...). Raw lines are kept in
  `mdm-raw.log` to improve matching.
- `eslogger` output is not a stable API; Apple may change it between macOS releases.
- Anything running as root, including an MDM agent, could stop logbook or edit its files. A gap is
  flagged the next time logbook starts, and phone alerts copy entries off the Mac as they happen.

## Develop

```sh
go test ./...
LOGBOOK_DEMO_DIR=/tmp/lb-demo go test -run TestWriteDemoData . &&
  LOGBOOK_DIR=/tmp/lb-demo LOGBOOK_CACHE_DIR=/tmp/lb-demo/cache go run .
```

The second command opens the UI on simulated data, without installing anything.

## License

[MIT](LICENSE)
