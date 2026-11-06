#!/bin/bash
# Runs logbook against a fake Mac in a temporary folder. Needs no sudo and touches nothing real.
set -u

SCRIPT="$(cd "$(dirname "$0")" && pwd)/logbook"
WORK=$(mktemp -d)
trap 'rm -rf "${WORK:?}"' EXIT
export LOGBOOK_TEST_ROOT="$WORK/mac" LOGBOOK_DIR="$WORK/data"

FAILS=0
OUTPUT=""

check() {
  OUTPUT=$("$SCRIPT" 2>&1)
  STATUS=$?
}

has() {
  case "$OUTPUT" in
    *"$1"*) ;;
    *)
      echo "FAIL: expected: $1"
      echo "--- output:"
      echo "$OUTPUT"
      echo "---"
      FAILS=$((FAILS + 1))
      ;;
  esac
}

lacks() {
  case "$OUTPUT" in
    *"$1"*)
      echo "FAIL: did not expect: $1"
      echo "--- output:"
      echo "$OUTPUT"
      echo "---"
      FAILS=$((FAILS + 1))
      ;;
  esac
}

app() {
  mkdir -p "$WORK/mac/Applications/$1.app/Contents"
  cat >"$WORK/mac/Applications/$1.app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>$2</string></dict></plist>
EOF
}

profiles() {
  cat >"$WORK/mac/profiles.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>_computerlevel</key><array>$1</array></dict></plist>
EOF
}

PPPC='<dict>
  <key>ProfileDisplayName</key><string>Rippling PPPC Profile</string>
  <key>ProfileIdentifier</key><string>com.example.pppc</string>
  <key>ProfileInstallDate</key><date>2026-11-05T19:17:00Z</date>
  <key>ProfileItems</key><array><dict>
    <key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string>
    <key>PayloadContent</key><dict><key>Services</key><dict>
      <key>Accessibility</key><array><dict>
        <key>Identifier</key><string>/usr/local/rippling/daemon</string>
        <key>Authorization</key><string>Allow</string>
      </dict></array>
      <key>SystemPolicyAllFiles</key><array><dict>
        <key>Identifier</key><string>/usr/local/rippling/daemon</string>
        <key>Allowed</key><true/>
      </dict></array>
    </dict></dict>
  </dict></array>
</dict>'

FILEVAULT='<dict>
  <key>ProfileDisplayName</key><string>FileVault</string>
  <key>ProfileIdentifier</key><string>com.example.filevault</string>
  <key>ProfileItems</key><array><dict>
    <key>PayloadType</key><string>com.apple.MCX.FileVault2</string>
    <key>PayloadContent</key><dict><key>Enable</key><string>On</string></dict>
  </dict></array>
</dict>'

FILEVAULT2=${FILEVAULT/<string>On<\/string>/<string>Off<\/string>}

AGENT='<dict>
  <key>ProfileDisplayName</key><string>Example Agent Profile</string>
  <key>ProfileIdentifier</key><string>com.example.agent</string>
  <key>ProfileItems</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string>
      <key>PayloadContent</key><dict><key>Services</key><dict>
        <key>ScreenCapture</key><array><dict>
          <key>Identifier</key><string>com.example.agent</string>
          <key>Authorization</key><string>AllowStandardUserToSetSystemService</string>
        </dict></array>
        <key>Camera</key><array><dict>
          <key>Identifier</key><string>com.example.agent</string>
          <key>Authorization</key><string>Deny</string>
        </dict></array>
      </dict></dict>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadContent</key><data>AAEC</data>
    </dict>
  </array>
</dict>'

mkdir -p "$WORK/mac/Library/LaunchDaemons" "$WORK/mac/Library/LaunchAgents"
printf '3 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tTEAM1\tio.example.net (1.0/1)\tExample Net\t[activated enabled]\n' >"$WORK/mac/extensions.txt"
app "Slack" "4.42"
app "Old Tool" "1.0"
echo one >"$WORK/mac/Library/LaunchDaemons/com.example.one.plist"
profiles "$PPPC$FILEVAULT"

echo "first check records the starting point"
check
has "First check - saved as the starting point"
has "/usr/local/rippling/daemon"
has "Control the computer (Accessibility)"
has "Full Disk Access (all application data)"
has "Rippling PPPC Profile"
has "PROFILES (2)"
has "1 background service, 1 system extension, 2 apps"
has "Screen & System Audio Recording, Input Monitoring"

echo "nothing changed"
check
has "Nothing changed since"
lacks "NEW"

echo "changes are reported once"
app "Slack" "4.43"
app "Example Agent" "2.1"
rm -rf "${WORK:?}/mac/Applications/Old Tool.app"
echo two >"$WORK/mac/Library/LaunchDaemons/com.example.agent.plist"
echo changed >"$WORK/mac/Library/LaunchDaemons/com.example.one.plist"
printf '*\t*\tTEAM2\tcom.example.filter (3.0/3)\tExample Filter\t[activated enabled]\n' >>"$WORK/mac/extensions.txt"
profiles "$PPPC$FILEVAULT2$AGENT"
check
has "Screen recording may be approved by a standard user for com.example.agent (Example Agent Profile)"
has "Camera blocked for com.example.agent (Example Agent Profile)"
has "+ Profile: Example Agent Profile (contains: trusted root certificate)"
has "+ Background service: $WORK/mac/Library/LaunchDaemons/com.example.agent.plist"
has "+ System extension: Example Filter 3.0/3 [activated enabled]"
has "+ App: Example Agent 2.1"
has "- App: Old Tool 1.0"
has "~ App: Slack 4.42 → Slack 4.43"
has "~ Profile: FileVault (content changed)"
has "~ Background service: $WORK/mac/Library/LaunchDaemons/com.example.one.plist (content changed)"
has "6 new, 1 removed, 3 changed"
lacks "Control the computer"
[ "$(find "$WORK/data/history" -type f | wc -l | tr -d ' ')" = 1 ] || { echo "FAIL: expected one history file"; FAILS=$((FAILS + 1)); }
check
has "Nothing changed since"

echo "removed permissions are reported"
profiles "$FILEVAULT2$AGENT"
check
has "- Permission: Control the computer (Accessibility) for /usr/local/rippling/daemon (Rippling PPPC Profile)"
has "- Profile: Rippling PPPC Profile"

echo "a failed read does not look like everything was removed"
cp "$WORK/mac/profiles.xml" "$WORK/good.xml"
echo "not a plist" >"$WORK/mac/profiles.xml"
check
has "Warning: could not read permissions, keeping the previous results"
lacks "Profile: FileVault"
cp "$WORK/good.xml" "$WORK/mac/profiles.xml"
check
has "Nothing changed since"

echo "history older than 30 days is deleted"
touch -t 202001010000 "$WORK/data/history/old.txt"
app "Another" "1.0"
check
has "+ App: Another 1.0"
[ ! -e "$WORK/data/history/old.txt" ] || { echo "FAIL: old history was kept"; FAILS=$((FAILS + 1)); }

echo "a failed first check saves nothing"
rm -rf "${WORK:?}/data"
echo "not a plist" >"$WORK/mac/profiles.xml"
check
has "could not read permissions, nothing was saved"
[ "$STATUS" = 1 ] || { echo "FAIL: expected exit 1, got $STATUS"; FAILS=$((FAILS + 1)); }
[ ! -e "$WORK/data/latest" ] || { echo "FAIL: first check saved results after a failure"; FAILS=$((FAILS + 1)); }

echo "the first permission on a clean Mac is reported"
rm -rf "${WORK:?}/data"
profiles ""
check
has "PROFILES (0)"
profiles "$PPPC"
check
has "+ Permission: Control the computer (Accessibility) for /usr/local/rippling/daemon (Rippling PPPC Profile)"
has "+ Profile: Rippling PPPC Profile"

echo "apps without a version are listed by name"
rm -rf "${WORK:?}/data"
mkdir -p "$WORK/mac/Applications/No Plist.app"
mkdir -p "$WORK/mac/Applications/No Version.app/Contents"
cat >"$WORK/mac/Applications/No Version.app/Contents/Info.plist" <<'EOF2'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleName</key><string>x</string></dict></plist>
EOF2
check
if grep -qE "does not exist|Could not extract|Error Domain" "$WORK/data/latest/apps"; then
  echo "FAIL: a plutil error was stored as an app version"
  FAILS=$((FAILS + 1))
fi
grep -q $'\tNo Plist$' "$WORK/data/latest/apps" || { echo "FAIL: app without Info.plist not listed by name"; FAILS=$((FAILS + 1)); }
grep -q $'\tNo Version$' "$WORK/data/latest/apps" || { echo "FAIL: app without version not listed by name"; FAILS=$((FAILS + 1)); }

echo "no secrets are stored"
rm -rf "${WORK:?}/data"
profiles '<dict>
  <key>ProfileDisplayName</key><string>Office Wi-Fi</string>
  <key>ProfileIdentifier</key><string>com.example.wifi</string>
  <key>ProfileItems</key><array><dict>
    <key>PayloadType</key><string>com.apple.wifi.managed</string>
    <key>PayloadContent</key><dict><key>Password</key><string>TOP-SECRET-VALUE</string></dict>
  </dict></array>
</dict>'
check
has "Office Wi-Fi"
if grep -rq "TOP-SECRET-VALUE" "$WORK/data"; then
  echo "FAIL: a secret reached the saved results"
  FAILS=$((FAILS + 1))
fi

if [ "$FAILS" -ne 0 ]; then
  echo "$FAILS check(s) failed"
  exit 1
fi
echo "all checks passed"
