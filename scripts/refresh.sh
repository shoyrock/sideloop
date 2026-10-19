#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
CONFIG="$DATA_DIR/config.env"
APPS_DIR="$DATA_DIR/apps"
DEVICES_DIR="$DATA_DIR/devices"
STATE_DIR="$DATA_DIR/state"
ALTSERVER_BIN="${ALTSERVER_BIN:-/usr/local/bin/AltServer}"

[[ -r "$CONFIG" ]] || { echo "missing config: $CONFIG" >&2; exit 78; }
set -a; . "$CONFIG"; set +a
: "${RENEW_BEFORE_DAYS:=2}"
: "${ANISETTE_SERVER:=http://127.0.0.1:6969}"

FORCE=0; RECHECK=0; RESIGN_ONLY=0; INSTALL=0; CONFIRM_REPLACE=0; REPAIR=0; APP=""; DEVICE=""
while (( $# )); do
  case "$1" in
    --force) FORCE=1 ;;
    --install) INSTALL=1 ;;
    --confirm-replace) CONFIRM_REPLACE=1 ;;
    --repair) REPAIR=1 ;;
    # With --force for several apps: re-sign installed apps, don't install the rest.
    --resign-only) RESIGN_ONLY=1 ;;
    --recheck) RECHECK=1 ;;
    --app) APP="${2:?--app needs an id}"; shift ;;
    --device) DEVICE="${2:?--device needs a udid}"; shift ;;
  esac
  shift
done

if [[ -z "$APP" || -z "$DEVICE" ]]; then
  rc=0; n=0
  # Apple refusing an account fails every app it signs; each account is tried once per run.
  if [[ -z "${SIDELOOP_REFUSED:-}" ]]; then
    SIDELOOP_REFUSED="$(mktemp)"; export SIDELOOP_REFUSED
    trap 'rm -f "$SIDELOOP_REFUSED"' EXIT
  fi
  for d in "$APPS_DIR"/*/; do
    [[ -r "$d/meta.env" && -r "$d/app.ipa" ]] || continue
    id="$(basename "$d")"
    [[ -z "$APP" || "$APP" == "$id" ]] || continue
    for u in $(set -a; . "$d/meta.env"; printf '%s' "${DEVICES:-}"); do
      [[ -z "$DEVICE" || "${DEVICE,,}" == "${u,,}" ]] || continue
      [[ -r "$DEVICES_DIR/$u.env" ]] || continue
      n=$((n+1))
      args=(--app "$id" --device "$u")
      (( FORCE )) && args+=(--force)
      (( RESIGN_ONLY )) && args+=(--resign-only)
      (( RECHECK )) && args+=(--recheck)
      (( INSTALL )) && args+=(--install)
      (( CONFIRM_REPLACE )) && args+=(--confirm-replace)
      "${BASH_SOURCE[0]}" "${args[@]}" || rc=$?
    done
  done
  (( n )) || echo "nothing to do: no app is assigned to ${DEVICE:-any device}"
  exit "$rc"
fi

APP_DIR="$APPS_DIR/$APP"
[[ -r "$APP_DIR/meta.env" ]] || { echo "unknown app: $APP" >&2; exit 78; }
set -a; . "$APP_DIR/meta.env"; set +a
DEVICE_UDID="$DEVICE"
DEVICE_NAME="$DEVICE"
[[ -r "$DEVICES_DIR/$DEVICE.env" ]] && { set -a; . "$DEVICES_DIR/$DEVICE.env"; set +a; }
IPA_PATH="$APP_DIR/app.ipa"
APP_STATE="$APP_DIR/state/$DEVICE"
# Resolve a target's account without changing upstream app/device metadata.
account_context="$(python3 -m sideloop.accounts resolve "$APP" "$DEVICE")" || exit $?
eval "$account_context"
unset account_context
: "${APPLE_ID:?}" "${APPLE_PASSWORD:?}"
APP_STATE="$SIGNING_STATE"
TAG="[${APP_NAME:-$APP} on $DEVICE_NAME] "
EXPIRY="$APP_STATE/expiry"
CERT="$APP_STATE/certificate"
FAILS="$APP_STATE/consecutive_failures"
LOG_FILE="$STATE_DIR/refresh.log"
NOISE='^(Signing|Installation) Progress:|^Writing File: |^Signing: |^(Data|Value) ?: |^X-(Apple|Mme|MMe)-|^(MachineID|One-Time Password|Local User ID|Device UDID|Device Description|Date|Sanitized client info) ?:|^Byte:|^(HMAC_OUT|NP):|anisette|^Received (auth )?response status code'

export ALTSERVER_ANISETTE_SERVER="$ANISETTE_SERVER"
# Stock AltServer removes every free provisioning profile on the device before installing. Once the
# last profile of a developer is gone iOS forgets that the user trusted it, so every refresh brought
# back "Untrusted Developer". The patched AltServer leaves them in place, and prune_profiles below
# removes the outdated ones afterwards, never the newest.
export ALTSERVER_KEEP_PROFILES=1
export HOME="$SIGNING_HOME"
mkdir -p "$STATE_DIR" "$APP_STATE" "$HOME"
# AltServer caches its signing certificate in ./AltServerData. Without that cache it revokes the
# certificate and makes a new one, and iOS then asks to trust the developer again.
cd "$SIGNING_WORKDIR"

now() { date +%s; }
fmt_epoch() { date -d "@$1" '+%a %d %b %H:%M'; }
log() {
  local line; line="$(date '+%Y-%m-%d %H:%M:%S') $TAG$*"
  printf '%s\n' "$line" | tee -a "$LOG_FILE"
}
record() { printf '%s\t%s\t%s\n' "$(now)" "$1" "$2" > "$APP_STATE/last_run"; }

exec 9>"$STATE_DIR/.lock"
if ! flock -n 9; then
  echo "${TAG}waiting for $(cat "$STATE_DIR/.running" 2>/dev/null || echo "another run") to finish…"
  flock -w 1800 9 || { echo "${TAG}gave up waiting after 30 minutes"; exit 1; }
fi
printf '%s' "${TAG% }" > "$STATE_DIR/.running"
trap 'rm -f "$STATE_DIR/.running"' EXIT
RUN_START="$(now)"

conn_flag() {
  if timeout 10 idevice_id -l 2>/dev/null | grep -qi "^$DEVICE_UDID"; then echo ""
  elif timeout 10 idevice_id -n 2>/dev/null | grep -qi "^$DEVICE_UDID"; then printf '%s\n' -n
  else return 1; fi
}

device_online() {
  local f; f="$(conn_flag)" || return 1
  timeout 15 ideviceinfo ${f:+"$f"} -u "$DEVICE_UDID" -k DeviceName >/dev/null 2>&1
}

# Copies the device's provisioning profiles into a new temporary folder and prints its path.
copy_profiles() {
  local f tmp
  f="$(conn_flag)" || return 1
  tmp="$(mktemp -d)"
  if ! timeout 90 ideviceprovision ${f:+"$f"} -u "$DEVICE_UDID" copy "$tmp" >/dev/null 2>&1; then
    rm -rf "$tmp"; return 1
  fi
  echo "$tmp"
}

# Prints "<expiry> <certificate sha1>" of the newest profile in a folder for the main app of a
# bundle. Exits 1 when there is none, 2 when it is older than min_created. With a certificate
# sha1, profiles signed by another certificate (e.g. SideStore with another Apple ID) are skipped.
read_profile() {
  python3 - "$1" "$2" "${3:-0}" "${4:-}" <<'PY'
import datetime, glob, hashlib, plistlib, re, subprocess, sys
folder, bundle, min_created, cert = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
utc = lambda d: d.replace(tzinfo=datetime.timezone.utc).timestamp()
main_app = re.compile(r"^(\w+)\." + re.escape(bundle) + r"\.\1$")
best = None
for p in glob.glob(folder + "/*.mobileprovision"):
    xml = subprocess.run(["openssl", "smime", "-verify", "-noverify", "-inform", "DER", "-in", p],
                         capture_output=True).stdout
    try:
        d = plistlib.loads(xml)
    except Exception:
        continue
    if bundle and not main_app.match(d.get("Entitlements", {}).get("application-identifier", "")):
        continue
    c, e = d.get("CreationDate"), d.get("ExpirationDate")
    certs = [hashlib.sha1(x).hexdigest() for x in d.get("DeveloperCertificates") or [b""]]
    if cert and cert not in certs:
        continue
    if c and e and (best is None or c > best[0]):
        best = (c, int(utc(e)), certs[0])
if best is None:
    sys.exit(1)
if utc(best[0]) < min_created:
    sys.exit(2)
print(best[1], best[2])
PY
}

probe_expiry() {
  local tmp rc=0 cert=""
  if [[ "${1:-0}" == 0 ]]; then
    [[ -r "$CERT" ]] && cert="$(cat "$CERT")"
    # A different account's profile is not evidence that this signer installed the app.
    [[ "$SIGNING_ISOLATED" == 1 && -z "$cert" ]] && return 1
  fi
  tmp="$(copy_profiles)" || return 1
  read_profile "$tmp" "$BUNDLE_ID" "${1:-0}" "$cert" || rc=$?
  rm -rf "$tmp"
  return $rc
}

# AltServer removes the provisioning profiles of every sideloaded app on the device before it
# installs, and puts the others back only when the install succeeds. A run that fails or times
# out halfway leaves those apps without a profile, so iOS refuses to open them with "Untrusted
# Developer" even though their signature looks valid here. Check the other apps on the device
# after every run, and forget the signature of any that lost its profile so it gets reinstalled.
heal_siblings() {
  local tmp d s p name bundle cert
  tmp="$(copy_profiles)" || return 0
  for d in "$APPS_DIR"/*/; do
    s="$(python3 -m sideloop.accounts state "$(basename "$d")" "$DEVICE")" || continue
    [[ "$(basename "$d")" != "$APP" && -r "$s/expiry" && -r "$d/meta.env" ]] || continue
    IFS=$'\t' read -r bundle name < <(set -a; . "$d/meta.env"; printf '%s\t%s\n' "${BUNDLE_ID:-}" "${APP_NAME:-}")
    [[ -n "$bundle" ]] || continue
    cert=""; [[ -r "$s/certificate" ]] && cert="$(cat "$s/certificate")"
    if p="$(read_profile "$tmp" "$bundle" 0 "$cert")"; then
      echo "${p%% *}" > "$s/expiry"
    else
      # Mark it expired rather than forgetting it, so automatic checks still reinstall it.
      echo 1 > "$s/expiry"
      log "WARNING ${name:-$bundle} lost its provisioning profile during this run and won't open;" \
          "it will be reinstalled on the next run"
    fi
  done
  rm -rf "$tmp"
}

# Removes provisioning profiles of this Apple ID's team that a newer profile for the same app or
# extension replaced, on every app of the team. The newest one always stays, so the developer remains trusted.
prune_profiles() {
  local f tmp u
  f="$(conn_flag)" || return 0
  tmp="$(copy_profiles)" || return 0
  python3 - "$tmp" "$BUNDLE_ID" "$(cat "$CERT")" <<'PY' | while read -r u; do
import glob, hashlib, plistlib, re, subprocess, sys
folder, bundle, certificate = sys.argv[1], sys.argv[2], sys.argv[3]
profiles = []
for p in glob.glob(folder + "/*.mobileprovision"):
    xml = subprocess.run(["openssl", "smime", "-verify", "-noverify", "-inform", "DER", "-in", p],
                         capture_output=True).stdout
    try:
        d = plistlib.loads(xml)
    except Exception:
        continue
    certs = [hashlib.sha1(x).hexdigest() for x in d.get("DeveloperCertificates", [])]
    profiles.append((d.get("Entitlements", {}).get("application-identifier", ""), d["CreationDate"], d["UUID"], certs))
main = re.compile(r"^(\w+)\." + re.escape(bundle) + r"\.\1$")
# The app was just installed, so its newest profile belongs to this Apple ID's team. Profiles of
# other teams (SideStore, Xcode) are left alone.
ours = max(((c, a) for a, c, _, certs in profiles if main.match(a) and certificate in certs), default=None)
if ours is None:
    sys.exit()
team = ours[1].split(".", 1)[0]
newest = {}
for a, c, u, _ in profiles:
    if a.split(".", 1)[0] == team and (a not in newest or c > newest[a][0]):
        newest[a] = (c, u)
for a, c, u, _ in profiles:
    if a in newest and newest[a][1] != u:
        print(u)
PY
    timeout 30 ideviceprovision ${f:+"$f"} -u "$DEVICE_UDID" remove "$u" </dev/null >/dev/null 2>&1 || true
  done
  rm -rf "$tmp"
}

save_probe() {
  local e c old=""
  read -r e c <<< "$1"
  echo "$e" > "$EXPIRY"
  [[ -r "$CERT" ]] && old="$(cat "$CERT")"
  echo "$c" > "$CERT"
  if [[ -n "$old" && "$old" != "$c" ]]; then
    log "WARNING the signing certificate changed, so iOS will ask you to trust the developer again" \
        "(Settings > General > VPN & Device Management). It changes when $APPLE_ID is also used by" \
        "Xcode, AltStore, SideStore or Sideloadly, or when $DATA_DIR/AltServerData is lost."
  fi
}

stamp_success() {
  local p
  p="$(probe_expiry $(( RUN_START - 300 )))" || return 1
  save_probe "$p"
  echo 0 > "$FAILS"
}

# Names the apps iOS listed as filling the free-profile slots, e.g. "TEAM.com.example.app.TEAM".
blocking_apps() {
  python3 - "$out" "$APPS_DIR" <<'PY'
import pathlib, re, shlex, sys
text = pathlib.Path(sys.argv[1]).read_text(errors="replace")
m = re.search(r"\{\((.*?)\)\}", text, re.S)
names = {}
for meta in pathlib.Path(sys.argv[2]).glob("*/meta.env"):
    values = dict(shlex.split(line)[0].split("=", 1) for line in meta.read_text().splitlines() if "=" in line)
    names[values.get("BUNDLE_ID", "")] = values.get("APP_NAME") or values.get("BUNDLE_ID", "")
apps = []
for app_id in re.findall(r'"([^"]+)"', m.group(1) if m else ""):
    team, _, bundle = app_id.partition(".")
    bundle = re.sub(r"\." + re.escape(team) + r"$", "", bundle)
    apps.append(names.get(bundle, bundle))
print(", ".join(apps) or "apps installed by Sideloop or another tool")
PY
}
# Escapes text for use as a sed s/// replacement.
sed_escape() { printf '%s' "$1" | tr -d '\n' | sed -e 's/[\/&\\]/\\&/g'; }
stored_ios() { python3 -c 'import sys; from sideloop import store; print(store.device_ios(sys.argv[1]))' "$DEVICE" 2>/dev/null || true; }
read_fails() { local n=0; [[ -r "$FAILS" ]] && n="$(tr -cd '0-9' < "$FAILS")"; echo "${n:-0}"; }

if (( RECHECK )); then
  device_online || { echo "${TAG}${DEVICE_NAME} not reachable; unlock it and try again"; exit 1; }
  python3 -m sideloop.renewal check "$APP" "$DEVICE" || exit $?
  if [[ -r "$EXPIRY" ]]; then
    log "rechecked on the device: signature valid until $(fmt_epoch "$(cat "$EXPIRY")")"
  else
    log "not installed on this device"
  fi
  exit 0
fi

# Compare in seconds: whole days rounded down renewed up to a day before the configured window.
SECS_LEFT=-1; [[ -r "$EXPIRY" ]] && SECS_LEFT=$(( $(cat "$EXPIRY") - $(now) ))
(( FORCE == 0 && SECS_LEFT > RENEW_BEFORE_DAYS * 86400 )) && exit 0

if (( FORCE == 0 )); then
  # Automatic checks only renew apps the user installed and left on auto re-sign; installing
  # an app on a device is always the user's choice.
  [[ -r "$EXPIRY" ]] || exit 0
  [[ " ${MANUAL_APPS:-} " == *" $APP "* ]] && exit 0
fi
(( RESIGN_ONLY )) && [[ ! -r "$EXPIRY" ]] && exit 0

# Another app of this run already found the account refused; the same sign-in would fail again.
refused=""
[[ -n "${SIDELOOP_REFUSED:-}" ]] && refused="$(awk -F '\t' -v id="$APPLE_ID" '$1 == id { print $2; exit }' "$SIDELOOP_REFUSED" 2>/dev/null)"
if [[ -n "$refused" ]]; then
  log "skipped: $refused"
  record fail "skipped: $refused"
  exit 1
fi

# Persist across watcher/device-arrival batches. Manual installs and renewals can retry now.
AUTH_RETRY="$SIGNING_WORKDIR/.auth-retry-after"
if (( FORCE == 0 )) && [[ -r "$AUTH_RETRY" ]]; then
  retry_after="$(cat "$AUTH_RETRY")"
  if [[ "$retry_after" =~ ^[0-9]{1,10}$ ]] && (( 10#$retry_after > $(now) )); then
    log "skipped: Apple authentication HTTP 503; automatic retries paused until $(fmt_epoch "$retry_after")"
    exit 0
  fi
fi

announce() {
  if [[ -r "$EXPIRY" ]]; then
    local left="expired"
    (( SECS_LEFT > 0 )) && left="$(( SECS_LEFT / 86400 ))d $(( SECS_LEFT % 86400 / 3600 ))h left"
    log "signature has ${left} (threshold ${RENEW_BEFORE_DAYS}d)$( (( FORCE )) && echo ", forced run" )"
  else
    log "no signature on record yet, doing the first install"
  fi
}

if ! device_online; then
  # Log once per absence; automatic checks repeat every 30 minutes while an app is due.
  if (( FORCE )) || [[ "$(cut -f2 "$APP_STATE/last_run" 2>/dev/null)" != offline ]]; then
    announce
    log "${DEVICE_NAME} not reachable (asleep, locked, or off this Wi-Fi); will retry when it's back"
  fi
  record offline "device not reachable"
  exit 0
fi
announce

if (( INSTALL )); then
guard_args=(); (( CONFIRM_REPLACE )) && guard_args+=(--confirmed)
(( REPAIR )) && guard_args+=(--repair)
if ! python3 -m sideloop.renewal guard "$APP" "$DEVICE" "${guard_args[@]}"; then
  record repair "could not confirm safe replacement; check the device and use Install / Update"
  exit 1
fi
[[ -r "$IPA_PATH" ]] || { log "ERROR IPA missing: $IPA_PATH"; record fail "IPA missing"; exit 1; }

# iOS rejects an app whose minimum version is newer than the device's only after it was signed
# and copied, and AltServer reports that as an AltStore message. Check first, without contacting Apple.
f="$(conn_flag)" && DEVICE_IOS="$(timeout 15 ideviceinfo ${f:+"$f"} -u "$DEVICE_UDID" -k ProductVersion 2>/dev/null)" || DEVICE_IOS=""
# Wi-Fi lockdown reads fail intermittently; fall back to the version from the last scan.
[[ "$DEVICE_IOS" =~ ^[0-9] ]] || DEVICE_IOS="$(stored_ios)"
MIN_IOS="$(python3 -m sideloop.ipa "$APP_DIR")" || MIN_IOS=""
# Both end up in messages and a sed replacement; the IPA's Info.plist is untrusted input.
[[ "$MIN_IOS" =~ ^[0-9]+(\.[0-9]+)*$ ]] || MIN_IOS=""
[[ "$DEVICE_IOS" =~ ^[0-9]+(\.[0-9]+)*$ ]] || DEVICE_IOS=""
# Remembered so the UI can show the requirement while the device is away.
[[ -n "$DEVICE_IOS" ]] && python3 -c 'import sys; from sideloop import store; store.set_device_ios(*sys.argv[1:])' \
  "$DEVICE" "$DEVICE_IOS" 2>/dev/null || true
needs="$(python3 -m sideloop.ipa "$APP_DIR" "$DEVICE_IOS")" && too_old=0 || too_old=$?
if (( too_old == 3 )); then
  msg="${APP_NAME:-$APP} ${APP_VERSION:-} needs iOS $needs or later, but $DEVICE_NAME runs iOS $DEVICE_IOS; add a version of the IPA that supports iOS $DEVICE_IOS or update the device"
  n=$(( $(read_fails) + 1 )); echo "$n" > "$FAILS"
  log "SKIP $msg"; record fail "$msg"
  exit 1
fi

# Signs a copy without app extensions unless the app keeps them, so it uses one slot and one App ID.
SIGN_IPA="$(python3 -m sideloop.ipa --signing-copy "$APP_DIR")" || { log "ERROR could not prepare the IPA"; record fail "could not prepare the IPA"; exit 1; }
[[ "$SIGN_IPA" != "$IPA_PATH" ]] && log "removed the app's extensions so it uses one of the device's 3 app slots (keep them in Settings)"
log "signing and installing $(basename "$IPA_PATH") on $DEVICE_UDID"
command=("$ALTSERVER_BIN" -u "$DEVICE_UDID" "$SIGN_IPA")
else
log "renewing installed profiles on $DEVICE_NAME; no app transfer"
command=(python3 -m sideloop.renewal renew "$APP" "$DEVICE")
MIN_IOS=""; DEVICE_IOS=""
fi
out="$(mktemp)"
trap 'rm -f "$STATE_DIR/.running" "$out"' EXIT
set +e
if [[ -t 0 && -t 1 ]]; then
  ALTSERVER_APPLE_ID="$APPLE_ID" ALTSERVER_APPLE_PASSWORD="$APPLE_PASSWORD" \
  TZ=UTC timeout --foreground 2400 "${command[@]}" 2>&1 \
    | tee "$out"
  rc=${PIPESTATUS[0]}
else
  ALTSERVER_APPLE_ID="$APPLE_ID" ALTSERVER_APPLE_PASSWORD="$APPLE_PASSWORD" \
  TZ=UTC timeout 2400 "${command[@]}" </dev/null 2>&1 \
    | tee "$out"
  rc=${PIPESTATUS[0]}
fi
# AltServer words every iOS version rejection as AltStore's own 12.2 requirement; state the app's.
REQUIREMENT="This app needs iOS ${MIN_IOS:-a newer version} or later${DEVICE_IOS:+; the device runs iOS $DEVICE_IOS}."
tr '\r' '\n' < "$out" | grep -vE "$NOISE" | cut -c1-400 \
  | sed -e "s/Your device must be running iOS 12\.2 or later to install AltStore\./$(sed_escape "$REQUIREMENT")/" \
        -e "s/^Please deactivate a sideloaded app with AltStore.*/$(sed_escape "$(python3 -c 'from sideloop import jobs; print(jobs.LIMIT_ADVICE)')")/" \
  >> "$LOG_FILE"
reported_error="$(grep -E '^(Error:|Exception:)' "$out" | tail -n1 | cut -c1-240)"
if (( rc == 0 )) && [[ -n "$reported_error" ]]; then rc=1; fi
set -e

confirmed=0
if (( rc == 0 )); then
  if (( INSTALL )); then
    if python3 -m sideloop.renewal record "$APP" "$DEVICE" && stamp_success; then confirmed=1; fi
  elif grep -qx 'Profile renewal succeeded. No app was copied.' "$out"; then
    confirmed=1
  fi
fi
if (( confirmed )); then
  rm -f "$AUTH_RETRY"
  msg="profiles renewed without copying the app, valid until $(fmt_epoch "$(cat "$EXPIRY")")"
  (( INSTALL )) && msg="installed saved IPA, valid until $(fmt_epoch "$(cat "$EXPIRY")")"
  log "OK $msg"; record ok "$msg"
  (( INSTALL )) && prune_profiles
  (( INSTALL )) && heal_siblings
  exit 0
fi

hint=""; result=fail; refused=0
if (( rc == 42 )); then
  if (( INSTALL == 0 )) && python3 -m sideloop.renewal can-reinstall "$APP" "$DEVICE"; then
    log "profile renewal needs a full re-sign; reinstalling only the exact previously installed IPA"
    rm -f "$out"
    exec 9>&-
    exec "${BASH_SOURCE[0]}" --app "$APP" --device "$DEVICE" --force --install --confirm-replace --repair
  fi
  result=repair
  hint="$(grep '^Renewal requires repair:' "$out" | tail -n1 | cut -c1-240) Use Install / Update to review replacing the app; no IPA was copied"
elif grep -q 'com.rileytestut.AltServer (9)' "$out"; then
  # iOS allows 3 apps signed with free developer profiles per device, whichever tool installed them.
  result=limit
  hint="$DEVICE_NAME already has the 3 apps iOS allows with free developer profiles ($(blocking_apps)). The limit counts apps from every Apple account, so another account won't help; delete one from the device, then tap Install again"
elif grep -qx 'Apple authentication HTTP status: 503' "$out"; then
  hint="Apple authentication service unavailable (HTTP 503); Apple may be refusing this signing service identity. Automatic retries for this account are paused for 30 minutes; verify it in Settings to retry now"
  refused=1
  (( rc == 0 )) && rc=1
  printf '%s\n' "$(( $(now) + 1800 ))" > "$AUTH_RETRY"
elif grep -q -- '-22411' "$out"; then
  hint="Apple could not complete authentication for $APPLE_ID (-22411); verify the account in Settings. This can also indicate a signing-service compatibility problem"
  refused=1
elif grep -q -- '-80045' "$out"; then
  # Apple refuses a client identity that doesn't match the platform that made the Anisette data.
  hint="Apple refused the sign-in from this signing service (-80045), not $APPLE_ID; update Sideloop to the latest image"
  refused=1
elif grep -q -- '-20101' "$out"; then
  hint="Apple rejected the Apple ID or password of $APPLE_ID (-20101); check them in Settings"
  refused=1
elif grep -q 'com.rileytestut.AltServer (10)' "$out"; then
  # AltServer maps iOS's DeviceOSVersionTooLow to "must be running iOS 12.2 or later to install AltStore".
  runs="an older version"; [[ -n "$DEVICE_IOS" ]] && runs="iOS $DEVICE_IOS"
  hint="iOS refused ${APP_NAME:-$APP} ${APP_VERSION:-}: it needs iOS ${MIN_IOS:-a newer version} or later, and $DEVICE_NAME runs $runs"
elif grep -qiE 'two.?factor code|verification code' "$out" && ! grep -qE 'Got token for|Fetching team' "$out"; then
  # A missing code may also produce Error:/Exception: or a zero exit status.
  # Classify it before the generic error so remaining apps do not repeat the sign-in.
  (( rc == 0 )) && rc=1
  hint="Apple is asking for a 2FA code for $APPLE_ID; verify the account in Settings"
  refused=1
elif [[ -n "$reported_error" ]]; then
  hint="$reported_error"
elif (( rc == 0 )); then
  rc=1
  hint="AltServer finished, but the app isn't on the device (did it lock or leave Wi-Fi mid-copy?)"
elif (( rc == 124 )); then
  hint="AltServer timed out"
fi
n=$(( $(read_fails) + 1 )); echo "$n" > "$FAILS"
log "FAIL AltServer exited $rc (consecutive failures: $n)${hint:+ - $hint}"
if (( refused )) && [[ -n "${SIDELOOP_REFUSED:-}" ]]; then
  printf '%s\t%s\n' "$APPLE_ID" "$hint" >> "$SIDELOOP_REFUSED"
fi
record "$result" "AltServer exited $rc${hint:+: $hint}"
(( INSTALL )) && heal_siblings
exit "$rc"
