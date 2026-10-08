#!/usr/bin/env bash
set -u

# Supervisor gives this wrapper its own process group. Clean up the builtin
# USB/Wi-Fi children if Sideloop exits, so a restart cannot leave old muxers.
cleanup() {
  trap '' TERM INT
  kill -TERM 0 2>/dev/null || true
}

python3 -m sideloop &
app_pid=$!
trap cleanup EXIT
trap 'kill -TERM "$app_pid" 2>/dev/null || true; wait "$app_pid" 2>/dev/null || true; exit 0' TERM INT
wait "$app_pid"
exit $?
