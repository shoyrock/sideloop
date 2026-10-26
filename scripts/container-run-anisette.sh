#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${ANISETTE_V3_SERVERS:-}" ]]; then
  exec python3 -m sideloop.anisette
fi
# Preserve the legacy local backend and its existing identity for explicit use.
exec /usr/local/bin/anisette-v3-server --host 127.0.0.1 --adi-path "$DATA_DIR/anisette"
