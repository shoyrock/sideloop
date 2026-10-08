#!/usr/bin/env bash
set -euo pipefail

export DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR/anisette/runtime"
# The separate Anisette container used this same unprivileged account.
# Its persisted identity and downloaded libraries now live beside Sideloop data.
chown -R Alcoholic:Alcoholic "$DATA_DIR/anisette"

exec "$@"
