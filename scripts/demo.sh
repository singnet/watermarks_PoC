#!/usr/bin/env bash
# Run the OpenWater internal demo end-to-end.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x .venv/bin/python ]]; then
  echo "No .venv found. Run scripts/setup.sh first." >&2
  exit 1
fi

exec .venv/bin/python -m openwater_mk.cli demo "$@"
