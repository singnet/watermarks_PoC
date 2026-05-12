#!/usr/bin/env bash
# Run the OpenWater internal demo end-to-end.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -d .venv ]]; then
  echo "No .venv found. Run scripts/setup.sh first." >&2
  exit 1
fi

# shellcheck source=/dev/null
. .venv/bin/activate
openwater demo "$@"
