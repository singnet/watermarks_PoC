#!/usr/bin/env bash
# Create venv, install pinned requirements + demo (with vendored oprow),
# run upstream test suite as a smoke check.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON_BIN="${PYTHON:-python3}"
REPO_ROOT="$(pwd -P)"
VENV_PATH="$REPO_ROOT/.venv"

"$PYTHON_BIN" - <<'PY'
import sys

if not ((3, 11) <= sys.version_info[:2] < (3, 14)):
    raise SystemExit(
        "openwater-demo requires Python >=3.11,<3.14 for the pinned "
        "dev/test stack; rerun with PYTHON=/path/to/python3.11-3.13"
    )
PY

recreate_venv=0
if [[ ! -x .venv/bin/python ]]; then
  recreate_venv=1
else
  current_prefix="$(
    .venv/bin/python - <<'PY' 2>/dev/null || true
import pathlib
import sys
print(pathlib.Path(sys.prefix).resolve())
PY
  )"
  if [[ "$current_prefix" != "$VENV_PATH" ]]; then
    recreate_venv=1
  fi
  if ! .venv/bin/python - <<'PY' >/dev/null 2>&1; then
import sys
raise SystemExit(0 if ((3, 11) <= sys.version_info[:2] < (3, 14)) else 1)
PY
    recreate_venv=1
  fi
fi

if [[ "$recreate_venv" == "1" ]]; then
  echo "Creating fresh .venv at $VENV_PATH"
  rm -rf .venv
  "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e '.[web,test]'

echo "Running upstream oprow test suite (vendored) as a smoke check..."
.venv/bin/python -m pytest tests/oprow_upstream/ -q

echo "Setup complete. Activate with:  . .venv/bin/activate"
