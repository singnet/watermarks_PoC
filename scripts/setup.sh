#!/usr/bin/env bash
# Create venv, install pinned requirements + demo (with vendored oprow),
# run upstream test suite as a smoke check.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

# shellcheck source=/dev/null
. .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e '.[web,test]'

echo "Running upstream oprow test suite (vendored) as a smoke check..."
python -m pytest tests/oprow_upstream/ -q

echo "Setup complete. Activate with:  . .venv/bin/activate"
