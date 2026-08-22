#!/usr/bin/env sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ ! -x "$repo_root/.venv/bin/python" ]; then
    echo "Virtual environment not found. Run scripts/setup.sh first." >&2
    exit 1
fi
export PYTHONUTF8=1
cd "$repo_root"
exec "$repo_root/.venv/bin/python" app.py
