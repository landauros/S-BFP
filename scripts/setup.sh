#!/usr/bin/env sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 -m venv "$repo_root/.venv"
"$repo_root/.venv/bin/python" -m pip install --upgrade pip
"$repo_root/.venv/bin/python" -m pip install -r "$repo_root/requirements.txt"
echo "Setup complete. Run scripts/run.sh from the repository root."
