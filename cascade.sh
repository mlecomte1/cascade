#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  echo "Premier lancement : installation..."
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
fi

export PYTHONPATH="$PWD/src"
exec .venv/bin/python -m cascade
