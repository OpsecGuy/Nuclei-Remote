#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ ! -f config.env ]]; then
  echo 'Copy config.env.example to config.env and fill in your settings.' >&2
  exit 1
fi
set -a
source ./config.env
set +a
if [[ "$NUCLEI_API_TOKEN" == PASTE_GENERATED_TOKEN* ]]; then
  echo 'Set your own random API token in config.env.' >&2
  exit 1
fi
exec .venv/bin/python server.py
