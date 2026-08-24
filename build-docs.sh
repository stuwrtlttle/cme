#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
uv run python build_site.py
