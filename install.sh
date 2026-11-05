#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
exec python3 "$SCRIPT_DIR/install.py" "$@"
