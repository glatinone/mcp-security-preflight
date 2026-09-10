#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
PYTHONPATH=. python3 -m src.cli reset
