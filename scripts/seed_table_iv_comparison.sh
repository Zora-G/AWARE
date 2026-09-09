#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/results/paper/comparison}"

cd "$ROOT"

python3 "$ROOT/scripts/reuse_comparison.py" \
  --output "$OUT"

