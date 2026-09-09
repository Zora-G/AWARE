#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/results/table_iv_aware/server}"
CPUS_ARGS=()

if [[ -n "${AWARE_CPUS:-}" ]]; then
  CPUS_ARGS=(--cpus "$AWARE_CPUS")
fi

cd "$ROOT"

"$ROOT/scripts/build_release.sh"

python3 "$ROOT/scripts/run_pipeline.py" \
  --role server \
  --output "$OUT" \
  "${CPUS_ARGS[@]}" \
  --target TableIV

