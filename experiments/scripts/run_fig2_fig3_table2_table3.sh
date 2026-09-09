#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$ROOT/results/paper}"
FIGURES="${2:-$ROOT/figures/paper}"
CPUS_ARGS=()

if [[ -n "${AWARE_CPUS:-}" ]]; then
  CPUS_ARGS=(--cpus "$AWARE_CPUS")
fi

cd "$ROOT"

"$ROOT/experiments/scripts/build_release.sh"

python3 "$ROOT/experiments/scripts/run_pipeline.py" \
  --role client \
  --output "$OUT/client" \
  --target Fig2 \
  --target TableII \
  --target TableIII

python3 "$ROOT/experiments/scripts/run_pipeline.py" \
  --role server \
  --output "$OUT/server" \
  "${CPUS_ARGS[@]}" \
  --target Fig2 \
  --target Fig3 \
  --target TableII \
  --target TableIII \
  --target TableIV

python3 "$ROOT/experiments/scripts/reuse_comparison.py" \
  --output "$OUT/comparison"

python3 "$ROOT/experiments/scripts/render_results.py" \
  --results "$OUT" \
  --figures "$FIGURES"
