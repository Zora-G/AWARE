#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/results/paper}"
FIGURES="${2:-$ROOT/figures/paper}"
CPUS_ARGS=()

if [[ -n "${AWARE_CPUS:-}" ]]; then
  CPUS_ARGS=(--cpus "$AWARE_CPUS")
fi

cd "$ROOT"

"$ROOT/scripts/build_release.sh"

python3 "$ROOT/scripts/run_pipeline.py" \
  --role client \
  --output "$OUT/client" \
  --target Fig3a \
  --target Fig3b \
  --target TableII \
  --target TableIII

python3 "$ROOT/scripts/run_pipeline.py" \
  --role server \
  --output "$OUT/server" \
  "${CPUS_ARGS[@]}" \
  --target Fig3a \
  --target Fig3c \
  --target Fig4a \
  --target Fig4b \
  --target TableII \
  --target TableIII \
  --target TableIV

python3 "$ROOT/scripts/reuse_comparison.py" \
  --output "$OUT/comparison"

python3 "$ROOT/scripts/render_results.py" \
  --results "$OUT" \
  --figures "$FIGURES"
