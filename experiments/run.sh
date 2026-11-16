#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo build --release --locked --features benchmarks --manifest-path "$root/rust_protocol/Cargo.toml"
for role in ${AWARE_ROLES:-client server}; do
  python3 "$root/experiments/pipeline.py" --role "$role" --target "$1" ${AWARE_CPUS:+--cpus "$AWARE_CPUS"}
done
if [[ -z "${AWARE_ROLES:-}" ]]; then
  python3 "$root/experiments/render.py" "$1"
fi
