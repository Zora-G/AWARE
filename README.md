# AWARE

Implementation and benchmarks for *Unseen at the Gate, Opened Only in Council: Whistleblowing against Issuer Tracing and Recipient Corruption*.

## Requirements

Rust 1.89 or later. Python 3.12 with `pip install -r requirements.txt`. The figures use the URW base35 fonts (`fonts-urw-base35` on Debian and Ubuntu).

## Build and test

```bash
cargo build --release --manifest-path rust_protocol/Cargo.toml
cargo test --release --manifest-path rust_protocol/Cargo.toml
```

## Paper results

```bash
experiments/run.sh table2
experiments/run.sh table3
experiments/run.sh table4
experiments/run.sh fig2
experiments/run.sh fig3
```

Outputs go to `results/`. Table 4 reads the GlobaLeaks 5.0.99 timings from `experiments/globaleaks.csv`. The paper measured client rows on an Apple M2 and server rows on a Xeon host with `AWARE_CPUS=0-39`. To split the roles across hosts, set `AWARE_ROLES=client` or `AWARE_ROLES=server` on each host. Then collect both into `results/` and run `experiments/render.py <target>`.

## License

AWARE is released under the MIT License (`LICENSE`). `rust_protocol/vendor/mcore` is MIRACL Core (commit a6df673, Apache-2.0), with its mask counters made thread-local.
