<div align="center">

# AWARE BN462 Rust Artifact

Complete Rust implementation and experiment harness for the AWARE protocol.

![Rust](https://img.shields.io/badge/rust-1.89%2B-orange)
![Status](https://img.shields.io/badge/status-research%20artifact-lightgrey)
![Curve](https://img.shields.io/badge/curve-MIRACL%20Core%20BN462-blue)

</div>

## Overview

This repository is the minimal AWARE artifact package. It contains the BN462
Rust implementation, all benchmark entry points used by the manuscript results,
default experiment parameters, and scripts for reproducing Table II, Fig. 2,
Fig. 3, Table III, and the AWARE-side measurements for Table IV.

Default protocol parameters are recorded in
[`config/defaults.json`](./config/defaults.json): `m=15`, `n=5`, `t=3`,
`lambda=128`, 1 MiB report payloads, 30 measured runs, and 10 warmups.

## Code Map

| Path | Purpose |
| --- | --- |
| [`src/`](./src/) | AWARE BN462 implementation: algebra, canonical encodings, TNIBS, holder binding, threshold encryption, reporting, ledger acceptance, and accountable opening. |
| [`src/bin/aware-bench.rs`](./src/bin/aware-bench.rs) | Single benchmark binary covering every paper operation. |
| [`tests/`](./tests/) | Rust correctness and streaming tests retained for implementation validation. |
| [`vendor/mcore/`](./vendor/mcore/) | Vendored MIRACL Core BN462 dependency and upstream license. |
| [`scripts/run_pipeline.py`](./scripts/run_pipeline.py) | Parameter-sweep runner that emits raw per-trial CSVs and manifests. |
| [`scripts/render_results.py`](./scripts/render_results.py) | Renderer for figures and LaTeX/CSV tables. |
| [`scripts/reuse_comparison.py`](./scripts/reuse_comparison.py) | Seeds the unchanged GlobaLeaks comparison files used when rendering Table IV. |
| [`data/globaleaks_official_comparison/`](./data/globaleaks_official_comparison/) | Bundled provenance and raw summaries for the official GlobaLeaks side of Table IV. |

## Protocol Operations

| Paper stage | Rust entry point |
| --- | --- |
| `Setup` | `tnibs::signer`, `tgs::keygen`, `opening::keygen` |
| `RegU` | `tnibs::register` |
| `RegIss` | `tnibs::prepare_issue`, `tnibs::issue` |
| `RegObt` | `tnibs::obtain` / `tnibs::obtain_with_randomness` |
| `RepGen` | `protocol::generate` / `protocol::generate_stream` |
| `PostAccept` | `protocol::Ledger::accept` |
| `RepDec` | `opening::contribute` |
| `RepCom` | `opening::combine` / `opening::combine_to_sink` |

## Setup

The recorded artifact environment used Ubuntu 24.04, Python 3.12, OpenSSL, and
a Xeon Gold 6133 server for server-side timings. The checked-in `Cargo.lock`
was generated with Rust 1.89.0 and is intended for Rust 1.89 or newer.

```bash
git clone https://github.com/Zora-G/AWARE-BN462.git
cd AWARE-BN462

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

cargo build --release --locked --features benchmarks
cargo test --locked
```

On macOS with Homebrew OpenSSL, set the library path before building if Cargo
cannot find OpenSSL:

```bash
export LIBRARY_PATH="$(brew --prefix openssl@3)/lib"
```

## Benchmark Entry Points

The benchmark binary has one positional interface:

```bash
target/release/aware-bench <operation> <runs> <warmups> <n> <t> <m> <payload_bytes> <users> <workers> <clients> [stream]
```

Supported operations are `Setup`, `RegU`, `RegIss`, `RegObt`, `TGSEnc`,
`RepGen`, `PostAccept`, `RepDec`, `RepCom`, `CompleteOpen`,
`HolderAblation`, `OpeningAblation`, `EpochIssuance`, `BB`, and
`ReplayRace`.

Example with the default paper parameters:

```bash
target/release/aware-bench RepGen 30 10 5 3 15 1048576 1 8 1
```

## Reproduce Results

Run the full public artifact script for Table II, Fig. 2, Fig. 3, and Table III:

```bash
scripts/run_fig2_fig3_table2_table3.sh
```

Outputs are written under `results/paper/` and `figures/paper/`. For servers
where CPU pinning is required, set `AWARE_CPUS`:

```bash
AWARE_CPUS=0-39 scripts/run_fig2_fig3_table2_table3.sh
```

Run only the AWARE-side benchmark needed for Table IV:

```bash
scripts/run_table_iv_aware.sh
```

Seed the bundled GlobaLeaks comparison files when rendering Table IV:

```bash
scripts/seed_table_iv_comparison.sh
```

The renderer writes `table_II.csv`, `table_II.tex`, `table_III.csv`,
`table_III.tex`, `table_IV.csv`, and `table_IV.tex` under
`results/paper/summary/`. It also writes both internal and manuscript-facing
figure names:

| Manuscript artifact | Output files |
| --- | --- |
| Fig. 2 protocol costs | `fig2_aware_bn462.{pdf,png,svg}` |
| Fig. 3 scalability | `fig3_aware_bn462.{pdf,png,svg}` |
| Internal protocol-cost name | `fig3_bn462.{pdf,png,svg}` |
| Internal scalability name | `fig4_bn462.{pdf,png,svg}` |

## Reproducibility Notes

The implementation uses MIRACL Core BN462, SHA-256 transcripts, AES-256-GCM
with 16-byte IVs and 16-byte tags, and AWCE/AWCL canonical framing. Large
payload report generation uses the streaming path at and above 50 MiB.

Table IV reuses the unchanged official GlobaLeaks 5.0.99 comparison data from
the same Xeon host and keeps the original provenance files in `data/`. The
AWARE columns are regenerated by `scripts/run_table_iv_aware.sh`.

See [`MIGRATION.md`](./MIGRATION.md) for the precise migration contract and
cryptographic instantiation decisions.

## License

This repository is a public research snapshot. The source is provided under the
proprietary terms recorded in [`CITATION.cff`](./CITATION.cff); no broad
open-source license is granted. Third-party dependencies retain their own
licenses.
