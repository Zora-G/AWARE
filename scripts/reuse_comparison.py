#!/usr/bin/env python3
"""Seed the Table IV GlobaLeaks comparison files bundled with this artifact."""
import argparse
import csv
import json
import shutil
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'data/globaleaks_official_comparison'
PAYLOADS = {'10k': 10240, '1m': 1048576, '100m': 104857600,
            '1g': 1073741824, '5g': 5368709120}
COMMIT = '8e015fd4cb8d56c54b8c9d9e0e695d6e815510f5'
OPERATIONS = ('GLSubmitCrypto', 'GLRecipientOpen')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    provenance = []
    for payload in PAYLOADS.values():
        source = args.source / str(payload)
        metadata = json.loads((source / 'metadata.json').read_text())
        raw = list(csv.DictReader((source / 'raw_samples.csv').open()))
        summary = list(csv.DictReader((source / 'summary.csv').open()))
        runs, warmups = (1, 0) if payload >= 1073741824 else (30, 10)
        assert metadata['globaleaks_commit'] == COMMIT
        assert metadata['globaleaks_version'] == '5.0.99'
        assert metadata['payload_size_bytes'] == payload
        assert metadata['recipients'] == 5 and metadata['chunk_bytes'] == 65536
        assert metadata['measured_runs'] == runs and metadata['warmups'] == warmups
        assert metadata['paper_operations'] == list(OPERATIONS)
        for operation in OPERATIONS:
            samples = [r for r in raw if r['operation'] == operation]
            assert sorted(int(r['run']) for r in samples) == list(range(1, runs + 1))
            observed = next(r for r in summary if r['operation'] == operation)
            assert observed['boundary_id'] == metadata['boundary_catalog'][operation]
            assert abs(statistics.fmean(float(r['wall_clock_ms']) for r in samples)
                       - float(observed['mean_ms'])) < 1e-6
        output = args.output / str(payload)
        output.mkdir(parents=True, exist_ok=True)
        for name in ['metadata.json', 'raw_samples.csv', 'summary.csv']:
            shutil.copy2(source / name, output / name)
        if (source / 'original_environment.jsonl').exists():
            shutil.copy2(source / 'original_environment.jsonl', output / 'original_environment.jsonl')
        entry = json.loads((source / 'reused.json').read_text())
        entry.update(dict(runs=runs, warmups=warmups))
        (output / 'reused.json').write_text(json.dumps(entry, indent=2) + '\n')
        provenance.append(entry)
    (args.output / 'reuse_provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print('OFFICIAL_COMPARISON_REUSED: 5 payloads, original raw data and dates retained')


if __name__ == '__main__':
    main()
