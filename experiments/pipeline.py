#!/usr/bin/env python3
import argparse
import csv
import io
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'rust_protocol/target/release/aware-bench'
TARGETS = ['table2', 'table3', 'table4', 'fig2', 'fig3']

K, M, G = 1 << 10, 1 << 20, 1 << 30
WORKERS = {'client': 8, 'server': 40}
ROUNDS = 30
TOKENS = [1, 5, 10, 15, 20, 30]
PAYLOADS = [10 * K, 100 * K, 512 * K, M, 20 * M, 50 * M, 100 * M, 150 * M, 500 * M, G]
COMMITTEES = [6, 9, 12, 15]
THRESHOLDS = [2, 4, 6, 8, 10]
USERS = [10, 100, 500, 1000, 5000, 10000]
AS_WORKERS = [1, 4, 8, 16]
CLIENTS = [1, 2, 4, 8, 16, 32, 64, 128, 256]
COPIES = [2, 4, 8, 16, 32, 64]
TABLE4_PAYLOADS = [10 * K, M, 100 * M, G, 5 * G]
ARGS = ['runs', 'warmups', 'n', 't', 'm', 'payload', 'users', 'workers', 'clients']


def jobs(role):
    out = []

    def add(name, op, targets, runs=30, warmups=10, n=5, t=3, m=15, payload=M, users=1,
            workers=None, clients=1, rounds=1):
        out.append(dict(name=name, op=op, targets=targets, runs=runs, warmups=warmups, n=n, t=t,
                        m=m, payload=payload, users=users, workers=workers or WORKERS[role],
                        clients=clients, rounds=rounds))

    if role == 'client':
        for m in TOKENS:
            add(f'regobt_m{m}', 'RegObt', ['fig2', 'table2'] if m == 15 else ['fig2'], m=m)
        add('regu', 'RegU', ['table2'])
        for p in PAYLOADS:
            runs, warmups = (5, 2) if p >= 50 * M else (30, 10)
            add(f'tgsenc_{p}', 'TGSEnc', ['fig2'], runs, warmups, payload=p, rounds=ROUNDS)
            if p != M:
                add(f'repgen_{p}', 'RepGen', ['fig2'], runs, warmups, payload=p, rounds=ROUNDS)
        add('holder', 'HolderAblation', ['table2', 'table3', 'fig2'])
    else:
        for m in TOKENS:
            add(f'regiss_m{m}', 'RegIss', ['fig2', 'table2'] if m == 15 else ['fig2'], m=m)
        for n in COMMITTEES:
            for t in THRESHOLDS:
                if t <= n:
                    add(f'completeopen_n{n}_t{t}', 'CompleteOpen', ['fig2'], n=n, t=t)
        for op in ['Setup', 'PostAccept', 'RepDec', 'RepCom', 'CompleteOpen']:
            add(op.lower(), op, ['table2'])
        add('holder', 'HolderAblation', ['table3'])
        add('opening', 'OpeningAblation', ['table3'])
        for p in TABLE4_PAYLOADS:
            runs, warmups = (10, 2) if p >= G else (30, 10)
            for op in ['RepGen', 'RepDecFull', 'RepComFull']:
                add(f'{op.lower()}_{p}', op, ['table4'], runs, warmups, payload=p)
        for k in COPIES:
            add(f'replay_k{k}', 'ReplayRace', ['fig3'], 100, 10, clients=k)
        for w in AS_WORKERS:
            for u in USERS:
                add(f'issuance_u{u}_w{w}', 'EpochIssuance', ['fig3'], 10 if u <= 1000 else 3, 10,
                    users=u, workers=w)
        for c in CLIENTS:
            add(f'bb_c{c}', 'BB', ['fig3'], 5, 20, clients=c)
    return out


def run(job, raw, cpus):
    path = raw / f"{job['name']}.csv"
    if path.exists():
        return
    rows = []
    for r in range(job['rounds']):
        cmd = [str(BINARY), job['op']] + [str(job[k]) for k in ARGS]
        if job['rounds'] > 1:
            cmd.append('stream')
        if cpus:
            cmd = ['taskset', '-c', cpus] + cmd
        print(' '.join(cmd), flush=True)
        stdout = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=True).stdout
        for row in csv.DictReader(io.StringIO(stdout)):
            row['run'] = str(r * job['runs'] + int(row['run']))
            rows.append(row)
    part = path.with_suffix('.part')
    with part.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    part.rename(path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--role', required=True, choices=['client', 'server'])
    p.add_argument('--target', required=True, action='append', choices=TARGETS)
    p.add_argument('--output', type=Path, default=ROOT / 'results')
    p.add_argument('--cpus')
    args = p.parse_args()
    raw = args.output / args.role
    raw.mkdir(parents=True, exist_ok=True)
    for job in jobs(args.role):
        if set(job['targets']) & set(args.target):
            run(job, raw, args.cpus)


if __name__ == '__main__':
    main()
