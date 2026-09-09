//! Paper-operation timers. Fixture construction precedes each measured boundary.
use aware_bn462::{
    algebra::*,
    encoding,
    opening::{self, Attributed},
    protocol::{self, Ledger, Submission},
    tgs,
    tnibs::{self, Epoch},
};
use rayon::prelude::*;
use std::{
    hint::black_box,
    io::{self, Write},
    sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
struct Config {
    op: String,
    runs: usize,
    warmups: usize,
    n: usize,
    t: usize,
    m: usize,
    payload: usize,
    users: usize,
    workers: usize,
    clients: usize,
    stream: bool,
}
impl Config {
    fn parse() -> Self {
        let args: Vec<_> = std::env::args().skip(1).collect();
        let n = |i: usize| args[i].parse().unwrap();
        Self {
            op: args[0].clone(),
            runs: n(1),
            warmups: n(2),
            n: n(3),
            t: n(4),
            m: n(5),
            payload: n(6),
            users: n(7),
            workers: n(8),
            clients: n(9),
            stream: args.get(10).is_some_and(|mode| mode == "stream"),
        }
    }
    fn row(&self, run: usize, variant: &str, metric: &str, unit: &str, value: f64) {
        println!(
            "{},{run},{variant},{},{},{},{},{},{},{},{metric},{unit},{value:.9}",
            self.op, self.n, self.t, self.m, self.payload, self.users, self.workers, self.clients
        );
        io::stdout().flush().unwrap()
    }
}
struct Fixture {
    sk: tnibs::SignerSecret,
    signer: tnibs::SignerPublic,
    user: tnibs::Recipient,
    epoch: Epoch,
    token: tnibs::Finalized,
    pk: tgs::PublicKey,
    secrets: Vec<tgs::SecretShare>,
    opening: opening::OpeningPublic,
    opening_secret: opening::OpeningSecret,
}
impl Fixture {
    fn new(c: &Config, r: &mut Random) -> Self {
        let (sk, signer) = tnibs::signer(r);
        let user = tnibs::register(r);
        let epoch = Epoch::new("epoch-0", c.m);
        let pre = tnibs::issue(
            &tnibs::prepare_issue(&sk, &user.public, &epoch),
            &epoch,
            1,
            r,
        );
        let token = tnibs::obtain(&pre, &user, r);
        let (pk, secrets) = tgs::keygen(c.n, c.t, r);
        let (opening, opening_secret) = opening::keygen(r);
        Self {
            sk,
            signer,
            user,
            epoch,
            token,
            pk,
            secrets,
            opening,
            opening_secret,
        }
    }
    fn report(&self, c: &Config, r: &mut Random) -> Submission {
        if c.payload >= 50 * 1024 * 1024 {
            protocol::generate_stream(
                &self.pk,
                &mut io::repeat(82),
                c.payload,
                &self.token,
                &self.user.x,
                &self.epoch,
                r,
            )
            .unwrap()
        } else {
            protocol::generate(
                &self.pk,
                &vec![82; c.payload],
                &self.token,
                &self.user.x,
                &self.epoch,
                r,
            )
        }
    }
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn main() {
    let c = Config::parse();
    println!(
        "operation,run,variant,n,t,m,payload_bytes,users,workers,concurrency,metric,unit,value"
    );
    let mut r = Random::new();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(c.workers)
        .build()
        .unwrap();
    let f = Fixture::new(&c, &mut r);
    match c.op.as_str() {
        "EpochIssuance" => issuance(&c, &f, &pool),
        "BB" => bb(&c, &f, &pool),
        "ReplayRace" => replay(&c, &f, &pool),
        "HolderAblation" => holder_ablation(&c, &f),
        "OpeningAblation" => opening_ablation(&c, &f, &pool),
        _ => core(&c, &f, &pool),
    }
}
fn core(c: &Config, f: &Fixture, pool: &rayon::ThreadPool) {
    let mut r = Random::new();
    let ctx = tnibs::prepare_issue(&f.sk, &f.user.public, &f.epoch);
    let pre: Vec<_> = (1..=c.m)
        .map(|j| tnibs::issue(&ctx, &f.epoch, j, &mut r))
        .collect();
    let inverse = f.user.x.inverse();
    let message = if !c.stream && c.payload < 50 * 1024 * 1024 {
        vec![82; c.payload]
    } else {
        vec![]
    };
    for trial in 0..c.warmups + c.runs {
        let run = trial.saturating_sub(c.warmups) + 1;
        let measured = trial >= c.warmups;
        let (time, bytes) = match c.op.as_str() {
            "Setup" => {
                let start = Instant::now();
                black_box(tnibs::signer(&mut r));
                black_box(tgs::keygen(c.n, c.t, &mut r));
                black_box(opening::keygen(&mut r));
                (elapsed(start), 0)
            }
            "RegU" => {
                let start = Instant::now();
                let user = tnibs::register(&mut r);
                let time = elapsed(start);
                (
                    time,
                    encoding::encode("AWARE-REGU-v1", &[&user.public.encode()]).len(),
                )
            }
            "RegIss" => {
                let start = Instant::now();
                let tokens: Vec<_> = (1..=c.m)
                    .map(|j| tnibs::issue(&ctx, &f.epoch, j, &mut r))
                    .collect();
                let time = elapsed(start);
                (time, tokens.iter().map(|p| p.encode().len()).sum())
            }
            "RegObt" => {
                let start = Instant::now();
                for p in &pre {
                    black_box(tnibs::obtain_with_randomness(p, &inverse, r.nonzero()));
                }
                (elapsed(start), 0)
            }
            "TGSEnc" | "RepGen" => {
                let start = Instant::now();
                if c.op == "TGSEnc" {
                    let ct = if message.is_empty() {
                        tgs::encrypt_stream(
                            &f.pk,
                            &mut io::repeat(82),
                            c.payload,
                            &f.token.token.encode(),
                            &mut r,
                        )
                        .unwrap()
                    } else {
                        tgs::encrypt(&f.pk, &message, &f.token.token.encode(), &mut r)
                    };
                    let time = elapsed(start);
                    black_box(ct);
                    (time, 0)
                } else {
                    let sub = if message.is_empty() {
                        protocol::generate_stream(
                            &f.pk,
                            &mut io::repeat(82),
                            c.payload,
                            &f.token,
                            &f.user.x,
                            &f.epoch,
                            &mut r,
                        )
                        .unwrap()
                    } else {
                        protocol::generate(&f.pk, &message, &f.token, &f.user.x, &f.epoch, &mut r)
                    };
                    let time = elapsed(start);
                    let size = sub.encoded_len();
                    black_box(sub);
                    (time, size)
                }
            }
            "PostAccept" => {
                let sub = f.report(c, &mut r);
                let ledger = Ledger::default();
                let start = Instant::now();
                ledger.accept(&f.signer, &f.epoch, sub).unwrap();
                (elapsed(start), 0)
            }
            "RepDec" | "RepCom" | "CompleteOpen" => {
                let ledger = Ledger::default();
                let record = ledger
                    .accept(&f.signer, &f.epoch, f.report(c, &mut r))
                    .unwrap();
                let context = opening::prepare(&ledger, &record, &f.pk).unwrap();
                if c.op == "RepDec" {
                    let start = Instant::now();
                    let share =
                        opening::contribute(&f.opening, &f.secrets[0], &context, &mut r).unwrap();
                    let time = elapsed(start);
                    (time, share.encode().len())
                } else {
                    let prepared = if c.op == "RepCom" {
                        Some(contributions(f, &context, pool, c.t))
                    } else {
                        None
                    };
                    let start = Instant::now();
                    let shares = prepared.unwrap_or_else(|| contributions(f, &context, pool, c.t));
                    let out = opening::combine_to_sink(
                        &f.opening,
                        &f.opening_secret,
                        &f.pk,
                        &context,
                        &shares,
                        &mut io::sink(),
                    );
                    let time = elapsed(start);
                    assert_eq!(out.plaintext.unwrap(), c.payload);
                    let bytes = if c.op == "CompleteOpen" {
                        shares.iter().map(|s| s.contribution.encode().len()).sum()
                    } else {
                        0
                    };
                    (time, bytes)
                }
            }
            _ => panic!("operation"),
        };
        if measured {
            c.row(run, "aware", "latency", "ms", time);
            if bytes > 0 {
                c.row(run, "aware", "communication", "bytes", bytes as f64)
            }
            if c.op == "RepGen" || c.op == "TGSEnc" {
                c.row(
                    run,
                    "aware",
                    "throughput",
                    "MiB/s",
                    c.payload as f64 / (1024.0 * 1024.0) / (time / 1000.0),
                )
            }
        }
    }
}
fn contributions(
    f: &Fixture,
    ctx: &opening::Context,
    pool: &rayon::ThreadPool,
    t: usize,
) -> Vec<Attributed> {
    pool.install(|| {
        f.secrets[..t]
            .par_iter()
            .map(|s| Attributed {
                member: s.index,
                contribution: opening::contribute(&f.opening, s, ctx, &mut Random::new()).unwrap(),
            })
            .collect()
    })
}
fn issuance(c: &Config, f: &Fixture, pool: &rayon::ThreadPool) {
    let mut r = Random::new();
    let prepared: Vec<_> = (0..c.users)
        .map(|_| tnibs::prepare_issue(&f.sk, &tnibs::register(&mut r).public, &f.epoch))
        .collect();
    for trial in 0..c.warmups + c.runs {
        let count = if trial < c.warmups {
            c.users.min(10)
        } else {
            c.users
        };
        let start = Instant::now();
        let issued: usize = pool.install(|| {
            prepared[..count]
                .par_iter()
                .map_init(Random::new, |r, ctx| {
                    for j in 1..=c.m {
                        black_box(tnibs::issue(ctx, &f.epoch, j, r));
                    }
                    c.m
                })
                .sum()
        });
        let time = elapsed(start);
        assert_eq!(issued, count * c.m);
        if trial >= c.warmups {
            let run = trial - c.warmups + 1;
            c.row(run, "aware", "latency", "ms", time);
            c.row(run, "aware", "issued_tokens", "count", issued as f64);
            c.row(
                run,
                "aware",
                "tokens_per_second",
                "tokens/s",
                issued as f64 / (time / 1000.0),
            )
        }
    }
}
fn replay(c: &Config, f: &Fixture, pool: &rayon::ThreadPool) {
    let mut r = Random::new();
    let epoch = Epoch::new("revision2-system-epoch-replay", c.m);
    let pre = tnibs::issue(
        &tnibs::prepare_issue(&f.sk, &f.user.public, &epoch),
        &epoch,
        1,
        &mut r,
    );
    let token = tnibs::obtain(&pre, &f.user, &mut r);
    let reports: Vec<_> = (0..c.clients)
        .map(|i| {
            let mut message = vec![b'a'; c.payload];
            let prefix = format!("candidate-{i}");
            let len = prefix.len().min(message.len());
            message[..len].copy_from_slice(&prefix.as_bytes()[..len]);
            protocol::generate(&f.pk, &message, &token, &f.user.x, &epoch, &mut r)
        })
        .collect();
    for trial in 0..c.warmups + c.runs {
        let ledger = Ledger::default();
        let start = Instant::now();
        let accepted: usize = pool.install(|| {
            reports
                .par_iter()
                .map(|s| usize::from(ledger.accept(&f.signer, &epoch, s.clone()).is_ok()))
                .sum()
        });
        let time = elapsed(start);
        assert_eq!(accepted, 1);
        if trial >= c.warmups {
            let run = trial - c.warmups + 1;
            c.row(run, "aware", "accepted", "count", accepted as f64);
            c.row(
                run,
                "aware",
                "rejected",
                "count",
                (c.clients - accepted) as f64,
            );
            c.row(run, "aware", "latency", "ms", time)
        }
    }
}
fn bb(c: &Config, f: &Fixture, pool: &rayon::ThreadPool) {
    // Capacity is fixture provisioning; every request uses a distinct valid token.
    let capacity = std::env::var("AWARE_SUBMISSION_POOL")
        .map(|v| v.parse().unwrap())
        .unwrap_or(65536usize);
    eprintln!("preparing {capacity} complete submissions outside timers");
    let reports: Vec<_> = pool.install(|| {
        (0..capacity)
            .into_par_iter()
            .map_init(Random::new, |r, index| {
                let user = tnibs::register(r);
                let epoch = Epoch::new(&format!("revision2-system-epoch-{index}"), c.m);
                let pre = tnibs::issue(
                    &tnibs::prepare_issue(&f.sk, &user.public, &epoch),
                    &epoch,
                    index % c.m + 1,
                    r,
                );
                let tok = tnibs::obtain(&pre, &user, r);
                let mut message = vec![b'a'; c.payload];
                let prefix = format!("-{index}");
                let len = prefix.len().min(message.len());
                message[..len].copy_from_slice(&prefix.as_bytes()[..len]);
                let submission = protocol::generate(&f.pk, &message, &tok, &user.x, &epoch, r);
                (epoch, submission)
            })
            .collect()
    });
    if c.warmups > 0 {
        black_box(bb_phase(c, f, pool, &reports, c.warmups));
    }
    for run in 1..=c.runs {
        let (accepted, rejected, seconds) = bb_phase(c, f, pool, &reports, 60);
        c.row(
            run,
            "aware",
            "throughput",
            "reports/s",
            accepted as f64 / seconds,
        );
        c.row(run, "aware", "accepted", "count", accepted as f64);
        c.row(run, "aware", "rejected", "count", rejected as f64);
        c.row(run, "aware", "elapsed", "s", seconds)
    }
}
fn bb_phase(
    c: &Config,
    f: &Fixture,
    pool: &rayon::ThreadPool,
    reports: &[(Epoch, Submission)],
    seconds: usize,
) -> (usize, usize, f64) {
    let ledger = Ledger::default();
    let cursor = AtomicUsize::new(0);
    let accepted = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let gate = Barrier::new(c.clients + 1);
    let start = std::sync::OnceLock::<Instant>::new();
    std::thread::scope(|scope| {
        for _ in 0..c.clients {
            let (ledger, cursor, accepted, rejected, gate, start) =
                (&ledger, &cursor, &accepted, &rejected, &gate, &start);
            scope.spawn(move || {
                gate.wait();
                while start.get().unwrap().elapsed().as_secs_f64() < seconds as f64 {
                    let index = cursor.fetch_add(1, Ordering::Relaxed);
                    assert!(
                        index < reports.len(),
                        "complete submission fixture pool exhausted"
                    );
                    if pool.install(|| {
                        ledger
                            .accept(&f.signer, &reports[index].0, reports[index].1.clone())
                            .is_ok()
                    }) {
                        accepted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
        start.set(Instant::now()).unwrap();
        gate.wait();
    });
    (
        accepted.load(Ordering::Relaxed),
        rejected.load(Ordering::Relaxed),
        start.get().unwrap().elapsed().as_secs_f64(),
    )
}
fn holder_ablation(c: &Config, f: &Fixture) {
    let mut r = Random::new();
    let message = vec![82; c.payload];
    for trial in 0..c.warmups + c.runs {
        let start = Instant::now();
        let ct = tgs::encrypt(&f.pk, &message, &f.token.token.encode(), &mut r);
        black_box(ct.encode());
        let base_gen = elapsed(start);
        let start = Instant::now();
        let sub = protocol::generate(&f.pk, &message, &f.token, &f.user.x, &f.epoch, &mut r);
        let aware_gen = elapsed(start);
        let base_ledger = Ledger::default();
        let candidate = sub.clone();
        let start = Instant::now();
        base_ledger
            .accept_without_holder(&f.signer, &f.epoch, candidate)
            .unwrap();
        let base_verify = elapsed(start);
        let aware_ledger = Ledger::default();
        let candidate = sub.clone();
        let start = Instant::now();
        aware_ledger.accept(&f.signer, &f.epoch, candidate).unwrap();
        let aware_verify = elapsed(start);
        let base_bytes = encoding::encode(
            "AWARE-SUBMISSION-v1",
            &[&f.token.token.encode(), &ct.encode()],
        )
        .len();
        let aware_bytes = sub.encoded_len();
        if trial >= c.warmups {
            let run = trial - c.warmups + 1;
            for (metric, base, aware, unit) in [
                ("RepGen", base_gen, aware_gen, "ms"),
                ("PostAccept", base_verify, aware_verify, "ms"),
                ("Submission", base_bytes as f64, aware_bytes as f64, "bytes"),
            ] {
                c.row(run, "baseline", metric, unit, base);
                c.row(run, "aware", metric, unit, aware);
                c.row(run, "delta", metric, unit, aware - base)
            }
        }
    }
}
fn opening_ablation(c: &Config, f: &Fixture, pool: &rayon::ThreadPool) {
    let mut r = Random::new();
    let ledger = Ledger::default();
    let rec = ledger
        .accept(&f.signer, &f.epoch, f.report(c, &mut r))
        .unwrap();
    let ctx = opening::prepare(&ledger, &rec, &f.pk).unwrap();
    let sub = rec.submission();
    let ad = sub.token.encode();
    for trial in 0..c.warmups + c.runs {
        let start = Instant::now();
        let plain = tgs::share_dec(&f.secrets[0], &sub.ciphertext, &ad).unwrap();
        let base_dec = elapsed(start);
        let start = Instant::now();
        let share = opening::contribute(&f.opening, &f.secrets[0], &ctx, &mut r).unwrap();
        let aware_dec = elapsed(start);
        let plain_shares: Vec<_> = f.secrets[..c.t]
            .iter()
            .map(|s| tgs::share_dec(s, &sub.ciphertext, &ad).unwrap())
            .collect();
        let start = Instant::now();
        let plain_message = tgs::combine(&f.pk, &sub.ciphertext, &ad, &plain_shares).unwrap();
        let base_com = elapsed(start);
        let entries = contributions(f, &ctx, pool, c.t);
        let start = Instant::now();
        let message = opening::combine(&f.opening, &f.opening_secret, &f.pk, &ctx, &entries)
            .plaintext
            .unwrap();
        let aware_com = elapsed(start);
        assert_eq!(plain_message, message);
        let start = Instant::now();
        let plain_shares: Vec<_> = pool.install(|| {
            f.secrets[..c.t]
                .par_iter()
                .map(|s| tgs::share_dec(s, &sub.ciphertext, &ad).unwrap())
                .collect()
        });
        black_box(tgs::combine(&f.pk, &sub.ciphertext, &ad, &plain_shares).unwrap());
        let base_complete = elapsed(start);
        let start = Instant::now();
        let entries = contributions(f, &ctx, pool, c.t);
        black_box(
            opening::combine(&f.opening, &f.opening_secret, &f.pk, &ctx, &entries)
                .plaintext
                .unwrap(),
        );
        let aware_complete = elapsed(start);
        let plain_bytes = plain.encode().len();
        let aware_bytes = share.encode().len();
        if trial >= c.warmups {
            let run = trial - c.warmups + 1;
            for (metric, base, aware, unit) in [
                ("RepDec", base_dec, aware_dec, "ms"),
                ("RepCom", base_com, aware_com, "ms"),
                ("CompleteOpen", base_complete, aware_complete, "ms"),
                (
                    "Contribution",
                    plain_bytes as f64,
                    aware_bytes as f64,
                    "bytes",
                ),
            ] {
                c.row(run, "baseline", metric, unit, base);
                c.row(run, "aware", metric, unit, aware);
                c.row(run, "delta", metric, unit, aware - base)
            }
        }
    }
}
