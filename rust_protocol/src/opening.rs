//! Protocol 4: publicly verifiable encrypted shares with authenticated attribution.
use crate::{
    algebra::*,
    encoding::{self, Transcript},
    hash,
    protocol::{AcceptedRecord, Ledger},
    tgs::{self, PublicKey, SecretShare, Share},
};
use std::collections::BTreeSet;
#[derive(Clone)]
pub struct OpeningPublic {
    pub p: G1,
    q: GT,
}
pub struct OpeningSecret {
    pub z: Scalar,
}
pub fn keygen(rng: &mut Random) -> (OpeningPublic, OpeningSecret) {
    let z = rng.nonzero();
    let p = G1::generator().mul(&z);
    let q = pairing(&p, &G2::generator());
    (OpeningPublic { p, q }, OpeningSecret { z })
}
#[derive(Clone)]
pub struct Proof {
    pub c: Scalar,
    pub s: Scalar,
}
#[derive(Clone)]
pub struct Contribution {
    pub index: usize,
    pub sid: [u8; 32],
    pub r: G1,
    pub encrypted: G1,
    pub proof: Proof,
}
/// The authenticated transport supplies `member`; contribution bytes carry index.
#[derive(Clone)]
pub struct Attributed {
    pub member: usize,
    pub contribution: Contribution,
}
pub struct Context<'a> {
    record: &'a AcceptedRecord,
    u: G1,
    prefixes: Vec<Transcript>,
}
pub struct Outcome<T = Vec<u8>> {
    pub plaintext: Result<T, &'static str>,
    pub blame: Vec<usize>,
    pub valid_members: Vec<usize>,
}
pub fn prepare<'a>(
    ledger: &Ledger,
    record: &'a AcceptedRecord,
    pk: &PublicKey,
) -> Result<Context<'a>, &'static str> {
    if !ledger.contains(record) || *record.sid() != record.submission().sid() {
        return Err("accepted record");
    }
    let sub = record.submission();
    let token = sub.token.encode();

    let prefixes = (1..=pk.shares.len())
        .map(|i| {
            let mut h = Transcript::new(hash::H3_OPEN, 8, sub.frame);
            h.field(&(i as u32).to_be_bytes());
            h.field(record.sid());
            h.field_with(sub.ciphertext.encoded_len(sub.frame), |w| {
                sub.ciphertext.write_to(w, sub.frame)
            })
            .unwrap();
            h.field(&token);
            h
        })
        .collect();
    Ok(Context {
        record,
        u: hash::ciphertext(&sub.ciphertext.v, &token),
        prefixes,
    })
}
fn challenge(mut prefix: Transcript, r: &G1, c: &G1, u: &G1, v: &GT) -> Scalar {
    for b in [r.encode(), c.encode(), u.encode(), v.encode()] {
        prefix.field(&b)
    }
    Scalar::from_digest(&prefix.finish())
}
pub fn contribute(
    public: &OpeningPublic,
    secret: &SecretShare,
    ctx: &Context,
    rng: &mut Random,
) -> Result<Contribution, &'static str> {
    let ct = &ctx.record.submission().ciphertext;
    if !tgs::verify_prepared(ct, &ctx.u) {
        return Err("ciphertext verification");
    }
    let w = ct.v.mul(&secret.alpha);
    let r = rng.nonzero();
    let k = rng.nonzero();
    let commitment = G1::generator().mul(&r);
    let encrypted = w.add(&public.p.mul(&r));
    let u = G1::generator().mul(&k);
    let v = public.q.pow(&k);
    let c = challenge(
        ctx.prefixes[secret.index - 1].clone(),
        &commitment,
        &encrypted,
        &u,
        &v,
    );
    let s = k.add(&c.mul(&r));
    Ok(Contribution {
        index: secret.index,
        sid: *ctx.record.sid(),
        r: commitment,
        encrypted,
        proof: Proof { c, s },
    })
}
pub fn verify(public: &OpeningPublic, pk: &PublicKey, ctx: &Context, c: &Contribution) -> bool {
    if c.sid != *ctx.record.sid()
        || c.index == 0
        || c.index > pk.shares.len()
        || c.r.is_identity()
        || c.encrypted.is_identity()
    {
        return false;
    }
    let ct = &ctx.record.submission().ciphertext;
    let e = pairing_product(&[
        (&c.encrypted, &G2::generator()),
        (&ct.v.neg(), &pk.shares[c.index - 1].theta_hat),
    ]);
    let u = G1::generator().mul(&c.proof.s).sub(&c.r.mul(&c.proof.c));
    let v = public.q.pow(&c.proof.s).mul(&e.pow(&c.proof.c.neg()));
    challenge(
        ctx.prefixes[c.index - 1].clone(),
        &c.r,
        &c.encrypted,
        &u,
        &v,
    ) == c.proof.c
}
pub fn combine_to_sink(
    public: &OpeningPublic,
    secret: &OpeningSecret,
    pk: &PublicKey,
    ctx: &Context,
    entries: &[Attributed],
    sink: &mut dyn std::io::Write,
) -> Outcome<usize> {
    let ct = &ctx.record.submission().ciphertext;
    let mut blame = Vec::new();
    let mut valid = Vec::new();
    let mut seen = BTreeSet::new();
    if !tgs::verify_prepared(ct, &ctx.u) {
        return Outcome {
            plaintext: Err("ciphertext verification"),
            blame,
            valid_members: vec![],
        };
    }
    for entry in entries {
        let c = &entry.contribution;
        if c.sid != *ctx.record.sid()
            || entry.member == 0
            || entry.member > pk.shares.len()
            || !seen.insert(entry.member)
        {
            continue;
        }
        if c.index != entry.member || !verify(public, pk, ctx, c) {
            blame.push(entry.member);
            continue;
        }
        let share = Share {
            index: c.index,
            w: c.encrypted.sub(&c.r.mul(&secret.z)),
        };
        if tgs::share_verify(pk, ct, &share) {
            valid.push(share)
        } else {
            blame.push(entry.member)
        }
    }
    let valid_members = valid.iter().map(|s| s.index).collect();
    let plaintext = if valid.len() < pk.threshold {
        Err("threshold")
    } else {
        crate::payload::decrypt(
            &hash::key(&ct.v, &tgs::reconstruct(&valid[..pk.threshold])),
            &ct.encrypted,
            sink,
        )
        .map_err(|_| "AES-GCM authentication")
    };
    Outcome {
        plaintext,
        blame,
        valid_members,
    }
}
impl Contribution {
    pub fn encode(&self) -> Vec<u8> {
        let proof = encoding::encode(
            "AWARE-OPEN-PROOF-v1",
            &[&self.proof.c.encode(), &self.proof.s.encode()],
        );
        encoding::encode(
            "AWARE-OPEN-CONTRIBUTION-v1",
            &[
                &(self.index as u32).to_be_bytes(),
                &self.sid,
                &self.r.encode(),
                &self.encrypted.encode(),
                &proof,
            ],
        )
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        let f = encoding::decode("AWARE-OPEN-CONTRIBUTION-v1", b, 5)?;
        let p = encoding::decode("AWARE-OPEN-PROOF-v1", f[4], 2)?;
        Ok(Self {
            index: u32::from_be_bytes(f[0].try_into().map_err(|_| "index length")?) as usize,
            sid: f[1].try_into().map_err(|_| "sid length")?,
            r: G1::decode(f[2])?,
            encrypted: G1::decode(f[3])?,
            proof: Proof {
                c: Scalar::decode(p[0])?,
                s: Scalar::decode(p[1])?,
            },
        })
    }
}

pub fn combine(
    public: &OpeningPublic,
    secret: &OpeningSecret,
    pk: &PublicKey,
    ctx: &Context,
    entries: &[Attributed],
) -> Outcome {
    let mut bytes = Vec::new();
    let out = combine_to_sink(public, secret, pk, ctx, entries, &mut bytes);
    Outcome {
        plaintext: out.plaintext.map(|_| bytes),
        blame: out.blame,
        valid_members: out.valid_members,
    }
}
