use crate::{
    algebra::*,
    encoding::{self, Frame, Transcript},
    hash,
    payload::Payload,
    protocol::{self, AcceptedRecord, Ledger, MemberView},
    tgs::{self, Header, PublicKey, SecretShare, Share},
    tnibs::Token,
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
#[derive(Clone)]
pub struct Attributed {
    pub member: usize,
    pub contribution: Contribution,
}
pub struct Context<'a> {
    sid: [u8; 32],
    header: Header,
    u: G1,
    payload: Option<&'a Payload>,
}
impl Context<'_> {
    fn prefix(&self, i: usize) -> Transcript {
        let mut h = Transcript::new(hash::H3_OPEN, 7, Frame::Canonical);
        h.field(&(i as u32).to_be_bytes());
        h.field(&self.sid);
        h.field(&self.header.v.encode());
        h
    }
    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }
}
pub struct Outcome<T = Vec<u8>> {
    pub plaintext: Result<T, &'static str>,
    pub blame: Vec<usize>,
    pub valid_members: Vec<usize>,
}
fn context<'a>(
    sid: [u8; 32],
    token: &Token,
    header: Header,
    payload: Option<&'a Payload>,
) -> Context<'a> {
    Context {
        sid,
        u: hash::ciphertext(&header.v, &token.encode()),
        header,
        payload,
    }
}
pub fn prepare_member<'a>(view: &MemberView) -> Result<Context<'a>, &'static str> {
    if protocol::record_id(&view.token, &view.header, &view.proof) != view.sid {
        return Err("accepted record");
    }
    Ok(context(view.sid, &view.token, view.header.clone(), None))
}
pub fn prepare<'a>(
    ledger: &Ledger,
    record: &'a AcceptedRecord,
) -> Result<Context<'a>, &'static str> {
    let sub = record.submission();
    if !ledger.contains(record)
        || protocol::record_id(&sub.token, record.header(), &sub.proof) != *record.sid()
    {
        return Err("accepted record");
    }
    Ok(context(
        *record.sid(),
        &sub.token,
        record.header().clone(),
        Some(&sub.ciphertext.encrypted),
    ))
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
    if !tgs::verify_header(&ctx.header, &ctx.u) {
        return Err("ciphertext verification");
    }
    let w = ctx.header.v.mul(&secret.alpha);
    let r = rng.nonzero();
    let k = rng.nonzero();
    let commitment = G1::generator().mul(&r);
    let encrypted = w.add(&public.p.mul(&r));
    let u = G1::generator().mul(&k);
    let v = public.q.pow(&k);
    let c = challenge(ctx.prefix(secret.index), &commitment, &encrypted, &u, &v);
    let s = k.add(&c.mul(&r));
    Ok(Contribution {
        index: secret.index,
        sid: ctx.sid,
        r: commitment,
        encrypted,
        proof: Proof { c, s },
    })
}
pub fn verify(public: &OpeningPublic, pk: &PublicKey, ctx: &Context, c: &Contribution) -> bool {
    if c.sid != ctx.sid
        || c.index == 0
        || c.index > pk.shares.len()
        || c.r.is_identity()
        || c.encrypted.is_identity()
    {
        return false;
    }
    let neg_c = c.proof.c.neg();
    let u = G1::generator().mul2(&c.proof.s, &c.r, &neg_c);
    let v = pairing_product(&[
        (
            &public.p.mul2(&c.proof.s, &c.encrypted, &neg_c),
            &G2::generator(),
        ),
        (
            &ctx.header.v.mul(&c.proof.c),
            &pk.shares[c.index - 1].theta_hat,
        ),
    ]);
    challenge(ctx.prefix(c.index), &c.r, &c.encrypted, &u, &v) == c.proof.c
}
pub fn combine_to_sink(
    public: &OpeningPublic,
    secret: &OpeningSecret,
    pk: &PublicKey,
    ctx: &Context,
    entries: &[Attributed],
    sink: &mut dyn std::io::Write,
) -> Outcome<usize> {
    let mut blame = Vec::new();
    let mut valid = Vec::new();
    let mut seen = BTreeSet::new();
    let Some(payload) = ctx.payload else {
        return Outcome {
            plaintext: Err("combiner context needs the accepted record"),
            blame,
            valid_members: vec![],
        };
    };
    let v = &ctx.header.v;
    if !tgs::verify_header(&ctx.header, &ctx.u) {
        return Outcome {
            plaintext: Err("ciphertext verification"),
            blame,
            valid_members: vec![],
        };
    }
    for entry in entries {
        let c = &entry.contribution;
        if c.sid != ctx.sid
            || entry.member == 0
            || entry.member > pk.shares.len()
            || seen.contains(&entry.member)
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
        if tgs::share_verify_v(pk, v, &share) {
            seen.insert(entry.member);
            valid.push(share)
        } else {
            blame.push(entry.member)
        }
    }
    let valid_members = valid.iter().map(|s| s.index).collect();
    let plaintext = if valid.len() < pk.threshold {
        Err("threshold")
    } else if hash::payload_digest(payload) != ctx.header.digest {
        Err("payload digest")
    } else {
        crate::payload::decrypt(
            &hash::key(v, &tgs::reconstruct(&valid[..pk.threshold])),
            payload,
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
