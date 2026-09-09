//! Protocols 1 and 2: length-three TNIBS with recipient and epoch binding.
use crate::{
    algebra::*,
    encoding::{decode, encode},
    hash,
};
#[derive(Clone)]
pub struct SignerSecret {
    pub a: [Scalar; 3],
}
#[derive(Clone)]
pub struct SignerPublic {
    pub a: [G2; 3],
}
#[derive(Clone)]
pub struct Recipient {
    pub x: Scalar,
    pub public: G1,
}
#[derive(Clone)]
pub struct Signature {
    pub z: G1,
    pub y: G1,
    pub y_hat: G2,
    pub t: G2,
}
#[derive(Clone)]
pub struct PreToken {
    pub eta: String,
    pub slot: usize,
    pub nonce: Vec<u8>,
    pub h: G1,
    pub psi: G1,
    pub sig: Signature,
}
#[derive(Clone)]
pub struct Token {
    pub eta: String,
    pub rho: G1,
    pub zeta: G1,
    pub sig: Signature,
}
#[derive(Clone)]
pub struct Finalized {
    pub token: Token,
    pub slot: usize,
}
pub struct IssueContext {
    eta: String,
    upk_a1: G1,
    a2: Scalar,
    a3: Scalar,
    tag: G2,
}
#[derive(Clone)]
pub struct Epoch {
    pub eta: String,
    pub slots: Vec<G1>,
    pub tag: G2,
}
impl Epoch {
    pub fn new(eta: &str, m: usize) -> Self {
        Self {
            eta: eta.into(),
            slots: (1..=m).map(|i| hash::slot(eta, i)).collect(),
            tag: hash::tag(eta),
        }
    }
}
pub fn signer(rng: &mut Random) -> (SignerSecret, SignerPublic) {
    let a = std::array::from_fn(|_| rng.nonzero());
    let p = SignerPublic {
        a: std::array::from_fn(|i| G2::generator().mul(&a[i])),
    };
    (SignerSecret { a }, p)
}
pub fn register(rng: &mut Random) -> Recipient {
    let x = rng.nonzero();
    Recipient {
        x,
        public: G1::generator().mul(&x),
    }
}
pub fn prepare_issue(sk: &SignerSecret, public: &G1, epoch: &Epoch) -> IssueContext {
    IssueContext {
        eta: epoch.eta.clone(),
        upk_a1: public.mul(&sk.a[0]),
        a2: sk.a[1],
        a3: sk.a[2],
        tag: epoch.tag.clone(),
    }
}
pub fn issue(ctx: &IssueContext, epoch: &Epoch, slot: usize, rng: &mut Random) -> PreToken {
    issue_with_randomness(ctx, epoch, slot, &rng.nonzero().encode(), rng.nonzero())
}
pub fn issue_with_randomness(
    ctx: &IssueContext,
    epoch: &Epoch,
    slot: usize,
    nonce: &[u8],
    y: Scalar,
) -> PreToken {
    let h = hash::nonce(nonce);
    let psi = epoch.slots[slot - 1].clone();
    let inverse = y.inverse();
    let z = ctx
        .upk_a1
        .add(&h.mul(&ctx.a2))
        .add(&psi.mul(&ctx.a3))
        .mul(&y);
    PreToken {
        eta: ctx.eta.clone(),
        slot,
        nonce: nonce.to_vec(),
        h,
        psi,
        sig: Signature {
            z,
            y: G1::generator().mul(&inverse),
            y_hat: G2::generator().mul(&inverse),
            t: ctx.tag.mul(&inverse),
        },
    }
}
pub fn obtain(pre: &PreToken, user: &Recipient, rng: &mut Random) -> Finalized {
    obtain_with_randomness(pre, &user.x.inverse(), rng.nonzero())
}
pub fn obtain_with_randomness(pre: &PreToken, inverse: &Scalar, omega: Scalar) -> Finalized {
    let inv = omega.inverse();
    Finalized {
        slot: pre.slot,
        token: Token {
            eta: pre.eta.clone(),
            rho: pre.h.mul(inverse),
            zeta: pre.psi.mul(inverse),
            sig: Signature {
                z: pre.sig.z.mul(&inverse.mul(&omega)),
                y: pre.sig.y.mul(&inv),
                y_hat: pre.sig.y_hat.mul(&inv),
                t: pre.sig.t.mul(&inv),
            },
        },
    }
}
pub fn verify(pk: &SignerPublic, token: &Token, epoch: &Epoch) -> bool {
    let s = &token.sig;
    if token.eta != epoch.eta
        || [&token.rho, &token.zeta, &s.z, &s.y]
            .iter()
            .any(|p| p.is_identity())
        || s.y_hat.is_identity()
        || s.t.is_identity()
    {
        return false;
    }
    let g = G1::generator();
    let h = G2::generator();
    pairing_product(&[
        (&s.z, &s.y_hat),
        (&g.neg(), &pk.a[0]),
        (&token.rho.neg(), &pk.a[1]),
        (&token.zeta.neg(), &pk.a[2]),
    ]) == GT::identity()
        && pairing_product(&[(&s.y, &h), (&g.neg(), &s.y_hat)]) == GT::identity()
        && pairing_product(&[(&g, &s.t), (&s.y.neg(), &epoch.tag)]) == GT::identity()
}
impl PreToken {
    pub fn encode(&self) -> Vec<u8> {
        let s = &self.sig;
        encode(
            "AWARE-CurrentTNIBS-PreToken-v1",
            &[
                self.eta.as_bytes(),
                &(self.slot as u32).to_be_bytes(),
                &self.nonce,
                &self.h.encode(),
                &self.psi.encode(),
                &s.z.encode(),
                &s.y.encode(),
                &s.y_hat.encode(),
                &s.t.encode(),
            ],
        )
    }
}
impl Token {
    pub fn encode(&self) -> Vec<u8> {
        let s = &self.sig;
        encode(
            "AWARE-CurrentTNIBS-Token-v1",
            &[
                self.eta.as_bytes(),
                &self.rho.encode(),
                &self.zeta.encode(),
                &s.z.encode(),
                &s.y.encode(),
                &s.y_hat.encode(),
                &s.t.encode(),
            ],
        )
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        let f = decode("AWARE-CurrentTNIBS-Token-v1", b, 7)?;
        Ok(Self {
            eta: std::str::from_utf8(f[0]).map_err(|_| "epoch UTF8")?.into(),
            rho: G1::decode(f[1])?,
            zeta: G1::decode(f[2])?,
            sig: Signature {
                z: G1::decode(f[3])?,
                y: G1::decode(f[4])?,
                y_hat: G2::decode(f[5])?,
                t: G2::decode(f[6])?,
            },
        })
    }
}
impl PreToken {
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        let f = decode("AWARE-CurrentTNIBS-PreToken-v1", b, 9)?;
        Ok(Self {
            eta: std::str::from_utf8(f[0]).map_err(|_| "epoch UTF8")?.into(),
            slot: u32::from_be_bytes(f[1].try_into().map_err(|_| "slot length")?) as usize,
            nonce: f[2].into(),
            h: G1::decode(f[3])?,
            psi: G1::decode(f[4])?,
            sig: Signature {
                z: G1::decode(f[5])?,
                y: G1::decode(f[6])?,
                y_hat: G2::decode(f[7])?,
                t: G2::decode(f[8])?,
            },
        })
    }
}
