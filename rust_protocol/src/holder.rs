//! Protocol 3 m-way Schnorr OR proof with a hidden real branch.
use crate::{
    algebra::*,
    encoding::{self, Frame, Transcript},
    hash,
    tnibs::{Epoch, Token},
};
#[derive(Clone)]
pub struct Proof {
    pub c: Vec<Scalar>,
    pub z: Vec<Scalar>,
}
pub fn prefix(token: &Token, ct: &[u8], m: usize) -> Transcript {
    let mut h = Transcript::new(hash::H3_HOLDER, m + 2, Frame::Canonical);
    h.field(&token.encode());
    h.field(ct);
    h
}
pub fn generate(
    token: &Token,
    x: &Scalar,
    tau: usize,
    epoch: &Epoch,
    ct: &[u8],
    rng: &mut Random,
) -> Proof {
    generate_prepared(
        token,
        x,
        tau,
        epoch,
        prefix(token, ct, epoch.slots.len()),
        rng,
    )
}
pub fn generate_prepared(
    token: &Token,
    x: &Scalar,
    tau: usize,
    epoch: &Epoch,
    mut transcript: Transcript,
    rng: &mut Random,
) -> Proof {
    let m = epoch.slots.len();
    let mut c = vec![Scalar::zero(); m];
    let mut z = c.clone();
    let mut sum = Scalar::zero();
    let mut points = vec![G1::identity(); m];
    for j in 0..m {
        if j != tau - 1 {
            c[j] = rng.scalar();
            z[j] = rng.scalar();
            sum = sum.add(&c[j]);
            points[j] = token.zeta.mul(&z[j]).sub(&epoch.slots[j].mul(&c[j]))
        }
    }
    let r = rng.scalar();
    points[tau - 1] = token.zeta.mul(&r);
    for p in points {
        transcript.field(&p.encode())
    }
    c[tau - 1] = Scalar::from_digest(&transcript.finish()).sub(&sum);
    z[tau - 1] = r.add(&c[tau - 1].mul(x));
    Proof { c, z }
}
pub fn verify(token: &Token, proof: &Proof, epoch: &Epoch, ct: &[u8]) -> bool {
    verify_prepared(token, proof, epoch, prefix(token, ct, epoch.slots.len()))
}
pub fn verify_prepared(
    token: &Token,
    proof: &Proof,
    epoch: &Epoch,
    mut transcript: Transcript,
) -> bool {
    if proof.c.len() != epoch.slots.len()
        || proof.z.len() != proof.c.len()
        || token.zeta.is_identity()
    {
        return false;
    }
    let mut sum = Scalar::zero();
    for ((c, z), psi) in proof.c.iter().zip(&proof.z).zip(&epoch.slots) {
        sum = sum.add(c);
        transcript.field(&token.zeta.mul(z).sub(&psi.mul(c)).encode())
    }
    sum == Scalar::from_digest(&transcript.finish())
}
impl Proof {
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![(self.c.len() as u32).to_be_bytes().to_vec()];
        for (c, z) in self.c.iter().zip(&self.z) {
            fields.push(c.encode());
            fields.push(z.encode())
        }
        encoding::encode(
            "AWARE-HolderBinding-Proof-v1",
            &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
    }
    pub fn decode(b: &[u8], m: usize) -> Result<Self, &'static str> {
        let f = encoding::decode("AWARE-HolderBinding-Proof-v1", b, 1 + 2 * m)?;
        if f[0] != (m as u32).to_be_bytes() {
            return Err("OR branch count");
        };
        Ok(Self {
            c: (0..m)
                .map(|j| Scalar::decode(f[1 + 2 * j]))
                .collect::<Result<_, _>>()?,
            z: (0..m)
                .map(|j| Scalar::decode(f[2 + 2 * j]))
                .collect::<Result<_, _>>()?,
        })
    }
}
