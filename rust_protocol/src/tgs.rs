//! Boneh–Shoup TGS, preserving the Java DDKG polynomial sum and AES-256-GCM.
use crate::payload::{self, Payload};
use crate::{algebra::*, encoding::encode, hash};
#[derive(Clone)]
pub struct PublicShare {
    pub theta: G1,
    pub theta_hat: G2,
}
#[derive(Clone)]
pub struct SecretShare {
    pub index: usize,
    pub alpha: Scalar,
}
#[derive(Clone)]
pub struct PublicKey {
    pub theta: G1,
    pub shares: Vec<PublicShare>,
    pub threshold: usize,
}
#[derive(Clone)]
pub struct Ciphertext {
    pub v: G1,
    pub v_hat: G2,
    pub encrypted: Payload,
    pub bar_w: G1,
}
#[derive(Clone)]
pub struct Share {
    pub index: usize,
    pub w: G1,
}
pub fn keygen(n: usize, t: usize, rng: &mut Random) -> (PublicKey, Vec<SecretShare>) {
    assert!(2 <= t && t <= n, "2 <= threshold <= committee size");
    let polynomials: Vec<Vec<Scalar>> = (0..n)
        .map(|_| (0..t).map(|_| rng.scalar()).collect())
        .collect();
    keygen_from_polynomials(&polynomials)
}
pub fn keygen_from_polynomials(polys: &[Vec<Scalar>]) -> (PublicKey, Vec<SecretShare>) {
    let n = polys.len();
    let t = polys[0].len();
    let theta = polys.iter().fold(G1::identity(), |acc, p| {
        acc.add(&G1::generator().mul(&p[0]))
    });
    let secrets: Vec<_> = (1..=n)
        .map(|i| {
            let x = Scalar::from_u64(i as u64);
            let alpha = polys.iter().fold(Scalar::zero(), |a, p| {
                a.add(&p.iter().rev().fold(Scalar::zero(), |v, c| v.mul(&x).add(c)))
            });
            SecretShare { index: i, alpha }
        })
        .collect();
    let shares = secrets
        .iter()
        .map(|s| {
            let theta = G1::generator().mul(&s.alpha);
            let theta_hat = G2::generator().mul(&s.alpha);
            assert_eq!(
                pairing_product(&[
                    (&theta, &G2::generator()),
                    (&G1::generator().neg(), &theta_hat),
                ]),
                GT::identity()
            );
            PublicShare { theta, theta_hat }
        })
        .collect();
    (
        PublicKey {
            theta,
            shares,
            threshold: t,
        },
        secrets,
    )
}
pub fn encrypt(pk: &PublicKey, message: &[u8], ad: &[u8], rng: &mut Random) -> Ciphertext {
    encrypt_with_randomness(pk, message, ad, rng.nonzero(), rng.bytes())
}
pub fn encrypt_with_randomness(
    pk: &PublicKey,
    message: &[u8],
    ad: &[u8],
    beta: Scalar,
    iv: [u8; 16],
) -> Ciphertext {
    let v = G1::generator().mul(&beta);
    let v_hat = G2::generator().mul(&beta);
    let w = pk.theta.mul(&beta);
    let encrypted =
        payload::encrypt(&hash::key(&v, &w), &iv, &mut &message[..], message.len()).unwrap();
    let bar_w = hash::ciphertext(&v, ad).mul(&beta);
    Ciphertext {
        v,
        v_hat,
        encrypted,
        bar_w,
    }
}
pub fn encrypt_symmetric(key: &[u8; 32], message: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    payload::encrypt(key, iv, &mut &message[..], message.len())
        .unwrap()
        .to_vec()
}
pub fn decrypt_symmetric(key: &[u8; 32], encrypted: &Payload) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(encrypted.len() - 32);
    payload::decrypt(key, encrypted, &mut out).map_err(|_| "AES-GCM authentication")?;
    Ok(out)
}
pub fn verify(ct: &Ciphertext, ad: &[u8]) -> bool {
    verify_prepared(ct, &hash::ciphertext(&ct.v, ad))
}
pub fn verify_prepared(ct: &Ciphertext, u: &G1) -> bool {
    if ct.v.is_identity()
        || ct.v_hat.is_identity()
        || ct.bar_w.is_identity()
        || ct.encrypted.len() < 32
    {
        return false;
    }
    let g = G1::generator();
    let h = G2::generator();
    pairing_product(&[(&ct.v, &h), (&g.neg(), &ct.v_hat)]) == GT::identity()
        && pairing_product(&[(&ct.bar_w, &h), (&u.neg(), &ct.v_hat)]) == GT::identity()
}
pub fn share_dec(secret: &SecretShare, ct: &Ciphertext, ad: &[u8]) -> Result<Share, &'static str> {
    if !verify(ct, ad) {
        return Err("ciphertext verification");
    };
    Ok(Share {
        index: secret.index,
        w: ct.v.mul(&secret.alpha),
    })
}
pub fn share_verify(pk: &PublicKey, ct: &Ciphertext, share: &Share) -> bool {
    pk.shares.get(share.index.wrapping_sub(1)).is_some_and(|p| {
        pairing_product(&[(&share.w, &G2::generator()), (&ct.v.neg(), &p.theta_hat)])
            == GT::identity()
    })
}
pub fn lagrange(indices: &[usize]) -> Vec<Scalar> {
    indices
        .iter()
        .map(|&j| {
            indices
                .iter()
                .filter(|&&i| i != j)
                .fold(Scalar::one(), |a, &l| {
                    a.mul(&Scalar::from_u64(l as u64)).mul(
                        &Scalar::from_u64(l as u64)
                            .sub(&Scalar::from_u64(j as u64))
                            .inverse(),
                    )
                })
        })
        .collect()
}
pub fn reconstruct(shares: &[Share]) -> G1 {
    let indices: Vec<_> = shares.iter().map(|s| s.index).collect();
    shares
        .iter()
        .zip(lagrange(&indices))
        .fold(G1::identity(), |a, (s, c)| a.add(&s.w.mul(&c)))
}
pub fn combine(
    pk: &PublicKey,
    ct: &Ciphertext,
    ad: &[u8],
    shares: &[Share],
) -> Result<Vec<u8>, &'static str> {
    if !verify(ct, ad) {
        return Err("ciphertext verification");
    }
    let mut seen = std::collections::BTreeSet::new();
    let valid: Vec<_> = shares
        .iter()
        .filter(|s| seen.insert(s.index) && share_verify(pk, ct, s))
        .cloned()
        .collect();
    if valid.len() < pk.threshold {
        return Err("threshold");
    }
    decrypt_symmetric(
        &hash::key(&ct.v, &reconstruct(&valid[..pk.threshold])),
        &ct.encrypted,
    )
}
impl Ciphertext {
    pub fn encode(&self) -> Vec<u8> {
        encode(
            "AWARE-CT-v1",
            &[
                &self.v.encode(),
                &self.v_hat.encode(),
                &self.encrypted.to_vec(),
                &self.bar_w.encode(),
            ],
        )
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        let frame = if b.starts_with(b"AWCL") {
            crate::encoding::Frame::Long
        } else {
            crate::encoding::Frame::Canonical
        };
        Self::decode_frame(b, frame)
    }
    pub(crate) fn decode_frame(
        b: &[u8],
        frame: crate::encoding::Frame,
    ) -> Result<Self, &'static str> {
        let f = crate::encoding::decode_frame("AWARE-CT-v1", b, 4, frame)?;
        Ok(Self {
            v: G1::decode(f[0])?,
            v_hat: G2::decode(f[1])?,
            encrypted: f[2].into(),
            bar_w: G1::decode(f[3])?,
        })
    }
}

impl Ciphertext {
    pub fn encoded_len(&self, frame: crate::encoding::Frame) -> usize {
        crate::encoding::encoded_len(
            "AWARE-CT-v1",
            &[G1_BYTES, G2_BYTES, self.encrypted.len(), G1_BYTES],
            frame,
        )
    }
    pub fn write_to(
        &self,
        w: &mut dyn std::io::Write,
        frame: crate::encoding::Frame,
    ) -> std::io::Result<()> {
        use crate::encoding::{field_header, header};
        w.write_all(&header("AWARE-CT-v1", 4, frame))?;
        for b in [self.v.encode(), self.v_hat.encode()] {
            field_header(w, frame, b.len())?;
            w.write_all(&b)?
        }
        field_header(w, frame, self.encrypted.len())?;
        self.encrypted.write_to(w)?;
        let b = self.bar_w.encode();
        field_header(w, frame, b.len())?;
        w.write_all(&b)
    }
}
pub fn encrypt_stream(
    pk: &PublicKey,
    input: &mut impl std::io::Read,
    len: usize,
    ad: &[u8],
    rng: &mut Random,
) -> std::io::Result<Ciphertext> {
    let beta = rng.nonzero();
    let v = G1::generator().mul(&beta);
    let v_hat = G2::generator().mul(&beta);
    let w = pk.theta.mul(&beta);
    let encrypted = payload::encrypt(&hash::key(&v, &w), &rng.bytes(), input, len)?;
    let bar_w = hash::ciphertext(&v, ad).mul(&beta);
    Ok(Ciphertext {
        v,
        v_hat,
        encrypted,
        bar_w,
    })
}
impl Share {
    pub fn encode(&self) -> Vec<u8> {
        let point = self.w.encode();
        let mut out = (self.index as u32).to_be_bytes().to_vec();
        out.extend((point.len() as u32).to_be_bytes());
        out.extend(point);
        out
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() != 8 + G1_BYTES {
            return Err("share length");
        };
        let index = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        let len = u32::from_be_bytes(b[4..8].try_into().unwrap()) as usize;
        if len != G1_BYTES {
            return Err("share point length");
        };
        Ok(Self {
            index,
            w: G1::decode(&b[8..])?,
        })
    }
}
