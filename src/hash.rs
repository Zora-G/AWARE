//! Protocols 1–4 random-oracle domains, with the approved explicit TGS labels.
use crate::{
    algebra::{G1, G2, Scalar},
    encoding::{Frame, digest},
};
pub const H1_NONCE: &str = "AWARE-H1-v1";
pub const H1_SLOT: &str = "AWARE-H3-v1";
pub const H1_CIPHERTEXT: &str = "AWARE-H1-CIPHERTEXT-v1";
pub const H2_TAG: &str = "AWARE-TAG-v1";
pub const H3_HOLDER: &str = "AWARE-H4-v1";
pub const H3_OPEN: &str = "AWARE-OPEN-FS-v1";
pub const H4_RECORD: &str = "AWARE-ACCEPTED-RECORD-SID-v1";
pub const H5_KDF: &str = "AWARE-H5-KDF-v1";
pub fn nonce(b: &[u8]) -> G1 {
    G1::map(&digest(H1_NONCE, &[b], Frame::Canonical))
}
pub fn slot(eta: &str, j: usize) -> G1 {
    G1::map(&digest(
        H1_SLOT,
        &[eta.as_bytes(), &(j as u32).to_be_bytes()],
        Frame::Canonical,
    ))
}
pub fn tag(eta: &str) -> G2 {
    G2::map(&digest(H2_TAG, &[eta.as_bytes()], Frame::Canonical))
}
pub fn ciphertext(v: &G1, ad: &[u8]) -> G1 {
    G1::map(&digest(H1_CIPHERTEXT, &[&v.encode(), ad], Frame::Canonical))
}
pub fn challenge(domain: &str, fields: &[&[u8]]) -> Scalar {
    Scalar::from_digest(&digest(domain, fields, Frame::Canonical))
}
pub fn key(v: &G1, w: &G1) -> [u8; 32] {
    digest(H5_KDF, &[&v.encode(), &w.encode()], Frame::Canonical)
}
