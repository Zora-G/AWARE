//! BN462 prime-order groups. Multiplicative paper notation is represented by
//! addition in the source groups and multiplication in the target group.
use mcore::bn462::{
    big::{BIG, MODBYTES},
    ecp::ECP,
    ecp2::ECP2,
    fp12::FP12,
    pair, rom,
};
use mcore::rand::RAND;
use std::fmt;
pub const SCALAR_BYTES: usize = MODBYTES;
pub const G1_BYTES: usize = MODBYTES + 1;
pub const G2_BYTES: usize = 2 * MODBYTES + 1;
pub const GT_BYTES: usize = 12 * MODBYTES;
fn order() -> BIG {
    BIG::new_ints(&rom::CURVE_ORDER)
}
#[derive(Clone, Copy)]
pub struct Scalar(pub(crate) BIG);
impl Scalar {
    pub fn zero() -> Self {
        Self(BIG::new())
    }
    pub fn one() -> Self {
        Self::from_u64(1)
    }
    pub fn from_u64(n: u64) -> Self {
        let mut b = [0; SCALAR_BYTES];
        b[SCALAR_BYTES - 8..].copy_from_slice(&n.to_be_bytes());
        Self(BIG::frombytes(&b))
    }
    pub fn from_digest(d: &[u8; 32]) -> Self {
        let mut b = [0; SCALAR_BYTES];
        b[SCALAR_BYTES - 32..].copy_from_slice(d);
        Self(BIG::frombytes(&b))
    }
    pub fn is_zero(&self) -> bool {
        self.0.iszilch()
    }
    pub fn add(&self, b: &Self) -> Self {
        Self(BIG::modadd(&self.0, &b.0, &order()))
    }
    pub fn neg(&self) -> Self {
        let modulus = order();
        let mut value = BIG::modneg(&self.0, &modulus);
        // MIRACL returns the modulus for -0; Scalar retains canonical residues.
        value.ctmod(&modulus, 0);
        Self(value)
    }
    pub fn sub(&self, b: &Self) -> Self {
        self.add(&b.neg())
    }
    pub fn mul(&self, b: &Self) -> Self {
        Self(BIG::modmul(&self.0, &b.0, &order()))
    }
    pub fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "inverse requires a nonzero scalar");
        let mut v = self.0;
        v.invmodp(&order());
        Self(v)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0; SCALAR_BYTES];
        self.0.tobytes(&mut b);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() != SCALAR_BYTES {
            return Err("scalar length");
        };
        let v = BIG::frombytes(b);
        if BIG::comp(&v, &order()) >= 0 {
            return Err("scalar range");
        };
        Ok(Self(v))
    }
}
impl PartialEq for Scalar {
    fn eq(&self, b: &Self) -> bool {
        BIG::comp(&self.0, &b.0) == 0
    }
}
impl Eq for Scalar {}
impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Scalar(..)")
    }
}
pub struct Random(RAND);
impl Random {
    pub fn new() -> Self {
        let mut seed = [0; 64];
        getrandom::getrandom(&mut seed).expect("OS randomness");
        Self::from_seed(&seed)
    }
    /// Explicit reproducible randomness for cross-check vectors only.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut r = RAND::new();
        r.seed(seed.len(), seed);
        Self(r)
    }
    pub fn scalar(&mut self) -> Scalar {
        Scalar(BIG::randomnum(&order(), &mut self.0))
    }
    pub fn nonzero(&mut self) -> Scalar {
        loop {
            let s = self.scalar();
            if !s.is_zero() {
                return s;
            }
        }
    }
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.0.getbyte())
    }
}
impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone)]
pub struct G1(pub(crate) ECP);
#[derive(Clone)]
pub struct G2(pub(crate) ECP2);
#[derive(Clone, Copy)]
pub struct GT(pub(crate) FP12);
macro_rules! source_group {
    ($ty:ident,$inner:ident,$len:ident,$mul:ident,$member:ident) => {
        impl $ty {
            pub fn generator() -> Self {
                Self($inner::generator())
            }
            pub fn identity() -> Self {
                Self($inner::new())
            }
            pub fn is_identity(&self) -> bool {
                self.0.is_infinity()
            }
            pub fn add(&self, b: &Self) -> Self {
                let mut p = self.0.clone();
                p.add(&b.0);
                Self(p)
            }
            pub fn neg(&self) -> Self {
                let mut p = self.0.clone();
                p.neg();
                Self(p)
            }
            pub fn sub(&self, b: &Self) -> Self {
                self.add(&b.neg())
            }
            pub fn mul(&self, s: &Scalar) -> Self {
                Self(pair::$mul(&self.0, &s.0))
            }
            pub fn encode(&self) -> Vec<u8> {
                if self.is_identity() {
                    return vec![0; $len];
                };
                let mut b = vec![0; $len];
                self.0.tobytes(&mut b, true);
                b
            }
            pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
                if b.len() != $len {
                    return Err("group length");
                };
                if b.iter().all(|&v| v == 0) {
                    return Ok(Self::identity());
                };
                let p = Self($inner::frombytes(b));
                if !pair::$member(&p.0) || p.encode() != b {
                    return Err("canonical subgroup point");
                };
                Ok(p)
            }
            pub(crate) fn map(d: &[u8; 32]) -> Self {
                Self($inner::mapit(d))
            }
        }
        impl PartialEq for $ty {
            fn eq(&self, b: &Self) -> bool {
                self.0.equals(&b.0)
            }
        }
        impl Eq for $ty {}
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(..)"))
            }
        }
    };
}
source_group!(G1, ECP, G1_BYTES, g1mul, g1member);
source_group!(G2, ECP2, G2_BYTES, g2mul, g2member);
impl GT {
    pub fn identity() -> Self {
        Self(FP12::new_int(1))
    }
    pub fn mul(&self, b: &Self) -> Self {
        let mut p = self.0;
        p.mul(&b.0);
        p.reduce();
        Self(p)
    }
    pub fn inverse(&self) -> Self {
        let mut p = self.0;
        p.inverse();
        Self(p)
    }
    pub fn pow(&self, s: &Scalar) -> Self {
        Self(pair::gtpow(&self.0, &s.0))
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut p = self.0;
        let mut b = vec![0; GT_BYTES];
        p.reduce();
        p.tobytes(&mut b);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() != GT_BYTES {
            return Err("GT length");
        };
        let p = Self(FP12::frombytes(b));
        if (p == Self::identity() || pair::gtmember(&p.0)) && p.encode() == b {
            Ok(p)
        } else {
            Err("canonical GT subgroup")
        }
    }
}
impl PartialEq for GT {
    fn eq(&self, b: &Self) -> bool {
        self.0.equals(&b.0)
    }
}
impl Eq for GT {}
impl fmt::Debug for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("GT(..)")
    }
}
pub fn pairing(a: &G1, b: &G2) -> GT {
    if a.is_identity() || b.is_identity() {
        GT::identity()
    } else {
        GT(pair::fexp(&pair::ate(&b.0, &a.0)))
    }
}
/// One Miller accumulation and final exponentiation per independent equation.
pub fn pairing_product(terms: &[(&G1, &G2)]) -> GT {
    let mut acc = pair::initmp();
    for (a, b) in terms {
        if !a.is_identity() && !b.is_identity() {
            pair::another(&mut acc, &b.0, &a.0)
        }
    }
    GT(pair::fexp(&pair::miller(&mut acc)))
}
