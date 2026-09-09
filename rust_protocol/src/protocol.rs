//! Protocol 3: immutable accepted records and atomic first-valid serial spending.
use crate::{
    algebra::*,
    encoding::{self, Frame},
    hash,
    holder::{self, Proof},
    tgs::{self, Ciphertext, PublicKey},
    tnibs::{self, Epoch, Finalized, SignerPublic, Token},
};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
#[derive(Clone)]
pub struct Submission {
    pub token: Token,
    pub ciphertext: Ciphertext,
    pub proof: Proof,
    pub frame: Frame,
}
pub struct AcceptedRecord {
    sid: [u8; 32],
    submission: Arc<Submission>,
}
impl AcceptedRecord {
    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }
    pub fn submission(&self) -> &Submission {
        &self.submission
    }
}
#[derive(Default)]
struct State {
    spent: BTreeSet<Vec<u8>>,
    records: Vec<Arc<AcceptedRecord>>,
}
#[derive(Default)]
pub struct Ledger {
    state: Mutex<State>,
}
pub fn generate(
    pk: &PublicKey,
    message: &[u8],
    token: &Finalized,
    x: &Scalar,
    epoch: &Epoch,
    rng: &mut Random,
) -> Submission {
    let ciphertext = tgs::encrypt(pk, message, &token.token.encode(), rng);
    let proof = holder::generate(
        &token.token,
        x,
        token.slot,
        epoch,
        &ciphertext.encode(),
        rng,
    );
    Submission {
        token: token.token.clone(),
        ciphertext,
        proof,
        frame: Frame::Canonical,
    }
}
impl Submission {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.write_to(&mut out).unwrap();
        out
    }
    pub fn write_to(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        out.write_all(&encoding::header("AWARE-SUBMISSION-v1", 3, self.frame))?;
        let token = self.token.encode();
        encoding::field_header(out, self.frame, token.len())?;
        out.write_all(&token)?;
        encoding::field_header(out, self.frame, self.ciphertext.encoded_len(self.frame))?;
        self.ciphertext.write_to(out, self.frame)?;
        let proof = self.proof.encode();
        encoding::field_header(out, self.frame, proof.len())?;
        out.write_all(&proof)
    }
    pub fn sid(&self) -> [u8; 32] {
        let mut h = encoding::Transcript::new(hash::H4_RECORD, 3, Frame::Long);
        h.field(&self.token.encode());
        h.field_with(self.ciphertext.encoded_len(self.frame), |w| {
            self.ciphertext.write_to(w, self.frame)
        })
        .unwrap();
        h.field(&self.proof.encode());
        h.finish()
    }
    pub fn holder_prefix(&self, m: usize) -> encoding::Transcript {
        holder_prefix(&self.token, &self.ciphertext, self.frame, m)
    }
    pub fn encoded_len(&self) -> usize {
        encoding::encoded_len(
            "AWARE-SUBMISSION-v1",
            &[
                self.token.encode().len(),
                self.ciphertext.encoded_len(self.frame),
                self.proof.encode().len(),
            ],
            self.frame,
        )
    }
    pub fn decode(b: &[u8], m: usize) -> Result<Self, &'static str> {
        let frame = if b.starts_with(b"AWCL") {
            Frame::Long
        } else {
            Frame::Canonical
        };
        let f = encoding::decode_frame("AWARE-SUBMISSION-v1", b, 3, frame)?;
        Ok(Self {
            token: Token::decode(f[0])?,
            ciphertext: Ciphertext::decode_frame(f[1], frame)?,
            proof: Proof::decode(f[2], m)?,
            frame,
        })
    }
}
impl Ledger {
    pub fn accept(
        &self,
        signer: &SignerPublic,
        epoch: &Epoch,
        submission: Submission,
    ) -> Result<Arc<AcceptedRecord>, &'static str> {
        if !tnibs::verify(signer, &submission.token, epoch) {
            return Err("token authentication");
        }
        let token_bytes = submission.token.encode();

        if !tgs::verify(&submission.ciphertext, &token_bytes) {
            return Err("ciphertext verification");
        }
        if !holder::verify_prepared(
            &submission.token,
            &submission.proof,
            epoch,
            submission.holder_prefix(epoch.slots.len()),
        ) {
            return Err("holder binding");
        }
        self.record_verified(submission)
    }
    #[cfg(feature = "benchmarks")]
    pub fn accept_without_holder(
        &self,
        signer: &SignerPublic,
        epoch: &Epoch,
        submission: Submission,
    ) -> Result<Arc<AcceptedRecord>, &'static str> {
        if !tnibs::verify(signer, &submission.token, epoch)
            || !tgs::verify(&submission.ciphertext, &submission.token.encode())
        {
            return Err("baseline verification");
        }
        self.record_verified(submission)
    }
    fn record_verified(&self, submission: Submission) -> Result<Arc<AcceptedRecord>, &'static str> {
        let rho = submission.token.rho.encode();
        let sid = submission.sid();
        let mut state = self.state.lock().unwrap();
        if state.spent.contains(&rho) {
            return Err("spent serial");
        }
        let record = Arc::new(AcceptedRecord {
            sid,
            submission: Arc::new(submission),
        });
        state.spent.insert(rho);
        state.records.push(record.clone());
        Ok(record)
    }
    pub fn contains(&self, record: &AcceptedRecord) -> bool {
        self.state
            .lock()
            .unwrap()
            .records
            .iter()
            .any(|r| std::ptr::eq(r.as_ref(), record))
    }
    pub fn len(&self) -> usize {
        self.state.lock().unwrap().records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn records(&self) -> Vec<Arc<AcceptedRecord>> {
        self.state.lock().unwrap().records.clone()
    }
}

pub fn holder_prefix(
    token: &Token,
    ct: &Ciphertext,
    frame: Frame,
    m: usize,
) -> encoding::Transcript {
    let mut h = encoding::Transcript::new(hash::H3_HOLDER, m + 2, frame);
    h.field(&token.encode());
    h.field_with(ct.encoded_len(frame), |w| ct.write_to(w, frame))
        .unwrap();
    h
}
pub fn generate_stream(
    pk: &PublicKey,
    input: &mut impl std::io::Read,
    len: usize,
    token: &Finalized,
    x: &Scalar,
    epoch: &Epoch,
    rng: &mut Random,
) -> std::io::Result<Submission> {
    let ciphertext = tgs::encrypt_stream(pk, input, len, &token.token.encode(), rng)?;
    let frame = Frame::Long;
    let proof = holder::generate_prepared(
        &token.token,
        x,
        token.slot,
        epoch,
        holder_prefix(&token.token, &ciphertext, frame, epoch.slots.len()),
        rng,
    );
    Ok(Submission {
        token: token.token.clone(),
        ciphertext,
        proof,
        frame,
    })
}
