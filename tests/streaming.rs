use aware_bn462::{
    algebra::Random,
    encoding::Frame,
    opening::{self, Attributed},
    payload,
    protocol::{self, Ledger},
    tgs,
    tnibs::{self, Epoch},
};
#[test]
fn streaming_gcm_recovers_full_plaintext_and_authenticates_final_chunk() {
    use std::io::Read;
    let key = [7; 32];
    let iv = [3; 16];
    let message: Vec<_> = (0..payload::CHUNK_BYTES + 37)
        .map(|i| (i % 251) as u8)
        .collect();
    let encrypted = payload::encrypt(&key, &iv, &mut message.as_slice(), message.len()).unwrap();
    let mut reader = encrypted.reader();
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    let mut serialized = Vec::new();
    reader.read_to_end(&mut serialized).unwrap();
    assert_eq!(serialized, encrypted.to_vec());
    let mut out = Vec::new();
    assert_eq!(
        payload::decrypt(&key, &encrypted, &mut out).unwrap(),
        message.len()
    );
    assert_eq!(out, message);

    let mut bad = encrypted.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(payload::decrypt(&key, &bad, &mut std::io::sink()).is_err());
}
#[test]
fn long_frame_full_protocol_opens_and_binds_complete_payload() {
    let mut rng = Random::new();
    let (sk, pk) = tnibs::signer(&mut rng);
    let user = tnibs::register(&mut rng);
    let epoch = Epoch::new("stream", 3);
    let pre = tnibs::issue(
        &tnibs::prepare_issue(&sk, &user.public, &epoch),
        &epoch,
        2,
        &mut rng,
    );
    let token = tnibs::obtain(&pre, &user, &mut rng);
    let (keys, secrets) = tgs::keygen(5, 3, &mut rng);
    let len = payload::CHUNK_BYTES + 17;
    let report = protocol::generate_stream(
        &keys,
        &mut std::io::repeat(42),
        len,
        &token,
        &user.x,
        &epoch,
        &mut rng,
    )
    .unwrap();
    assert_eq!(report.frame, Frame::Long);
    assert_eq!(report.encode().len(), report.encoded_len());
    let decoded = protocol::Submission::decode(&report.encode(), 3).unwrap();
    assert_eq!(decoded.encode(), report.encode());
    let mixed_frame = aware_bn462::encoding::encode_frame(
        "AWARE-SUBMISSION-v1",
        &[
            &report.token.encode(),
            &report.ciphertext.encode(),
            &report.proof.encode(),
        ],
        Frame::Long,
    );
    assert!(protocol::Submission::decode(&mixed_frame, 3).is_err());
    let ledger = Ledger::default();
    let mut changed = report.clone();
    changed.ciphertext.encrypted[len - 3] ^= 1;
    assert!(ledger.accept(&pk, &epoch, changed).is_err());
    let rec = ledger.accept(&pk, &epoch, report).unwrap();
    let ctx = opening::prepare(&ledger, &rec, &keys).unwrap();
    let (public, secret) = opening::keygen(&mut rng);
    let entries: Vec<_> = secrets[..3]
        .iter()
        .map(|s| Attributed {
            member: s.index,
            contribution: opening::contribute(&public, s, &ctx, &mut rng).unwrap(),
        })
        .collect();
    let result = opening::combine(&public, &secret, &keys, &ctx, &entries);
    assert_eq!(result.plaintext.unwrap(), vec![42; len]);
}
