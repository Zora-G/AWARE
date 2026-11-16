use aware_bn462::{
    algebra::*,
    encoding::{self, Frame},
    holder,
    opening::{self, Attributed},
    protocol::{self, Ledger, Submission},
    tgs,
    tnibs::{self, Epoch},
};
fn rng() -> Random {
    Random::from_seed(b"AWARE BN462 correctness fixtures")
}
fn fixture(
    m: usize,
) -> (
    tnibs::SignerPublic,
    tnibs::Recipient,
    tnibs::Finalized,
    Epoch,
    tgs::PublicKey,
    Vec<tgs::SecretShare>,
    Submission,
) {
    let mut r = rng();
    let (sk, signer) = tnibs::signer(&mut r);
    let user = tnibs::register(&mut r);
    let epoch = Epoch::new("epoch-2026", m);
    let pre = tnibs::issue(
        &tnibs::prepare_issue(&sk, &user.public, &epoch),
        &epoch,
        m,
        &mut r,
    );
    let token = tnibs::obtain(&pre, &epoch, &user, &mut r).unwrap();
    let (pk, shares) = tgs::keygen(5, 3, &mut r);
    let sub = protocol::generate(
        &pk,
        b"accountable report\0\xff",
        &token,
        &user.x,
        &epoch,
        &mut r,
    );
    (signer, user, token, epoch, pk, shares, sub)
}
#[test]
fn bn462_group_equations_and_canonical_roundtrips() {
    assert_eq!(SCALAR_BYTES, 58);
    assert_eq!(G1_BYTES, 59);
    assert_eq!(G2_BYTES, 117);
    let a = Scalar::from_u64(37);
    let b = Scalar::from_u64(51);
    let g = G1::generator();
    let h = G2::generator();
    assert_eq!(pairing(&G1::identity(), &h), GT::identity());
    assert_eq!(pairing(&g, &G2::identity()), GT::identity());
    assert_eq!(a.mul(&a.inverse()), Scalar::one());
    assert_eq!(a.sub(&a), Scalar::zero());
    assert_eq!(Scalar::zero().neg(), Scalar::zero());
    assert_eq!(Scalar::zero().neg().encode(), vec![0; SCALAR_BYTES]);
    assert_eq!(Scalar::decode(&a.neg().encode()).unwrap(), a.neg());
    assert_eq!(
        pairing(&g.mul(&a), &h.mul(&b)),
        pairing(&g, &h).pow(&a.mul(&b))
    );
    assert_eq!(
        pairing_product(&[(&g.mul(&a), &h), (&g.neg(), &h.mul(&a))]),
        GT::identity()
    );
    for p in [g.clone(), g.mul(&a), G1::identity()] {
        assert_eq!(G1::decode(&p.encode()).unwrap(), p)
    }
    for p in [h.clone(), h.mul(&b), G2::identity()] {
        assert_eq!(G2::decode(&p.encode()).unwrap(), p)
    }
    for p in [GT::identity(), pairing(&G1::generator(), &G2::generator())] {
        assert_eq!(GT::decode(&p.encode()).unwrap(), p)
    }
    assert!(Scalar::decode(&[255; 58]).is_err());
    assert!(G1::decode(&[255; 59]).is_err());
    assert!(G2::decode(&[255; 117]).is_err());
}
#[test]
fn canonical_frames_and_types_are_unambiguous() {
    let b = encoding::encode("record", &[b"a", b"bc"]);
    assert_eq!(
        encoding::decode("record", &b, 2).unwrap(),
        vec![&b"a"[..], &b"bc"[..]]
    );
    assert_ne!(b, encoding::encode("record", &[b"ab", b"c"]));
    assert!(encoding::decode("other", &b, 2).is_err());
    let mut trailing = b.clone();
    trailing.push(0);
    assert!(encoding::decode("record", &trailing, 2).is_err());
    for n in 0..b.len() {
        assert!(encoding::decode("record", &b[..n], 2).is_err())
    }
    assert_ne!(
        b,
        encoding::encode_frame("record", &[b"a", b"bc"], Frame::Long)
    );
}
#[test]
fn tnibs_all_slots_wrong_recipient_epoch_and_signature() {
    let mut r = rng();
    let (sk, pk) = tnibs::signer(&mut r);
    let user = tnibs::register(&mut r);
    let other = tnibs::register(&mut r);
    let epoch = Epoch::new("epoch", 5);
    let ctx = tnibs::prepare_issue(&sk, &user.public, &epoch);
    for j in 1..=5 {
        let pre = tnibs::issue(&ctx, &epoch, j, &mut r);
        assert_eq!(
            tnibs::PreToken::decode(&pre.encode()).unwrap().encode(),
            pre.encode()
        );
        let token = tnibs::obtain(&pre, &epoch, &user, &mut r).unwrap();
        assert!(tnibs::verify(&pk, &token.token, &epoch));
        assert!(!tnibs::verify(
            &pk,
            &tnibs::obtain(&pre, &epoch, &other, &mut r).unwrap().token,
            &epoch
        ));
        assert_eq!(
            tnibs::Token::decode(&token.token.encode())
                .unwrap()
                .encode(),
            token.token.encode()
        );
        let rerandomized = tnibs::obtain(&pre, &epoch, &user, &mut r).unwrap();
        assert_eq!(rerandomized.token.rho, token.token.rho);
        assert_ne!(rerandomized.token.sig.z, token.token.sig.z);
        assert!(!tnibs::verify(
            &pk,
            &token.token,
            &Epoch::new("other epoch", 5)
        ));
        let mut bad = token.token.clone();
        bad.sig.z = bad.sig.z.add(&G1::generator());
        assert!(!tnibs::verify(&pk, &bad, &epoch));
        bad = token.token.clone();
        bad.sig.y = G1::identity();
        assert!(!tnibs::verify(&pk, &bad, &epoch));
    }
}
#[test]
fn tgs_recovers_every_threshold_subset_and_rejects_tampering() {
    let (_, _, _, _, pk, secrets, sub) = fixture(3);
    let ad = sub.token.encode();
    let ct = &sub.ciphertext;
    let shares: Vec<_> = secrets
        .iter()
        .map(|s| tgs::share_dec(s, ct, &ad).unwrap())
        .collect();
    for a in 0..3 {
        for b in a + 1..4 {
            for c in b + 1..5 {
                assert_eq!(
                    tgs::combine(
                        &pk,
                        ct,
                        &ad,
                        &[shares[c].clone(), shares[a].clone(), shares[b].clone()]
                    )
                    .unwrap(),
                    b"accountable report\0\xff"
                )
            }
        }
    }
    assert!(tgs::combine(&pk, ct, &ad, &shares[..2]).is_err());
    assert!(tgs::combine(&pk, ct, &ad, &vec![shares[0].clone(); 3]).is_err());
    let mut bad = ct.clone();
    bad.encrypted[16] ^= 1;
    assert!(tgs::combine(&pk, &bad, &ad, &shares).is_err());
    assert!(!tgs::verify(ct, b"other token"));
    bad = ct.clone();
    bad.v_hat = bad.v_hat.add(&G2::generator());
    assert!(!tgs::verify(&bad, &ad));
    let mut invalid = shares[0].clone();
    invalid.w = invalid.w.add(&G1::generator());
    assert!(!tgs::share_verify(&pk, ct, &invalid));
}
#[test]
fn holder_binds_witness_ciphertext_digest_and_branch_count() {
    let (_, user, token, epoch, _, _, sub) = fixture(5);
    assert!(holder::verify(
        &sub.token,
        &sub.proof,
        &epoch,
        &sub.ciphertext.header().encode()
    ));
    assert!(!holder::verify(
        &sub.token,
        &holder::generate(
            &sub.token,
            &user.x.add(&Scalar::one()),
            token.slot,
            &epoch,
            &sub.ciphertext.header().encode(),
            &mut rng()
        ),
        &epoch,
        &sub.ciphertext.header().encode()
    ));
    let mut bad = sub.ciphertext.clone();
    bad.encrypted[16] ^= 1;
    assert!(!holder::verify(
        &sub.token,
        &sub.proof,
        &epoch,
        &bad.header().encode()
    ));
    let mut proof = sub.proof.clone();
    proof.c[0] = proof.c[0].add(&Scalar::one());
    assert!(!holder::verify(
        &sub.token,
        &proof,
        &epoch,
        &sub.ciphertext.header().encode()
    ));
    assert!(holder::Proof::decode(&sub.proof.encode(), 4).is_err());
    assert_eq!(
        holder::Proof::decode(&sub.proof.encode(), 5)
            .unwrap()
            .encode(),
        sub.proof.encode()
    );
}
#[test]
fn first_valid_acceptance_is_atomic_and_invalid_submission_preserves_serial() {
    let (signer, _, _, epoch, _, _, sub) = fixture(1);
    let ledger = Ledger::default();
    let mut bad = sub.clone();
    bad.proof.z[0] = Scalar::zero();
    assert!(ledger.accept(&signer, &epoch, bad).is_err());
    assert!(ledger.is_empty());
    let decoded = Submission::decode(&sub.encode(), 1).unwrap();
    assert_eq!(decoded.encode(), sub.encode());
    let count = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| ledger.accept(&signer, &epoch, sub.clone()).is_ok()))
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(count, 1);
    assert_eq!(ledger.len(), 1);
}
#[test]
fn accountable_opening_attribution_blame_first_entry_and_record_binding() {
    let (signer, _, _, epoch, pk, secrets, sub) = fixture(3);
    let ledger = Ledger::default();
    let record = ledger.accept(&signer, &epoch, sub).unwrap();
    assert!(opening::prepare(&Ledger::default(), &record).is_err());
    let ctx = opening::prepare(&ledger, &record).unwrap();
    let (public, secret) = opening::keygen(&mut rng());
    let entries: Vec<_> = secrets
        .iter()
        .map(|s| Attributed {
            member: s.index,
            contribution: opening::contribute(&public, s, &ctx, &mut Random::new()).unwrap(),
        })
        .collect();
    for e in &entries {
        assert!(opening::verify(&public, &pk, &ctx, &e.contribution));
        assert_eq!(
            opening::Contribution::decode(&e.contribution.encode())
                .unwrap()
                .encode(),
            e.contribution.encode()
        )
    }
    let result = opening::combine(&public, &secret, &pk, &ctx, &entries[..3]);
    assert_eq!(result.plaintext.unwrap(), b"accountable report\0\xff");
    assert!(result.blame.is_empty());
    let mut corrupted = entries.clone();
    corrupted[0].contribution.proof.s = Scalar::zero();
    let result = opening::combine(&public, &secret, &pk, &ctx, &corrupted);
    assert!(result.plaintext.is_ok());
    assert_eq!(result.blame, vec![1]);
    let result = opening::combine(
        &public,
        &secret,
        &pk,
        &ctx,
        &[
            corrupted[0].clone(),
            entries[0].clone(),
            entries[1].clone(),
            entries[2].clone(),
        ],
    );
    assert_eq!(result.plaintext.unwrap(), b"accountable report\0\xff");
    assert_eq!(result.blame, vec![1]);
    assert_eq!(result.valid_members, vec![1, 2, 3]);
    let mut cross = entries.clone();
    cross[0].contribution.sid[0] ^= 1;
    let result = opening::combine(&public, &secret, &pk, &ctx, &cross);
    assert!(result.plaintext.is_ok());
    assert!(result.blame.is_empty());
    let mut misattributed = entries[0].clone();
    misattributed.member = 2;
    let result = opening::combine(&public, &secret, &pk, &ctx, &[misattributed]);
    assert_eq!(result.blame, vec![2]);
    assert!(result.plaintext.is_err());
    let result = opening::combine(
        &public,
        &secret,
        &pk,
        &ctx,
        &[entries[0].clone(), entries[0].clone(), entries[1].clone()],
    );
    assert!(result.plaintext.is_err());
}
#[test]
fn obtain_rejects_issuer_chosen_bases() {
    let mut r = rng();
    let (sk, _) = tnibs::signer(&mut r);
    let user = tnibs::register(&mut r);
    let epoch = Epoch::new("epoch", 3);
    let ctx = tnibs::prepare_issue(&sk, &user.public, &epoch);
    let pre = tnibs::issue(&ctx, &epoch, 2, &mut r);
    assert!(tnibs::obtain(&pre, &epoch, &user, &mut r).is_some());
    let mut tagged = pre.clone();
    tagged.h = user.public.mul(&r.nonzero());
    assert!(tnibs::obtain(&tagged, &epoch, &user, &mut r).is_none());
    let mut tagged = pre.clone();
    tagged.psi = user.public.mul(&r.nonzero());
    let token = tnibs::obtain(&tagged, &epoch, &user, &mut r).unwrap();
    assert_eq!(token.token.zeta, epoch.slots[1].mul(&user.x.inverse()));
    assert!(tnibs::obtain(&pre, &Epoch::new("other", 3), &user, &mut r).is_none());
}

#[test]
fn blake3_backend_matches_official_vector() {
    let mut h = blake3::Hasher::new();
    h.update(b"");
    assert_eq!(
        h.finalize().to_hex().as_str(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}
#[test]
fn member_opens_from_header_record_and_combiner_binds_payload() {
    let (signer, user, token, epoch, pk, secrets, sub) = fixture(3);
    let ledger = Ledger::default();
    let record = ledger.accept(&signer, &epoch, sub.clone()).unwrap();
    let header = sub.ciphertext.header();
    assert_eq!(*record.header(), header);
    assert_eq!(*record.sid(), sub.sid());
    assert_eq!(tgs::Header::decode(&header.encode()).unwrap(), header);
    let mut other = sub.ciphertext.clone();
    other.encrypted[20] ^= 1;
    assert_ne!(other.header().digest, header.digest);
    let view = ledger.header_record(record.sid()).unwrap();
    let bytes = view.encode();
    assert!(bytes.len() < 4096);
    let decoded = protocol::MemberView::decode(&bytes, 3).unwrap();
    assert_eq!(decoded.encode(), bytes);
    let (public, secret) = opening::keygen(&mut rng());
    let member_ctx = opening::prepare_member(&decoded).unwrap();
    let mut tampered = view.clone();
    tampered.header.digest[0] ^= 1;
    assert!(opening::prepare_member(&tampered).is_err());
    let entries: Vec<_> = secrets[..3]
        .iter()
        .map(|s| Attributed {
            member: s.index,
            contribution: opening::contribute(&public, s, &member_ctx, &mut Random::new()).unwrap(),
        })
        .collect();
    assert!(
        opening::combine(&public, &secret, &pk, &member_ctx, &entries)
            .plaintext
            .is_err()
    );
    let ctx = opening::prepare(&ledger, &record).unwrap();
    let result = opening::combine(&public, &secret, &pk, &ctx, &entries);
    assert_eq!(result.plaintext.unwrap(), b"accountable report\0\xff");
    assert!(result.blame.is_empty());
    let big = protocol::generate(
        &pk,
        &vec![7u8; 1 << 20],
        &token,
        &user.x,
        &epoch,
        &mut rng(),
    );
    let big_record = Ledger::default().accept(&signer, &epoch, big).unwrap();
    assert_eq!(big_record.member_view().encode().len(), bytes.len());
}

#[test]
fn fast_paths_equal_reference_computations() {
    let mut r = rng();
    for _ in 0..8 {
        let (a, b) = (r.nonzero(), r.nonzero());
        let p = G1::generator().mul(&r.nonzero());
        let q = G1::generator().mul(&r.nonzero());
        assert_eq!(p.mul2(&a, &q, &b), p.mul(&a).add(&q.mul(&b)));
        assert_eq!(p.mul2(&a, &q, &b.neg()), p.mul(&a).sub(&q.mul(&b)));
        let h = G2::generator();
        let y = G2::generator().mul(&r.nonzero());
        assert_eq!(pairing_product(&[(&p, &h)]), pairing(&p, &h));
        assert_eq!(
            pairing_product(&[(&p, &h), (&q, &y)]),
            pairing(&p, &h).mul(&pairing(&q, &y))
        );
        assert_eq!(pairing_product(&[(&p, &h), (&p.neg(), &h)]), GT::identity());
    }
}
#[test]
fn regression_vectors() {
    use aware_bn462::{hash, payload};
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    let c: payload::Payload = vec![0x41u8; 48].into();
    let dig = hash::payload_digest(&c);
    let (signer, _, _, epoch, _, secrets, sub) = fixture(3);
    let ledger = Ledger::default();
    let record = ledger.accept(&signer, &epoch, sub).unwrap();
    let ctd = record.header().encode();
    let view = ledger.header_record(record.sid()).unwrap();
    let ctx = opening::prepare_member(&view).unwrap();
    let (public, _) = opening::keygen(&mut rng());
    let contribution = opening::contribute(
        &public,
        &secrets[0],
        &ctx,
        &mut Random::from_seed(b"opening vector"),
    )
    .unwrap();
    let got = [
        hex(&dig),
        hex(&aware_bn462::encoding::digest(
            "ctd",
            &[&ctd],
            Frame::Canonical,
        )),
        hex(record.sid()),
        hex(&contribution.proof.c.encode()),
    ];
    assert_eq!(got, VECTORS.map(String::from));
}
const VECTORS: [&str; 4] = [
    "a317d5e2fbb6c6d26e190bdf8145c0a1e95c431cf12469eca11124aa1e1977f6",
    "37ef07da7c01ec3944f7c2cb42dbd67103609f3d30574b5cb64dacea33a1264a",
    "3f7ab595c49329aa511fb9828264969fbbf7f8c6581469b618f074080fc2580e",
    "00000000000000000000000000000000000000000000000000007196f637e35dc9d0e804c3d74e5b36ebbf7fd2ebf46518d6b242c99d9b8f8f6b",
];
