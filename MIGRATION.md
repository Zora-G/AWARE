# AWARE BN462 migration contract

Ground truth: `paper/AWARE-TDSC-Accountable.pdf`, Protocols 1–4 and Figures 3–4 / Tables II–IV; retained executable reference: sibling `aware_java/src/current` and `aware_java/src/thresholdDecryption`.

MIRACL source: https://github.com/miracl/core, commit `a6df6733c1ad1ad0918306abd0c3983b4cd4a58c`, generated with the official Rust `config64.py` BN462 selection (36). The vendored source includes the upstream Apache-2.0 license. Cargo.lock records the Rust dependencies; AES-GCM uses vendored OpenSSL and the existing SHA-256 transcripts use `sha2` 0.10.9 with its ARM hardware backend enabled on aarch64 and default backend selection on x86_64.

## Approved instantiation decisions

- MIRACL Core BN462 replaces JPBC Type F. Scalars have 58-byte canonical big-endian encodings. Compressed G1/G2 points occupy 59/117 bytes; GT occupies 696 bytes. The all-zero source-group encoding denotes the identity; protocol verification enforces the required nonidentity conditions. Decoding checks subgroup membership and canonical round trips.
- Source-group multiplication in the paper is source-group addition in the Rust API. Each independent pairing equation uses its own multi-pairing product and final exponentiation. Equations retain separate acceptance conditions.
- H1 nonce, H1 epoch-position, H2 epoch-tag, H3 holder, H3 opening, and H4 record retain Java's existing domain strings. Their semantic names follow the paper. As explicitly approved by the user, TGS H1 ciphertext and H5 key derivation gain explicit, separate canonical domains. These two transcripts therefore differ from the Java concatenation transcripts.
- H3 opening retains the Java transcript `(index, sid, complete ct, Tok, R, C, U, V)`. The full ciphertext/token binding supplements the public statement used by the verification equations.
- Nonces are sampled from nonzero BN462 scalars, following Protocol 2. The Java convenience issuer samples 16-byte nonces. Tests provide explicit nonce bytes when comparing issuance behavior.
- H1/H2 use MIRACL's native map-to-group operation on the protocol's existing SHA-256 digest, including cofactor clearing. H3 interprets that digest as a nonnegative integer in the BN462 scalar field. Hash-to-group output bytes differ across curves. SHA-256 and AES-256-GCM are the existing protocol primitives; AES-GCM retains 16-byte IVs and 16-byte tags.
- AWCE uses 32-bit framing. AWCL uses 64-bit framing. The record identifier uses AWCL for both paths, matching Java. Large-payload ciphertexts and proof transcripts use AWCL; token, holder proof, and contribution encodings remain AWCE.
- DDKG sums n independent degree-(t-1) polynomials and publishes paired verification shares, matching Java's honest-setup simulation. The library models the cryptographic setup computation, with authenticated/private dealer channels supplied by the environment as in the original artifact.
- The bulletin board atomically appends the first valid record for a serial. Accepted record construction is private. Opening contexts require membership in that ledger and the recomputed record identifier.
- Authenticated contribution attribution is a separate input from the serialized claimed index. Opening processes the first same-record entry for each attributed member, checks proofs and recovered shares, and returns blame even when the threshold fails.

## Cross-check scope

The source migration was checked against the retained Java implementation in the
larger AWARE working tree. This minimal Rust artifact keeps the standalone Rust
correctness suite: canonical framing, TNIBS verification and rejection cases,
holder proof binding, threshold recovery, replay handling, accountable opening,
and streaming payload authentication.

## Experimental contract

Defaults: m=15, (n,t)=(5,3), payload 1 MiB. Core measurements use 10 untimed warmups and 30 measured trials. Fig. 3(b) uses 30 independent process rounds per point; each round uses 10 warmups / 30 trials through 20 MiB, 2 warmups / 5 trials from 50 MiB through 1 GiB, and 0 warmups / 1 trial at 5 GiB. Table IV uses 30 / 10 at 10 KiB, 1 MiB and 100 MiB, and 1 / 0 at 1 GiB and 5 GiB.

Fig. 3(a): m in [1,5,10,15,20,30]. Fig. 3(b): [10 KiB,100 KiB,512 KiB,1 MiB,20 MiB,50 MiB,100 MiB,150 MiB,500 MiB,1 GiB,5 GiB]. Fig. 3(c): n in [6,9,12,15], t in [2,4,6,8,10], retaining t <= n.

Fig. 4(a): users [10,100,500,1000,5000,10000], workers [1,4,8,16], 10 measured epochs through 1000 users and 3 thereafter. Ten warmup epochs use min(users,10) users, exactly as `Revision2SystemBench`. Fig. 4(b): concurrency [1,2,4,8,16,32,64,128,256], 40 server workers, one 20-second warmup followed by five 60-second measured runs. Replay: concurrency [2,4,8,16,32,64], 10 warmup trials and 100 measured trials.

CompleteOpen times parallel generation of t contributions followed by RepCom. Opening preprocessing stays outside timed boundaries; CtVrfy remains inside each RepDec and RepCom. Timed operations perform full protocol computations and serialization, with network/storage excluded. Large payloads remain complete AES-GCM messages and complete proof transcripts.

BB provisioning creates 65,536 complete valid submissions before timing. Each submission has a fresh recipient, the Java fixture's indexed epoch, a cycling slot, and its indexed payload prefix. Every measured request consumes a distinct valid token in that phase's fresh ledger. This expands Java's 2,048-entry fixture capacity to cover BN462 throughput while retaining the same workers, concurrency, warmup, duration, and acceptance semantics. The CSV records accepted and rejected counts and actual phase duration. Replay candidates share one finalized token under the Java replay epoch and carry distinct indexed payload prefixes.

Table IV reuses the paper's unchanged official GlobaLeaks 5.0.99 measurements from `clean_xeon_final_20260904`, as requested by the user. Those runs used the same Gold 6133 host, CPUs 0–39, five recipients, and the same payload/trial schedules and stage boundaries. `scripts/reuse_comparison.py` checks the original raw means and retains the original measurement timestamps; the BN462 AWARE columns come from fresh full runs.

## Fig. 3(b) implementation audit (September 8, 2026)

The M2 build enables the existing sha2 0.10.9 ARM backend. The digest primitive,
domains, transcript bytes, and group mappings remain the same. The complete
correctness suite, including the retained Java oracle, passes with this backend.

All Fig. 3(b) sizes use the streaming interface, matching Java revision 3.
Thirty independent process rounds retain each point's original per-round trial
and warm-up schedule. The plot uses payload divided by the mean of every
measured latency. Table II uses the 1 MiB streaming latency and independently
measured canonical communication size, as in the Java revision-3 table script.
