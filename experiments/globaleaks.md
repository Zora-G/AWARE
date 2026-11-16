# GlobaLeaks timings

`globaleaks.csv` holds wall-clock times for the GlobaLeaks 5.0.99 backend (commit 8e015fd) on the server host, with PyNaCl 1.5.0, cryptography 41.0.7 and Python 3.12.3. Files are stored on tmpfs and processed in 64 KiB chunks, with five recipients.

- `GLSubmitCrypto`: receipt hash, tip key pair, session-key protection, whistleblower self-wrap, empty answers encryption, file metadata encryption, five recipient wraps, and `delivery.write_encrypted_file`.
- `GLRecipientOpen`: opening by one recipient: tip-key unwrap, answers and file metadata decryption, and decryption of the file stream.
- Not timed: key and payload fixtures, file cleanup, the correctness check, the database, HTTP, Tor and persistent storage.

Each payload up to 100 MiB has 30 runs after 10 warm-ups. The 1 GiB and 5 GiB payloads have one run each.
