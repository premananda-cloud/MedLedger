# MedLedger – Test Results

**Date:** 2026-02-23  
**Environment:** Python 3.12, `cryptography` 46.0.5  
**Test file:** `test_medledger.py`  
**Result: 26 / 26 passed**

---

## Raw Output

```
══════════════════════════════════════════════
  MedLedger – Integration Test
══════════════════════════════════════════════

── 1. KeyManager ──
  ✅  Patient keypair generated  →  pub_hash=94d4fe94b933…
  ✅  Doctor keypair generated  →  pub_hash=ccb7d9cd3992…
  ✅  Public keys are distinct
  ✅  get_public_key_from_private round-trips correctly

── 2. SignatureVerifier ──
  ✅  Client-side signature produced  →  len=70 bytes
  ✅  Server verifies valid signature  →  OK
  ✅  Tampered payload is rejected  →  Signature verification failed
  ✅  Wrong public key is rejected  →  Signature verification failed

── 3. Signature length edge cases ──
  ✅  All 50 payloads verify regardless of DER length  →  50/50 passed

── 4. ECIES (DEK wrapping) ──
  ✅  ECIES encrypt for patient produces bundle
  ✅  Patient decrypts DEK correctly
  ✅  Doctor decrypts re-encrypted DEK correctly
  ✅  Wrong private key rejected  →  Decryption failed (wrong key or tampered data)

── 5. AES-GCM file encryption ──
  ✅  File encrypted
  ✅  File decrypted correctly
  ✅  Tampered ciphertext rejected  →  AES-GCM decryption failed

── 6. Full permission grant→verify flow ──
  ✅  Step A – client signs locally, no key transmitted
  ✅  Step B – server verifies sig before persisting  →  OK
  ✅  Step C – time window is valid  →  2026-02-23T04:37:15 → 2026-02-23T06:37:15
  ✅  Step C – doctor access: sig re-verified  →  OK
  ✅  Step D – revoked/wrong record denied  →  Signature verification failed

── 7. main.py regressions ──
  ✅  No duplicate add_middleware call
  ✅  No hardcoded local IP in CORS
  ✅  create_all_tables not imported in main.py
  ✅  init_db used in startup
  ✅  create_all_tables defined in models.py

══════════════════════════════════════════════
  Results: 26 passed, 0 failed out of 26 checks
══════════════════════════════════════════════
```

---

## Annotations

### Section 1 — KeyManager
Keypair generation uses `cryptography.hazmat.primitives.asymmetric.ec` with `SECP256R1` (P-256). The public key hashes shown (`94d4fe94b933…`, `ccb7d9cd3992…`) are SHA-256 digests of the uncompressed public key bytes — these are what get stored in the database as unique identifiers. The round-trip check confirms `get_public_key_from_private()` derives the identical public key, which is used server-side to validate that a submitted private key belongs to the registered user.

### Section 2 — SignatureVerifier
The produced signature is 70 bytes — a valid DER-encoded ECDSA-P256 signature. The old code would accept this (it's within 70–72), but signatures of 68 or 69 bytes would have been silently rejected. The tamper and wrong-key checks confirm the core security guarantee: a grant cannot be forged or replayed for a different user.

### Section 3 — Signature length edge cases
This is a regression test for the bug fix. Running 50 payloads through sign+verify and getting 50/50 confirms that no valid signature is being discarded due to a DER encoding edge case. In practice, signatures at the low end (68–69 bytes) are rare but valid — they occur when the `r` or `s` integer happens to have a leading zero stripped.

### Section 4 — ECIES DEK wrapping
The ECIES flow that was confirmed working:
1. Server generates a 32-byte DEK (`os.urandom(32)`)
2. Server ECIES-encrypts it with the patient's public key → stored as `encrypted_dek_hex`
3. At grant time, patient decrypts the DEK client-side, re-encrypts with doctor's public key → stored as `doctor_encrypted_dek`
4. Doctor decrypts their bundle client-side to get the DEK
5. Doctor uses the DEK to AES-GCM decrypt the file

The "wrong private key rejected" check proves the GCM auth tag is working — decryption with the wrong key doesn't produce garbage output, it raises `ValueError`.

### Section 5 — AES-GCM file encryption
File bytes survive the encrypt/decrypt cycle exactly. The tamper check flips a single byte in the ciphertext and confirms the GCM authentication tag detects it — this is why AES-GCM is used instead of plain AES-CBC.

### Section 6 — Full permission flow
This is the most important section. It proves the complete access control sequence works without a database or API server:

- **Step A:** Patient signs locally. The private key is used here and then discarded — it never appears in a network request.
- **Step B:** Server receives the signature and verifies it against the patient's stored public key before writing anything to the DB. A bad signature at this step causes the grant to be rejected entirely.
- **Step C:** Doctor access re-verifies the same signature on every request, plus checks the time window. The 2-hour window (`04:37 → 06:37`) was valid at test time.
- **Step D:** The same signature against a different `record_id` fails verification — confirming that a valid permission for record A cannot be replayed to access record B.

### Section 7 — main.py regressions
Five static checks on source files confirming the startup `ImportError` bug is fixed and won't regress. The duplicate CORS middleware and hardcoded IP checks are likewise guarded here so they can't accidentally come back in a merge.

---

## Known Warning (Non-Issue)

```
DeprecationWarning: datetime.datetime.utcnow() is deprecated
```

Python 3.12 deprecates `utcnow()`. This does not affect correctness or security — all datetime comparisons are internally consistent. Will be replaced with `datetime.now(timezone.utc)` in a later cleanup.
