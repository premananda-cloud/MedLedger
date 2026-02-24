# MedLedger: The 5-Minute Master Summary

**For when you need to remember EVERYTHING fast**

---

## THE CORE PROBLEM

**58% of healthcare breaches are insider threats.**

Hospital admins have database access and can:
- Read encrypted medical records (traditional systems store plaintext)
- Delete audit logs (traditional systems allow deletion)
- Override access controls (traditional systems have admin override buttons)
- Disable 2FA, modify patient data, etc.

**Why it happens:** Trust-based security. "We trust admins not to abuse their access."

---

## THE MEDLEDGER SOLUTION

**Replace trust with math.**

When a patient registers:
1. **P-256 keypair generated on the patient's device**
2. **Private key never leaves the device**
3. **Public key registered with server**

When a doctor accesses a record:
1. **Server verifies patient's ECDSA signature**
2. **Signature proves patient authorized this specific doctor for this record**
3. **Even admin can't forge signature** (requires patient's private key)

**The core guarantee:** Admin + full database access ≠ readable medical records

---

## THE 6-STEP ENCRYPTION PIPELINE (Patient Upload)

```
File Upload
    ↓
1. SHA-256 hash the file → File fingerprint
2. ECDSA sign with patient's private key → Proof patient uploaded it
3. Generate random 32-byte DEK → Encryption key
4. AES-256-GCM encrypt file with DEK → Encrypted file + auth tag
5. ECIES wrap DEK with patient's public key → DEK encrypted for patient only
6. Server stores encrypted ciphertext (but NO unencrypted DEK)
```

**Result:** Server has gibberish. Patient's private key needed to decrypt.

---

## THE 4-STEP ACCESS VERIFICATION (Doctor View)

```
Doctor tries to access:
    ↓
1. Check: Does permission exist?
   ✗ NO → ACCESS DENIED
   ✓ YES → Continue
    ↓
2. Check: Is time window valid? (between time_start and time_end)
   ✗ EXPIRED → ACCESS DENIED
   ✓ VALID → Continue
    ↓
3. Verify: ECDSA signature matches? (using patient's public key)
   ✗ INVALID → ACCESS DENIED (admin tried to forge it?)
   ✓ VALID → Continue
    ↓
4. Check: Not revoked?
   ✗ REVOKED → ACCESS DENIED
   ✓ ACTIVE → Grant access
    ↓
Doctor receives encrypted DEK → doctor_private_key decrypts it
→ Doctor decrypts file → plaintext
```

---

## CRYPTOGRAPHY PRIMITIVES (THE "WHY")

| Primitive | What | Why We Use It |
|-----------|------|---------------|
| **P-256** | EC keypair standard | NIST-approved, TLS 1.3, 256-bit security, small keys |
| **ECDSA** | Sign/verify with keypair | Proves authorization; can't forge without private key |
| **SHA-256** | One-way hash | File fingerprint; proves file identity |
| **AES-256-GCM** | Encrypt + authenticate | Makes ciphertext unreadable; detects tampering |
| **ECIES** | Encrypt key for recipient | Only recipient's private key can decrypt; no pre-shared secret |
| **HKDF-SHA256** | Derive AES key | Standard KDF; domain-separation prevents key reuse |
| **Shamir 3-of-5** | Recover key from shares | Patient loses key? Any 3 of 5 trustees reconstruct it |

---

## KEY SECURITY PROPERTIES

### What Admin CANNOT Do (Even With Full DB Access)

1. **Read plaintext medical records**
   - Why: Ciphertext encrypted with AES-256-GCM; no DEK on server
   
2. **Grant themselves access to a record**
   - Why: Permissions require ECDSA signature; admin lacks patient's private key
   
3. **Modify a permission's time window and get away with it**
   - Why: Signature is on the original permission; modified time breaks signature
   
4. **Delete audit logs**
   - Why: Append-only table; no delete endpoint; hash-chained (deletion breaks chain)
   
5. **Create fake patient accounts and access their records**
   - Why: Each record requires valid patient signature; admin can't forge it

### What Patient STILL Controls

1. **Granting access** — Patient decides who sees what
2. **Revoking access** — Immediate (next access attempt fails)
3. **Time windows** — Decide how long doctor can access
4. **Key recovery** — 3 of 5 trustees can restore lost private key
5. **Audit visibility** — Who accessed my records and when

---

## THE DEMO APP (medledger_demo.py)

**What it proves:** Cryptography is real (not toy code)

### 5 Steps Shown:

1. **Register patient**
   - P-256 keypair generated locally
   - Private key stays on device
   
2. **Register doctor**
   - Another P-256 keypair
   - Both exist in same session

3. **Patient uploads & encrypts record**
   - 6-step animation shows:
     - SHA-256 hash
     - ECDSA signature
     - DEK generation
     - AES-256-GCM encryption
     - ECIES wrapping
     - Server storage (encrypted)

4. **Patient grants doctor access**
   - 5-step animation shows:
     - DEK decryption (ECIES)
     - DEK re-encryption for doctor
     - Permission creation
     - ECDSA signature
     - Server storage (permission + signature)

5. **Doctor views record**
   - Server verifies: permission exists, time valid, signature valid, not revoked
   - Doctor decrypts DEK with doctor's private key
   - Doctor decrypts file with DEK
   - Plaintext appears in viewer
   - File integrity verified

---

## COMMON QUESTIONS & SNAPPY ANSWERS

| Q | A |
|---|---|
| **Why not just use AES?** | AES requires pre-shared key. ECIES lets doctor and patient encrypt for each other without sharing a secret first. |
| **Why P-256 instead of RSA?** | Same security (256 bits) but faster, smaller keys. Used in TLS 1.3. |
| **Can admin fake a permission?** | No. Permission must be ECDSA-signed by patient. Admin lacks private key, so signature fails mathematically. |
| **What if patient loses key?** | Shamir 3-of-5: split among 5 trustees; any 3 reconstruct it. |
| **What if doctor's account is hacked?** | Hacker still needs valid patient signature to access records. Credentials alone grant nothing. |
| **Can law enforcement force access?** | Hospital can give encrypted ciphertext but can't decrypt without patient's private key (not on server). Patient has ultimate authority. |
| **Why ECIES instead of just encrypting DEK with AES?** | Need to encrypt DEK for someone (doctor) without sharing a key first. ECIES enables that. AES requires shared key. |
| **Why random IV each time?** | Same IV + key → same plaintext always encrypts identically. Random IV hides patterns. |
| **Why GCM mode?** | Authenticated encryption. Detects tampering automatically. |
| **Why HKDF?** | Standard-recommended KDF. Extracts randomness. Domain separation prevents key reuse. RFC 5869. |

---

## ATTACK SCENARIOS & HOW MEDLEDGER BLOCKS THEM

```
ATTACK 1: Admin reads ciphertext
→ Ciphertext is encrypted; no DEK on server → unreadable
→ BLOCKED ✓

ATTACK 2: Admin forges permission for self
→ Permission requires ECDSA signature with patient's private key
→ Admin doesn't have it → signature fails → BLOCKED ✓

ATTACK 3: Admin extends time window (16:00 → 23:59)
→ Signature is on original time_end
→ Changed time_end breaks signature hash → BLOCKED ✓

ATTACK 4: Admin deletes audit log
→ Append-only table; entries hash-chained
→ Deletion breaks hash chain (detectable) → BLOCKED ✓

ATTACK 5: Doctor keeps access after revocation
→ Permission marked is_revoked=true
→ Next access: signature verification finds no valid permission → BLOCKED ✓

ATTACK 6: Database breach
→ Ciphertext is garbage without DEK
→ DEK is ECIES-wrapped; no private keys on server
→ Attacker has encrypted ciphertext + encrypted DEK with no keys → BLOCKED ✓
```

---

## NUMBERS TO REMEMBER

- **P-256 private key:** 32 bytes
- **P-256 public key (uncompressed):** 65 bytes (0x04 + 32 + 32)
- **SHA-256 hash:** 32 bytes (64 hex chars)
- **ECDSA signature:** 68-72 bytes (DER-encoded), 140 hex chars
- **AES-256 key:** 32 bytes
- **AES-256-GCM IV:** 12 bytes (random)
- **GCM auth tag:** 16 bytes
- **DEK:** 32 bytes (random)
- **HKDF output:** 32 bytes (for AES-256)

---

## DEPLOYMENT CHECKLIST (What's Still Needed for Production)

- [ ] Independent cryptographic audit (especially Shamir GF-256 impl)
- [ ] Hardware-backed key storage (iOS Secure Enclave, Android Keystore, TPM)
- [ ] Distributed consensus for audit chain (currently single-node)
- [ ] HIPAA compliance review
- [ ] Penetration testing
- [ ] HTTPS / TLS everywhere (currently HTTP in dev)
- [ ] Formal threat modeling with independent security team

---

## YOUR DEMO TALKING POINTS (90 SECONDS)

> "MedLedger solves insider threats in healthcare by replacing trust with math. When a patient registers, a P-256 keypair is generated locally—the private key stays on the device. When the patient uploads a record, it's encrypted with AES-256-GCM and the encryption key is wrapped with ECIES so only the patient can decrypt it. When a doctor wants access, the patient signs a permission grant with their private key. The server verifies that signature on every access. Even if an admin has full database access, they can't read the records because they lack the patient's private key. The demo shows this full flow—registration, upload, encryption, permission grant, and decryption—using genuine cryptographic primitives from the Python cryptography library."

---

## BEFORE YOUR DEMO CHECKLIST

- [ ] Can I explain P-256 in 1 sentence?
- [ ] Can I explain ECDSA in 1 sentence?
- [ ] Can I explain ECIES in 2 sentences?
- [ ] Can I draw the 6-step upload pipeline?
- [ ] Can I draw the 4-step doctor access verification?
- [ ] Can I answer "Why not just AES?" (ECIES answer)
- [ ] Can I answer "Why can't admin forge permission?" (signature answer)
- [ ] Can I answer "What if patient loses private key?" (Shamir answer)
- [ ] Can I run the demo without reading scripts?
- [ ] Can I explain why GCM tag matters?
- [ ] Can I explain why random IV matters?
- [ ] Can I explain why signature must verify on EVERY access (not just once)?

---

## CONFIDENCE MANTRAS

🔐 **"Math enforces access, not policies."**
- Policies can be overridden by admins
- Math cannot be overridden (ECDSA, AES-256-GCM, ECIES are mathematically sound)

🔐 **"The private key is the security root."**
- Private key on patient's device only
- Admin access to database is worthless without it
- Signature verification mathematically requires it

🔐 **"Cryptography doesn't have insider threats."**
- ECDSA signatures can't be forged
- AES-256-GCM ciphertext can't be decrypted without the key
- Attacks are blocked by mathematics, not policy enforcement

🔐 **"The demo uses real cryptography."**
- Not toy code or simplified approximations
- `cryptography.io` library is used in production TLS 1.3
- All primitives (P-256, SHA-256, AES-256-GCM, ECIES) are genuine and standard

---

## FINAL CONFIDENCE CHECK

If you can answer these 10 questions without hesitation, you're ready:

1. What is P-256 and why do we use it? ✓
2. What does ECDSA prove and why can't admin forge it? ✓
3. What does AES-256-GCM do that regular AES doesn't? ✓
4. Why do we need ECIES instead of just AES? ✓
5. What are the 6 steps in the upload pipeline? ✓
6. What are the 4 verification steps for doctor access? ✓
7. Why is the GCM tag important? ✓
8. Why must the IV be random? ✓
9. What happens if the patient loses their private key? ✓
10. What is the security guarantee MedLedger provides? ✓

---

**You've got this. You know the material. Trust your preparation.**

🚀

---
