# MedLedger Quick Reference Card
**For rapid recall during demo and Q&A**

---

## CRYPTO PRIMITIVES AT A GLANCE

| Concept | What | Why | Answer |
|---------|------|-----|--------|
| **P-256** | Elliptic curve for keypairs | NIST standard, TLS 1.3, smaller keys than RSA | "256-bit security, used in TLS 1.3, faster than RSA, keys are only 32 bytes" |
| **ECDSA** | Signs with private key, verify with public key | Proves authorization; admin can't forge without private key | "Signs the permission; forgery requires patient's private key which the server doesn't have" |
| **SHA-256** | Hashes file to 32-byte fingerprint | File identity proof; detects tampering | "Creates a fingerprint; if file changes, hash changes; mathematically infeasible to find collision" |
| **AES-256-GCM** | Encrypts file + detects tampering | Confidentiality + authenticity; random IV prevents pattern leakage | "Encrypts the medical record and detects any tampering; GCM tag makes it fail if tampered" |
| **ECIES** | Encrypts DEK for doctor's public key | Only doctor with private key can decrypt | "Re-locks the key for the doctor using their public key; only their private key unlocks it" |
| **HKDF-SHA256** | Derives AES key from ECDH shared secret | Standard-recommended KDF; domain separation | "Combines the shared secret mathematically to create a random-looking AES key" |
| **Shamir 3-of-5** | Splits key into 5 shares; any 3 reconstruct | Key recovery; info-theoretically secure | "Key is split among 5 trustees; any 3 can reconstruct; any 2 reveal nothing" |

---

## QUICK ANSWERS TO COMMON QUESTIONS

### Q: Why doesn't the server store the encryption key?
**A:** "If the server stored it, an admin could read the encryption key and decrypt all records. By keeping the key encrypted (ECIES-wrapped), only the patient can decrypt it. Server has ciphertext but no key."

### Q: Why ECDSA signatures instead of just access control rules?
**A:** "Rules are policies that an admin can override. Signatures are math. An admin can change a policy rule, but they can't forge a signature without the private key. Cryptography can't be overridden."

### Q: What prevents the admin from creating a fake patient account and accessing records?
**A:** "The admin would need the real patient's private key to sign a valid permission grant. Without it, the signature fails cryptographically. You can't fake a signature—it's mathematics."

### Q: Why random IV for AES-256-GCM each time?
**A:** "If we used the same IV, the same plaintext would produce the same ciphertext every time. Attackers could see patterns. Random IV means same plaintext → different ciphertext each time."

### Q: What if the patient's device is stolen?
**A:** "Shamir 3-of-5 secret sharing lets the patient recover their key from 3 of 5 trusted shares. Plus, they can revoke all old permissions immediately and issue new ones."

### Q: Why is revocation instant?
**A:** "The server verifies the signature on every access, not just once. If permission is revoked (set is_revoked=true), the next signature check finds no valid permission and denies access immediately."

### Q: Can HIPAA regulators force the hospital to give records to law enforcement?
**A:** "The hospital can give encrypted ciphertext, but law enforcement can't decrypt it without the patient's private key (which the server doesn't have). Patient retains decryption authority even under court order."

### Q: Why is the demo important?
**A:** "The demo proves this isn't theoretical. It's real AES-256-GCM, real ECIES, real ECDSA using the cryptography library from production TLS. All the crypto genuinely works."

---

## THE 6-STEP UPLOAD PIPELINE

```
1. SHA-256 hash file
   → File fingerprint (32 bytes)

2. ECDSA sign with patient's private key
   → Signature (70 bytes, DER)
   → Proves: "Patient created this record"

3. Generate random 32-byte DEK
   → Data Encryption Key

4. AES-256-GCM encrypt file with DEK
   → IV (12 bytes) + ciphertext + GCM tag (16 bytes)
   → File is now unreadable

5. ECIES wrap DEK with patient's public key
   → Ephemeral key bundle (JSON)
   → DEK is now encrypted for patient only

6. Send to server
   → Ciphertext (encrypted file) ✓
   → IV + tag (for GCM decryption) ✓
   → Ephemeral key bundle (encrypted DEK) ✓
   → Hash + signature (prove authenticity) ✓
   → Server has encrypted ciphertext but no DEK ✓
```

---

## THE 4-STEP DOCTOR ACCESS VERIFICATION

```
Doctor tries to access record:

1. Permission exists?
   ✓ Doctor + record permission found
   ✗ No permission → ACCESS DENIED

2. Time window valid?
   ✓ current_time between [time_start, time_end]
   ✗ Expired or not yet valid → ACCESS DENIED

3. Signature verifies?
   ✓ ECDSA_verify(patient_public_key, signature, permission) = VALID
   ✗ Signature invalid (tampered permission) → ACCESS DENIED

4. Not revoked?
   ✓ is_revoked = false
   ✗ is_revoked = true → ACCESS DENIED

All 4 pass? → Doctor gets encrypted DEK → decrypts with doctor_private_key
→ Doctor decrypts file with DEK
```

---

## KEY NUMBERS TO KNOW

| Item | Size | Notes |
|------|------|-------|
| Private key (P-256) | 32 bytes | Never on server |
| Public key (uncompressed) | 65 bytes | 0x04 + 64 bytes |
| SHA-256 hash | 32 bytes | 64 hex chars |
| ECDSA signature (DER) | 68-72 bytes | Varies due to leading zeros |
| AES-256 key | 32 bytes | For AES-256-GCM |
| AES-256-GCM IV | 12 bytes | Random each time |
| GCM auth tag | 16 bytes | Appended to ciphertext |
| DEK (Data Encryption Key) | 32 bytes | Random, wrapped for each doctor |
| ECIES shared secret | 32 bytes | From ECDH |

---

## THREAT SCENARIOS & DEFENSES

| Scenario | Attack | Defense | Why It Works |
|----------|--------|---------|--------------|
| **Admin reads DB** | Query ciphertext directly | Ciphertext is encrypted; no DEK on server | Can't decrypt without private key (server doesn't have it) |
| **Admin forges permission** | INSERT fake permission with made-up signature | Signature verification fails | Admin lacks patient's private key |
| **Admin extends time window** | UPDATE permission.time_end to year 2099 | Signature hash mismatch; verification fails | Signature is on original permission; changed time breaks it |
| **Admin deletes audit log** | DELETE from AuditLog | Append-only table; no delete endpoint; hash-chained | Deletion breaks the hash chain (detectable) |
| **Doctor keeps access after revocation** | Uses cached DEK | Permission marked revoked; signature check finds no valid grant | Next access fails signature verification |
| **Hacker steals DB** | Full dump of ciphertext + keys | Keys are ECIES-wrapped; keys are ECIES-wrapped; attacker has no private keys | Ciphertext is garbage without DEK |
| **Doctor account compromised** | Hacker logs in as doctor | Doctor still needs valid patient signature for each record | Credentials alone grant zero access (patient's signature required) |

---

## DEMO FLOW CHEAT SHEET

```
STEP 1: Create Patient Account
  "Click Create Account → Enter name/email/password → Select Patient"
  Behind scenes: P-256 keypair generated locally

STEP 2: Create Doctor Account  
  "Log out → Create Account again → Different email → Select Doctor"
  Behind scenes: Another P-256 keypair generated

STEP 3: Patient Uploads Record
  "Log in as patient → Upload Record → Generate Demo PDF"
  Shows 6-step animation:
    1. SHA-256 hash
    2. ECDSA sign
    3. Generate DEK
    4. AES-256-GCM encrypt
    5. ECIES wrap DEK
    6. Store encrypted blob

STEP 4: Patient Grants Doctor Access
  "My Records → Select record → Grant Doctor Access → Select doctor"
  Shows 5-step animation:
    1. Decrypt DEK (ECIES)
    2. Re-encrypt DEK for doctor (ECIES)
    3. Create permission data
    4. Sign permission (ECDSA)
    5. Store permission + signature

STEP 5: Doctor Views Record
  "Log in as doctor → See patient's record → Decrypt & View"
  Shows 5-step process:
    1. Verify permission exists
    2. Verify time window
    3. Verify ECDSA signature
    4. Decrypt DEK (ECIES)
    5. Decrypt file (AES-256-GCM)
    → Plaintext displayed
```

---

## TALKING POINTS BY AUDIENCE TYPE

### For Security Experts
- "P-256 via NIST secp256r1, RFC 5869 HKDF, RFC 6979 deterministic ECDSA"
- "Permission is cryptographically bound to patient-doctor-record-timewindow tuple"
- "Shamir 3-of-5 is information-theoretically secure"
- "Audit chain is hash-chained append-only; no delete pathway in schema"

### For Doctors
- "You control who sees your records—not administrators"
- "Access automatically expires—you don't trust the hospital to revoke"
- "Complete audit trail—you know who accessed your data and when"
- "If you lose your key, 3 of 5 trusted people can restore it"

### For Business
- "58% of healthcare breaches are insider threats; we eliminate that vector"
- "Math enforces access, not policies that admins can override"
- "Layerable on existing EHR systems—not a replacement"
- "De-risks the hospital: no plaintext records in the database"

### For Hackers
- "Uses cryptography.io (battle-tested, TLS 1.3 library)"
- "No toy crypto—genuine P-256, AES-256-GCM, ECIES"
- "Threat model: insider with DB access cannot read plaintext"
- "Limitations: custom Shamir (needs audit), single-node chain (needs consensus), no HSM (needs enclave)"

---

## RED FLAGS IN ANSWERS (AVOID THESE)

❌ "The server keeps the encryption key encrypted"
✓ "The encryption key is ECIES-wrapped; only the patient's private key can unwrap it"

❌ "Admins can't override because of policy rules"
✓ "Admins can't override because of cryptography—the signature won't verify without the private key"

❌ "We use AES encryption so the server can't read it"
✓ "We use AES-256-GCM, where the private key never reaches the server, so no one there can decrypt"

❌ "The permission is encrypted"
✓ "The permission is ECDSA-signed by the patient; the signature verifies the patient authorized it"

❌ "Revocation works because we remove the permission"
✓ "Revocation works because every access verifies the signature; if the permission is revoked, the signature check finds no valid grant"

---

## STRENGTH LEVEL CHECKLIST

Before going live, ask yourself:

- [ ] Can I explain P-256 without looking it up?
- [ ] Can I draw the ECIES encryption/decryption flow?
- [ ] Can I explain why ECDSA signatures prevent admin forgery?
- [ ] Can I walk through the 6-step upload pipeline in order?
- [ ] Can I explain the 4 doctor access verifications?
- [ ] Can I defend against "Why not just use AES?" (ECIES answer)
- [ ] Can I explain Shamir 3-of-5 in 1-2 sentences?
- [ ] Can I describe a successful admin attack and then explain why MedLedger blocks it?
- [ ] Can I run the demo without reading scripts?
- [ ] Can I answer the most likely 5 questions confidently?

---

## FINAL CONFIDENCE BOOSTER

**Remember:**
- You've built real cryptography (not toy code)
- The crypto stack is standard & battle-tested
- The threat model is precise (insider threat)
- The security guarantee is mathematical (not policy-based)
- You have a working demo as proof

**You know this. Trust your preparation.**

---
