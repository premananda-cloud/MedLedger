# MedLedger Technical Q&A Preparation Guide

**Purpose:** Master cryptography concepts, security model, and demo walkthrough to answer technical questions with precision and confidence.

---

## PART 1: THE PROBLEM & VISION

### Core Problem: 58% of Healthcare Breaches are Insider Threats

Traditional hospital systems rely on **trust, not math**:
- An admin with database access can override access controls
- An admin can delete the audit log that would prove they were there
- Policies and rules only work if admins follow them

**MedLedger's Answer:** Replace trust with cryptography.
> "Cryptography doesn't have insider threats. Math doesn't take bribes."

### Central Security Guarantee

**No database administrator with full server access can read a patient's record without the patient's private key.**

- Patient's private key lives **only on the patient's device**
- Server never sees it, never stores it
- Every access requires cryptographic proof the patient authorized it
- An admin cannot forge this proof without the private key (mathematically impossible)

---

## PART 2: CRYPTOGRAPHIC FOUNDATIONS

### 2.1 Elliptic Curve Cryptography (ECC) — P-256

**What is it?**
A type of public-key cryptography based on the difficulty of the Elliptic Curve Discrete Log Problem (ECDLP). MedLedger uses P-256 (also called secp256r1), a NIST-standardized curve.

**Key Properties:**
- Uses elliptic curves over finite fields: `y² = x³ + ax + b (mod p)`
- P-256 operates over a 256-bit prime field
- Key pair: **private key** (256-bit random number) + **public key** (point on the curve)
- Computationally hard to derive private key from public key

**Why P-256?**
- NIST-approved and widely audited
- Used in TLS 1.3, iOS Secure Enclave, Android Keystore
- 256-bit security level ≈ RSA-3072 strength
- Faster than RSA for the same security level
- Compact keys: 32 bytes private, 65 bytes public (uncompressed)

**Answer Template:**
> "P-256 is an elliptic curve cryptosystem standardized by NIST. We chose it because it's widely audited, used in modern TLS, and gives us 256-bit security equivalent at smaller key sizes than RSA. The private key is a 256-bit random number; the public key is a point on the curve. Deriving the private key from the public key would require solving the discrete logarithm problem, which is computationally infeasible."

---

### 2.2 ECDSA (Elliptic Curve Digital Signature Algorithm) — P-256

**What it does:**
Creates unforgeable signatures that prove a message came from someone who holds a specific private key.

**Process (Signing):**
1. Patient has a message (permission grant data)
2. Hash the message with SHA-256 → 32-byte hash
3. Use private key to create signature (two numbers: r, s)
4. Signature is ~70 bytes, encoded as DER format
5. Return signature in hex (140 characters)

**Process (Verification):**
1. Anyone with the patient's public key can verify
2. Hash the original message (must be identical)
3. Use public key to check if signature is valid for this hash
4. Result: **True** (valid) or **False** (invalid or tampered)

**Why deterministic (RFC 6979)?**
- Standard ECDSA is randomized (different signature each time)
- MedLedger uses RFC 6979 deterministic variant
- Same message + private key = same signature always
- Better for testing and auditability

**Security Properties:**
- Cannot forge signature without private key
- Cannot change message without invalidating signature
- Non-repudiable: signer cannot deny they signed it

**Answer Template:**
> "ECDSA signs a message by hashing it (SHA-256) and using the private key to create two numbers (r, s). Anyone with the public key can verify the signature — if the message was changed, verification fails. We use RFC 6979 deterministic ECDSA, so the same message always produces the same signature. An attacker cannot forge a signature without the private key; the math makes it computationally infeasible."

**Real Example in MedLedger:**
```
Permission data:
{
  "patient_id": "alice-123",
  "doctor_id": "smith-456",
  "record_id": "cancer-diag",
  "time_start": "2025-02-19T14:00:00Z",
  "time_end": "2025-02-19T16:00:00Z",
  "permission_level": "view_only"
}

1. JSON serialization (deterministic, sorted keys)
2. SHA-256 hash → "a4f2e1c9..."
3. ECDSA sign with patient's private key → signature "3045022100..."
4. Server stores: permission + signature
5. Doctor accesses record → server verifies signature with patient's PUBLIC key
6. Signature valid? Grant access. Invalid? Deny (math says so).
```

---

### 2.3 SHA-256 Hashing

**What it does:**
Converts any data (file, text, message) into a fixed-size 256-bit (32-byte) fingerprint.

**Properties:**
- **Deterministic:** Same input → same hash always
- **Fast:** Computes in milliseconds
- **Fixed output:** Always 32 bytes (256 bits), regardless of input size
- **One-way:** Cannot reverse hash back to original data
- **Collision-resistant:** Computationally infeasible to find two inputs with same hash
- **Avalanche effect:** Tiny change in input → completely different hash

**Example:**
```
SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA256("hallo") = d3751713b7e979c5898dcc03db660c4d661208d262a1573ba9a11a959a3673d8
                                          ↑
                               Changed only one letter, completely different hash
```

**Why we use it:**
- Creates a file "fingerprint" that proves file identity
- If file is modified, hash changes
- Storage-efficient: store 32 bytes instead of storing full file

**Answer Template:**
> "SHA-256 is a cryptographic hash function that produces a 256-bit fingerprint of any data. It's deterministic, one-way, and collision-resistant. In MedLedger, we hash the file to create a fingerprint that proves file identity. If the file is tampered with, the hash changes. It's mathematically infeasible to find two different files with the same hash."

---

### 2.4 AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode)

**What it does:**
Encrypts data using a symmetric key, with built-in **authentication** to detect tampering.

**Components:**
- **AES-256:** Block cipher using a 256-bit key (32 bytes)
- **GCM (Galois/Counter Mode):** Mode that provides:
  - Confidentiality (encrypted data is unreadable)
  - Authenticity (detects tampering)
  - Integrity (ensures data wasn't modified)

**Encryption Process:**
```
Input: plaintext (any size), 32-byte key (DEK)
1. Generate random 12-byte IV (Initialization Vector)
2. Encrypt plaintext with AES-256 in GCM mode
3. GCM produces: ciphertext + 16-byte authentication tag
4. Output: IV (12 bytes) + ciphertext + tag (16 bytes)
```

**Decryption Process:**
```
Input: IV + ciphertext + tag, 32-byte key (same key)
1. Check authentication tag first
   - If tag is invalid → REJECT (data was tampered or wrong key)
   - If tag is valid → proceed
2. Decrypt ciphertext with AES-256 GCM
3. Output: plaintext
```

**Why GCM?**
- **Authenticated encryption:** Prevents tampering
- **Nonce-based:** Each IV is random, so same plaintext encrypts differently each time
- **No padding oracle:** Stream-mode, not block-mode padding
- **Standard:** Used in TLS 1.3, modern standards

**Security Properties:**
- Without the 32-byte key: data is unreadable
- Cannot forge the authentication tag without the key
- Cannot modify ciphertext without detection

**Answer Template:**
> "AES-256-GCM is authenticated encryption. It encrypts data with a 256-bit key and produces a 16-byte authentication tag that prevents tampering. If the ciphertext is modified, decryption fails because the authentication tag no longer matches. We use GCM because it's nonce-based—the same plaintext encrypts differently each time due to a random IV. This is standard in TLS 1.3 and modern cryptography."

**Real Example in MedLedger:**
```
File upload:
1. Generate random 32-byte DEK (Data Encryption Key)
2. SHA-256 hash the file
3. ECDSA sign the hash with patient's private key
4. AES-256-GCM encrypt: file + DEK → IV + ciphertext + tag
5. Server stores: ciphertext, IV, tag, hash, signature
6. Server CANNOT see the file (no DEK stored server-side)

Doctor access:
1. Doctor gets: ciphertext, IV, tag (but not DEK)
2. Server gives doctor: DEK wrapped for doctor's public key
3. Doctor decrypts DEK using doctor's private key
4. Doctor decrypts file: IV + ciphertext + tag + DEK → original file
5. Verify hash and signature to ensure file integrity
```

---

### 2.5 ECIES (Elliptic Curve Integrated Encryption Scheme)

**What it does:**
Encrypts a small secret (like the 32-byte DEK) for a recipient so only they can decrypt it with their private key.

**Why not just AES-256-GCM?**
- AES-256-GCM requires both parties to share a secret key ahead of time
- But we want: patient encrypts DEK for doctor without sharing a secret first
- Solution: Use the doctor's **public key** to encrypt the DEK

**ECIES Encryption Process:**

```
Goal: Encrypt 32-byte DEK for doctor's public key so only doctor can decrypt it

1. Generate ephemeral EC keypair (throwaway key, one-time only)
2. ECDH (Elliptic Curve Diffie-Hellman):
   - ephemeral_private * doctor_public = shared_secret (256-bit)
3. HKDF-SHA256 (Key Derivation Function):
   - shared_secret → AES encryption key (32 bytes)
4. AES-256-GCM encrypt:
   - DEK + AES_key → IV + ciphertext + tag
5. Output bundle (JSON-serializable):
   {
     "epk": "<ephemeral_public_key_hex>",  // 130 chars (65 bytes)
     "iv": "<IV_hex>",                     // 24 chars (12 bytes)
     "ct": "<ciphertext_hex>",             // varies
     "tag": "<GCM_tag_hex>"                // 32 chars (16 bytes)
   }
```

**ECIES Decryption Process:**

```
Goal: Doctor decrypts DEK using doctor's private key

1. Extract ephemeral public key from bundle
2. ECDH:
   - doctor_private * ephemeral_public = shared_secret (same as encryption)
3. HKDF-SHA256:
   - shared_secret → AES encryption key (same key as encryption)
4. AES-256-GCM decrypt:
   - IV + ciphertext + tag + AES_key → DEK
5. If decryption fails (wrong key or tampered data): raise ValueError
6. Return: original DEK
```

**Why ECDH works:**
```
Elliptic Curve math property:
ephemeral_private * doctor_public == doctor_private * ephemeral_public

Both sides compute the same shared_secret!

Encryption side:
  ephemeral_private * doctor_public = shared_secret

Decryption side:
  doctor_private * ephemeral_public = shared_secret (same value!)
```

**Security Properties:**
- Forward secrecy: ephemeral key is discarded after each encryption
- No pre-shared secret needed (unlike AES-256-GCM)
- Authenticated encryption: GCM tag prevents tampering
- Only recipient with private key can decrypt

**Answer Template:**
> "ECIES combines ECDH (Elliptic Curve Diffie-Hellman) with AES-256-GCM. We generate an ephemeral keypair, perform ECDH with the doctor's public key to derive a shared secret, convert that to an AES key via HKDF-SHA256, then encrypt the DEK with AES-256-GCM. Only the doctor with the corresponding private key can compute the same shared secret and decrypt. The ephemeral key is discarded after each encryption, providing forward secrecy."

**Real Example in MedLedger:**

```
Patient grants doctor access:

1. Patient decrypts DEK using own private key:
   ECIES_decrypt(patient_private, doctor_dek_bundle) → original_dek

2. Patient encrypts DEK for doctor:
   ECIES_encrypt(doctor_public, original_dek) → new_dek_bundle

3. Server stores: new_dek_bundle (doctor can only decrypt with doctor's private key)

Doctor views record:

1. Doctor receives: ciphertext (file) + new_dek_bundle
2. Doctor decrypts DEK:
   ECIES_decrypt(doctor_private, new_dek_bundle) → dek
3. Doctor decrypts file:
   AES_GCM_decrypt(dek, iv, ciphertext) → plaintext
```

---

## PART 3: THE MEDLEDGER SYSTEM FLOW

### 3.1 User Registration

**What happens:**

```
Patient opens app → clicks "Create Account"

1. Client generates EC keypair (P-256)
   - Private key stays on device (NEVER transmitted)
   - Public key sent to server

2. Server stores:
   - User ID (e.g., "alice-123")
   - Public key hash (SHA-256 of public key, used as identifier)
   - Public key itself (in hex format)
   - Password hash (for login)

3. Private key stored:
   - Client: encrypted locally in SQLite (medledger.db)
   - Or can be backed up via Shamir secret sharing

Security: Server cannot impersonate patient (no private key)
```

**Answer Template:**
> "During registration, the client generates a P-256 keypair on the device. The private key is stored locally and never transmitted. Only the public key is sent to the server, along with a username and password hash. This means the server never knows the patient's private key—it can only store the public key and use it to verify signatures later."

---

### 3.2 Record Upload & Encryption

**What happens when patient uploads a medical record:**

```
Patient: "I'm uploading my lab report"

STEP 1: Hash the file (SHA-256)
   File → SHA-256 → hash "e4f3a1c2..."

STEP 2: Sign the hash (ECDSA P-256)
   hash + patient_private_key → ECDSA sign → signature "3045022100..."
   (Proves: patient is the original uploader)

STEP 3: Generate Data Encryption Key (DEK)
   Random 256-bit (32-byte) key generated locally

STEP 4: Encrypt the file (AES-256-GCM)
   file + dek → AES-256-GCM encrypt → IV + ciphertext + tag
   (Now the file is unreadable without the DEK)

STEP 5: Wrap the DEK (ECIES)
   dek + patient_public_key → ECIES encrypt → ephemeral_key_bundle
   (DEK is now encrypted for patient's public key only)

STEP 6: Send to server
   Server receives:
   - Ciphertext (encrypted file)
   - IV (for GCM decryption)
   - GCM tag (for authentication)
   - Ephemeral key bundle (DEK encrypted for patient)
   - Hash (SHA-256)
   - Signature (ECDSA)
   - Patient ID
   
   ❌ Ciphertext cannot be read without DEK
   ❌ DEK cannot be decrypted without patient's private key
   ❌ Signature cannot be forged without patient's private key

Security: Server stores encrypted ciphertext, but cannot decrypt it.
         Only patient with private key can decrypt.
```

**Answer Template:**
> "When a patient uploads a file, we perform a 6-step encryption pipeline:
> 1. SHA-256 hash the file (creates fingerprint)
> 2. ECDSA sign the hash with patient's private key (proves authorship)
> 3. Generate random 32-byte DEK (Data Encryption Key)
> 4. AES-256-GCM encrypt the file with DEK (makes file unreadable)
> 5. ECIES wrap the DEK with patient's public key (now only patient can decrypt)
> 6. Server stores only the encrypted ciphertext, not the DEK
> The DEK never goes to the server unencrypted. The ciphertext cannot be read without the DEK. The DEK cannot be decrypted without the patient's private key. So even if an admin gets the database, they see only gibberish."

---

### 3.3 Permission Grant (Patient → Doctor)

**What happens when patient grants doctor access:**

```
Patient: "Dr. Smith can see my cancer diagnosis for 2 hours"

STEP 1: Retrieve the DEK
   Patient's device decrypts the stored DEK:
   ECIES_decrypt(patient_private_key, ephemeral_key_bundle) → dek

STEP 2: Re-encrypt DEK for doctor
   ECIES_encrypt(doctor_public_key, dek) → doctor_dek_bundle
   (Now doctor's private key can decrypt this DEK)

STEP 3: Create permission data
   permission = {
     "patient_id": "alice-123",
     "doctor_id": "smith-456",
     "record_id": "cancer-diag",
     "time_start": "2025-02-19T14:00:00Z",  ← NOW
     "time_end": "2025-02-19T16:00:00Z",    ← 2 hours later
     "permission_level": "view_only"
   }

STEP 4: Sign the permission
   JSON-serialize with sorted keys (deterministic)
   Hash with SHA-256
   ECDSA sign with patient's private key
   → signature "304502210..."

STEP 5: Send to server
   Server receives:
   - doctor_dek_bundle (DEK wrapped for doctor)
   - permission (patient_id, doctor_id, record_id, time window)
   - signature (ECDSA proof patient authorized this)

STEP 6: Server stores permission
   - No DEK is stored plaintext
   - No signature is stored without the permission
   - Doctor cannot decrypt DEK until signature is valid

Security: Permission is cryptographically bound to patient, doctor,
         record, and time window by the ECDSA signature.
         Forging permission requires patient's private key (impossible).
```

**Answering "What if an admin inserts a fake permission?"**

> "The permission is cryptographically signed by the patient. Even if an admin inserts a row into the database with fake permission data, the signature won't match. When the doctor tries to access the record, the server verifies the signature using the patient's public key. The signature fails because the admin doesn't have the patient's private key. Mathematics prevents the fraud."

---

### 3.4 Doctor Views Record

**What happens when doctor accesses a record:**

```
Doctor: "I need to see Alice's lab report"

STEP 1: Check if permission exists
   Server queries: SELECT * FROM permissions 
                   WHERE doctor_id='smith-456' 
                   AND record_id='cancer-diag'
   Found: permission + signature + doctor_dek_bundle

STEP 2: Verify permission is not revoked
   is_revoked = false ✓

STEP 3: Check time window
   current_time = 2025-02-19T14:30:00Z
   permission.time_start = 2025-02-19T14:00:00Z ✓
   permission.time_end = 2025-02-19T16:00:00Z ✓
   Within window ✓

STEP 4: Verify ECDSA signature
   Server has: signature, permission, patient_public_key
   Server verifies: ECDSA_verify(patient_public_key, signature, permission)
   Result: VALID ✓

STEP 5: Doctor decrypts DEK
   Doctor has: doctor_dek_bundle (stored on server)
   Doctor has: doctor_private_key (on doctor's device)
   Doctor decrypts: ECIES_decrypt(doctor_private_key, doctor_dek_bundle) → dek

STEP 6: Doctor decrypts file
   Doctor has: ciphertext, IV, tag (from server)
   Doctor has: dek (just decrypted)
   Doctor decrypts: AES_GCM_decrypt(dek, iv, ciphertext + tag) → plaintext

STEP 7: Doctor verifies file integrity
   Compute: SHA-256(plaintext) → hash
   Compare: hash == stored_hash ✓
   Verify: ECDSA_verify(patient_public_key, signature, hash) ✓
   Result: File is authentic (from patient, not tampered)

STEP 8: Log the access
   AuditLog: {
     "action": "RECORD_ACCESSED",
     "doctor_id": "smith-456",
     "record_id": "cancer-diag",
     "timestamp": "2025-02-19T14:30:00Z",
     "permission_valid": true
   }

Doctor sees the plaintext. Patient knows who accessed their record (audit log).
```

**Answer Template:**
> "When a doctor tries to access a record, the server performs a 4-step verification:
> 1. **Check permission exists** — is there a grant for this doctor-record pair?
> 2. **Check time window** — is the current time within the grant window?
> 3. **Verify ECDSA signature** — does the signature match using the patient's public key? (Prevents admin forgery)
> 4. **Check if revoked** — has the patient revoked this permission?
> 
> If all checks pass, the doctor gets the encrypted DEK bundle. The doctor decrypts it with their private key to get the actual DEK. Then they decrypt the file using AES-256-GCM. The server never gives the doctor the unencrypted DEK—it stays encrypted until the doctor's device decrypts it."

---

### 3.5 Revocation (Instant & Complete)

**What happens when patient revokes a doctor's access:**

```
Patient: "Dr. Smith is fired. Revoke access NOW."

STEP 1: Set revoked flag on server
   UPDATE permissions 
   SET is_revoked = true
   WHERE doctor_id='smith-456' AND record_id='cancer-diag'

STEP 2: Doctor tries to access again
   Doctor sends: "I want to access cancer-diag"
   Server checks: is_revoked = true
   Server responds: ACCESS DENIED

   Why doesn't doctor still have the DEK?
   - Doctor has: doctor_dek_bundle (encrypted on old permission)
   - Without the permission, the server doesn't provide the encrypted bundle
   - Even if doctor had cached it, it's useless without the permission
     (signature verification fails because permission no longer exists)

Result: Revocation is instant and complete.
        No stale keys. No cache expiry. No time window buffer.
        Math enforces it.
```

**Answer Template:**
> "Revocation is cryptographically enforced. When a patient revokes access, the server sets is_revoked=true on the permission. On the next access attempt, the signature verification fails because the permission no longer exists. The doctor's cached DEK bundle is useless without the permission—the server won't authenticate it. Revocation is instant and mathematically enforced, not just a policy flag."

---

## PART 4: SECURITY THREAT MODEL

### 4.1 Standard Attacks & Defenses

| Attacker | Attack | How It Works | MedLedger Defense |
|----------|--------|--------------|-------------------|
| **Admin** | Read plaintext from database | Admin queries DB directly | Records are AES-256-GCM encrypted; DEK is ECIES-wrapped; admin has no private key → unreadable |
| **Admin** | Forge fake permission | Admin INSERT into permissions table | Every permission must be ECDSA-signed with patient's private key; admin can't forge without it → signature fails |
| **Admin** | Extend access time | Admin UPDATE permission to `time_end='2099-12-31'` | Signature verification fails; the new time_end hash doesn't match the old signature → access denied |
| **Admin** | Delete audit log | Admin DELETE from AuditLog | Audit table is append-only; schema has no delete endpoint; entries are hash-chained so deletion breaks the chain (detectable) |
| **Hacker** | Steal database | Full DB dump via SQL injection | Ciphertext only; keys are not in DB; worthless without DEK → quantum-resistant if keys are protected |
| **Compromised doctor** | Access any record | Doctor has login credentials | Doctor still needs valid permission + valid signature; credentials alone grant nothing → patient has full control |
| **Doctor** | Keep access after revocation | Doctor cached the DEK | Without valid permission, signature verification fails even with cached DEK → immediate revocation |
| **Network attacker (MITM)** | Intercept DEK | Attacker sniffs transmission | DEK is transmitted inside ECIES bundle; bundle is encrypted for doctor's public key; attacker can't decrypt without doctor's private key → secure |

---

### 4.2 Attack Scenario: "The Malicious Admin"

```
SCENARIO: Database admin wants to read Alice's cancer diagnosis

ATTEMPT 1: Read ciphertext from database
  Admin queries: SELECT ciphertext FROM Records WHERE patient_id='alice'
  Admin gets: "e4f3a1c2d5b8a9f..."
  Problem: It's encrypted. No key stored on server.
  Result: FAILS ✗

ATTEMPT 2: Forge a permission for self
  Admin tries: INSERT INTO permissions {
    doctor_id: 'admin-malicious',
    patient_id: 'alice',
    record_id: 'cancer-diag',
    ...
  }
  Admin tries to set: signature = 'fake-signature'
  Doctor "admin-malicious" tries to access
  Server verifies: ECDSA_verify(alice_public_key, 'fake-signature', permission_data)
  Result: Signature invalid → ACCESS DENIED ✗
  Why: Admin doesn't have alice's private key, so they can't produce a valid ECDSA signature.
       Cryptography rejects the fraud.

ATTEMPT 3: Decrypt the ciphertext
  Admin has: ciphertext, IV, tag from database
  Admin tries: AES_GCM_decrypt(wrong_dek, iv, ciphertext + tag)
  Result: GCM authentication fails → ValueError ✗
  Why: Each wrong DEK produces garbage; auth tag doesn't match.

ATTEMPT 4: Find the DEK
  Admin searches database for stored DEK
  Result: DEK is never stored plaintext on server.
          DEK is only stored ECIES-wrapped (encrypted for patient's public key).
          Admin can't decrypt ECIES without patient's private key.
  Result: FAILS ✗

ATTEMPT 5: Steal patient's private key
  Admin tries: SELECT private_key FROM Users
  Result: Private key is not in database.
          Private key is stored on patient's device only.
          Even if stored (SQLite medledger.db), it's encrypted locally.
  Result: FAILS ✗

CONCLUSION: Math has defeated the admin. Every vector fails.
```

**Answer Template:**
> "A malicious admin cannot read patient records because:
> 1. Records are AES-256-GCM encrypted; the DEK is never stored plaintext on the server
> 2. Forging permissions requires ECDSA signatures; the admin lacks the patient's private key
> 3. The private key never reaches the server—it stays on the patient's device
> 4. Even with full database access, the admin faces encrypted ciphertext with no key to decrypt it
> Every attack vector is blocked by cryptography, not by access control policies that the admin could override."

---

## PART 5: KEY CRYPTOGRAPHIC CONSTANTS & PARAMETERS

### SHA-256 Hash
- **Output size:** 256 bits (32 bytes)
- **Hex representation:** 64 characters
- **Used for:** File fingerprinting, permission hashing, public key identification

### ECDSA P-256 Signature
- **Curve:** SECP256R1 (P-256)
- **Private key:** 256 bits (32 bytes)
- **Public key:** 65 bytes uncompressed (0x04 + 64 bytes)
- **Signature:** ~70 bytes DER-encoded (68-72 range due to r/s leading-zero stripping)
- **Hex representation:** 140 characters
- **Hash algorithm:** SHA-256

### AES-256-GCM
- **Key size:** 256 bits (32 bytes)
- **IV size:** 96 bits (12 bytes) — recommended for GCM
- **Authentication tag:** 128 bits (16 bytes)
- **Mode:** Galois/Counter Mode (authenticated encryption)

### ECIES (DEK Wrapping)
- **Ephemeral public key:** 65 bytes uncompressed (0x04 + 64 bytes)
- **Shared secret:** 256 bits (32 bytes) from ECDH
- **KDF:** HKDF-SHA256
- **KDF info:** "MedLedger-DEK-v1" (domain separation)
- **Wrapped output:** {epk, iv, ct, tag} as hex strings
- **Total size:** ~200 bytes JSON

### Shamir Secret Sharing (Key Recovery)
- **Curve:** GF(256) — Galois Field with 256 elements
- **Scheme:** 3-of-5 Shamir secret sharing
- **Private key:** Split into 5 shares
- **Reconstruction threshold:** Any 3 shares
- **Security:** Information-theoretically secure
- **Property:** Fewer than 3 shares reveal zero information about the key

---

## PART 6: THE DEMO APP — WALKTHROUGH

### What the Demo Does
A single Python file (`medledger_demo.py`) that demonstrates the entire MedLedger flow **in-memory** with a GUI. No server, no database — everything is local.

### Key Points About the Demo

1. **Real Cryptography:**
   - All crypto is from the `cryptography` library (battle-tested library used in production TLS)
   - P-256, SHA-256, AES-256-GCM, ECIES are all genuine implementations
   - Not toy crypto; not educational approximations

2. **What's Real:**
   - Keypair generation (P-256)
   - File encryption (AES-256-GCM)
   - Key wrapping (ECIES)
   - Signature creation and verification (ECDSA)
   - Permission flow and time window validation

3. **What's Simplified for Demo:**
   - No HTTP server (everything in memory)
   - No database (in-memory dictionaries)
   - No audit log persistence (logged to console)
   - No Shamir secret sharing (key recovery not shown)
   - Animated for learning (crypto happens instantly in production)

### Demo Walkthrough: Step-by-Step

#### Step 1: Register Patient
```
User clicks: "Create Account"
Enters: Name, email, password
Selects: "Patient" role

BEHIND THE SCENES:
1. P-256 keypair generated locally
2. Private key stored in in-memory dict (simulates local storage)
3. Public key hash displayed
4. GUI shows animated key generation
```

#### Step 2: Register Doctor
```
User clicks: "Log out"
Repeats registration with different email
Selects: "Doctor" role

BEHIND THE SCENES:
1. Another P-256 keypair generated
2. Different from patient's key
3. Both users exist in same in-memory session
```

#### Step 3: Patient Uploads & Encrypts Record
```
Patient logs back in
Clicks: "Upload Record"
Option 1: "Generate Demo PDF" (creates fake medical record)
Option 2: "Browse" (select real file)

BEHIND THE SCENES — 6-STEP ANIMATION:
Step 1: SHA-256 hash the file
   File bytes → SHA256 → "a4f2e1c9..."
   Displayed: hash value

Step 2: ECDSA sign the hash
   hash + patient_private_key → ECDSA sign → signature
   Displayed: signature hex (first 16 chars)

Step 3: Generate random DEK
   os.urandom(32) → dek bytes
   Displayed: "32-byte Data Encryption Key generated"

Step 4: AES-256-GCM encrypt file
   file + dek → AES_GCM_encrypt → IV, ciphertext, tag
   Displayed: ciphertext size, IV size, tag

Step 5: ECIES wrap DEK
   dek + patient_public_key → ECIES_encrypt → ephemeral_key_bundle
   Displayed: ephemeral public key, ciphertext

Step 6: Store encrypted blob
   Server (in-memory dict) stores:
   - ciphertext (encrypted file)
   - IV, tag
   - ephemeral_key_bundle (encrypted DEK)
   - hash, signature
   
   ✓ Record uploaded and encrypted.
   ✓ Ciphertext is now unreadable.
```

#### Step 4: Patient Grants Doctor Access
```
Patient goes to: "My Records"
Selects the uploaded record
Clicks: "Grant Doctor Access"
Selects doctor from dropdown
Clicks: "Grant"

BEHIND THE SCENES — 5-STEP ANIMATION:
Step 1: Decrypt DEK
   ECIES_decrypt(patient_private_key, ephemeral_key_bundle) → dek

Step 2: Re-encrypt DEK for doctor
   ECIES_encrypt(doctor_public_key, dek) → new_ephemeral_key_bundle

Step 3: Create permission
   permission = {
     patient_id: ...,
     doctor_id: ...,
     record_id: ...,
     time_start: now,
     time_end: now + 2 hours,
     permission_level: "view_only"
   }

Step 4: Sign permission
   JSON(permission) + patient_private_key → ECDSA sign → signature

Step 5: Store permission + signature
   Server stores: permission + signature + new_ephemeral_key_bundle
   
   ✓ Permission granted.
   ✓ Doctor now has a signed, time-limited access grant.
```

#### Step 5: Doctor Views Record
```
Doctor logs in
Sees Alice's record in the list
Clicks: "Decrypt & View"

BEHIND THE SCENES — 5-STEP VERIFICATION & DECRYPTION:
Step 1: Verify permission exists
   Server checks: permission found ✓

Step 2: Verify time window
   current_time within [time_start, time_end] ✓

Step 3: Verify ECDSA signature
   ECDSA_verify(patient_public_key, signature, permission) → VALID ✓

Step 4: Decrypt DEK
   ECIES_decrypt(doctor_private_key, ephemeral_key_bundle) → dek

Step 5: Decrypt file
   AES_GCM_decrypt(dek, iv, ciphertext + tag) → plaintext
   
   ✓ File is decrypted.
   ✓ Plaintext displayed in the viewer.
```

---

## PART 7: COMMON Q&A PATTERNS

### "Why P-256 instead of RSA?"

> "P-256 and RSA-3072 offer equivalent security (≈256 bits of security), but P-256 is faster and uses smaller keys. P-256 keys are 32 bytes for the private key and 65 bytes for the public key. RSA-3072 keys are 384 bytes. Also, P-256 is used in TLS 1.3, iOS Secure Enclave, and Android Keystore—it's become the modern standard."

### "What if the patient loses their private key?"

> "Shamir 3-of-5 secret sharing solves this. The patient splits their key into 5 shares and distributes them to 5 trusted people (family, lawyer, notary). If they lose their key, they retrieve any 3 of the 5 shares and reconstruct their private key mathematically. This is information-theoretically secure—even if 2 shares are compromised, they reveal nothing about the key."

### "Can the server admin give records to law enforcement?"

> "A court order doesn't change the cryptography. If the admin is served a subpoena, they can provide the encrypted ciphertext, but the patient's records remain unreadable. Law enforcement would need either:
> 1. The patient to decrypt it voluntarily, or
> 2. The patient's private key (which doesn't exist on the server)
> 
> This is an important design decision: MedLedger prioritizes patient privacy even under legal compulsion. The patient retains decryption authority—a hospital system cannot override it."

### "What if a doctor's account is compromised?"

> "The doctor's account gives access only to records the doctor has permission for. A hacker with the doctor's login still cannot:
> 1. Read records the patient hasn't granted access to (no signature, no access)
> 2. Forge a new permission (requires patient's private key)
> 3. Extend the time window of a permission (would break the signature)
> 4. Decrypt the DEK (needs the doctor's actual private key, not stored on the server)
> 
> Patient's private key remains in patient's control."

### "But isn't PKI a solved problem? Why reinvent it?"

> "We're not reinventing PKI. We're applying standard PKI (ECDSA, ECIES, AES-256-GCM) to a specific problem: healthcare data where patients control access, not administrators. Traditional EHR systems use PKI for TLS (secure connections) but trust the server for access control. MedLedger uses cryptography for access control itself—the patient's signature is the only thing that grants access. That's the difference."

### "Why use HKDF-SHA256 for ECIES key derivation?"

> "HKDF (HMAC-based Key Derivation Function) is a standard-recommended KDF. It:
> 1. Produces cryptographically independent keys from the shared secret
> 2. Includes domain separation ('MedLedger-DEK-v1') to prevent key reuse across contexts
> 3. Works even if the shared secret has less entropy than desired
> 4. Is used in TLS 1.3 and other modern protocols
> 
> It's not custom; it's RFC 5869."

### "Why 3-of-5 Shamir, not 2-of-3?"

> "Shamir 2-of-3 means any 2 trustees can reconstruct the key. If one trustee is compromised, the other + attacker can reconstruct. 3-of-5 requires 3 independent trustees; an attacker needs to compromise at least 2 of them. It's a better risk distribution."

### "Can MedLedger prevent the patient from viewing their own records?"

> "No. The patient holds the private key. The patient can always decrypt their own records. The system prevents the patient from accidentally sharing encrypted data with people they don't trust, and it prevents admins from accessing records without the patient's authorization. But the patient retains full decryption authority."

---

## PART 8: DEMO APP TALKING POINTS

When explaining the demo to judges/audience:

### Opening
> "MedLedger solves insider threats in healthcare by replacing trust with math. The demo shows the full patient-to-doctor access flow—from registration, through encrypted upload, to time-limited, patient-controlled permission grants—all using real cryptography from the Python `cryptography` library. Everything you'll see is cryptographically genuine."

### Registration Section
> "When a patient registers, a P-256 keypair is generated locally on the device. The private key stays on the device—it is never transmitted to the server. Only the public key is registered. This is the root of trust: the patient's asymmetric keypair."

### Upload Section
> "When the patient uploads a medical record, we perform a 6-step encryption pipeline. First, we hash the file to create a fingerprint. Second, we sign that hash with the patient's private key, proving the patient is the original uploader. Third, we generate a random 32-byte encryption key. Fourth, we encrypt the file with AES-256-GCM using that key. Fifth, we wrap that encryption key with the patient's public key using ECIES—now only the patient can decrypt it. Sixth, we send the encrypted record to the server. The server stores the encrypted ciphertext but never sees the encryption key. Without the private key, the ciphertext is unreadable."

### Permission Grant Section
> "When the patient wants to grant a doctor time-limited access, the patient decrypts their own encryption key, then re-encrypts it for the doctor's public key. The patient also signs a permission record containing the doctor's ID, record ID, and time window. This permission signature is cryptographically bound to that doctor, that record, and that time window. Even if a malicious admin inserts a fake permission into the database, the signature verification fails because the admin doesn't have the patient's private key. Math prevents the fraud."

### Doctor Access Section
> "When the doctor tries to view the record, the server performs four checks:
> 1. Does a permission exist for this doctor-record pair?
> 2. Is the current time within the permission's validity window?
> 3. Does the ECDSA signature on the permission verify using the patient's public key?
> 4. Has the patient revoked this permission?
> 
> If all four checks pass, the doctor gets the encrypted encryption key. The doctor decrypts it using their own private key, then decrypts the medical record. The server never gives the doctor an unencrypted encryption key—it stays encrypted until the doctor's device decrypts it."

### Security Statement
> "A hospital administrator with full database access still cannot read a patient's record because:
> - The record is encrypted with AES-256-GCM
> - The encryption key is wrapped with ECIES
> - The patient's private key is never on the server
> - Every permission requires a cryptographic signature the admin cannot forge
> 
> This is not a policy enforcement. This is mathematics."

---

## PART 9: EDGE CASES & NUANCES

### Edge Case 1: ECDSA Signature Length Variation
**Question:** "Why do ECDSA signatures vary from 68-72 bytes?"

> "ECDSA P-256 signatures are DER-encoded as two numbers: r and s, each 32 bytes. However, if the leading byte is >= 0x80 (indicates a negative number in two's complement), DER encoding prepends a 0x00 byte to keep it positive. Some signatures have leading zeros stripped, some don't. That's why we see 68-72 bytes instead of a fixed 64 bytes. The code handles this by letting the cryptography library validate the signature—we don't manually check length."

### Edge Case 2: AES-GCM IV Randomness
**Question:** "Why generate a random IV for each AES-256-GCM encryption?"

> "AES-256-GCM with a fixed IV is deterministic—the same plaintext encrypted twice produces the same ciphertext. This leaks information. If Alice encrypts 'I have cancer' twice and both ciphertexts match, an attacker learns Alice uploaded the same record twice. By using a random IV each time, the same plaintext encrypts to different ciphertexts. This hides patterns."

### Edge Case 3: Permission Time Window Clock Skew
**Question:** "What if the doctor's clock is slightly off?"

> "The server performs the time window check, not the doctor. The server uses its authoritative clock to verify that the current_time falls within [time_start, time_end]. If the doctor's clock is off, it doesn't matter—the server is the source of truth. The 'now' is determined by the server, not the client."

### Edge Case 4: Revoked Permission Replayed
**Question:** "If a doctor cached the encrypted DEK before revocation, can they still decrypt?"

> "The doctor has the encrypted DEK, but without a valid permission, the server won't authenticate the access. The server checks is_revoked=true and denies access. Even if the doctor had the unencrypted DEK (they don't—it's encrypted until the permission is valid), they can't present it to the server; the server verifies the permission signature, not the DEK directly. Revocation is enforce through the signature check, not the DEK."

### Edge Case 5: Hash Collision (Theoretical)
**Question:** "What if two files have the same SHA-256 hash?"

> "SHA-256 collision resistance is proven strong (no collisions in 2^256 attempts, which is astronomically large). Even if a collision existed, it would only affect file integrity checking, not access control. Access control is driven by ECDSA signatures on the permission, not the file hash. Tampering with the permission data breaks the signature."

---

## PART 10: PREPARING FOR DIFFERENT AUDIENCES

### For Judges / Security Experts
- Reference specific standards: NIST P-256, RFC 5869 (HKDF), RFC 6979 (deterministic ECDSA)
- Discuss threat model precisely (insider, database breach, compromised doctor account, etc.)
- Mention limitations (Shamir audit needed, no distributed consensus, no HSM backing)
- Emphasize the cryptographic guarantee vs. policy-based guarantee

### For Doctors / Healthcare Domain
- Focus on **patient control**: "Patients decide who sees their records, not admins"
- Emphasize **time-limited access**: "Doctor access auto-expires. You don't have to trust the hospital to revoke"
- Highlight **audit trail**: "Every access is logged. You know exactly who read your records"
- Avoid deep crypto jargon; use analogies: "It's like a digital lock only the patient has the key to"

### For Business / Non-Technical
- Lead with the problem: "58% of healthcare breaches are insider threats"
- Explain the core value: "Math enforces access control, not policies"
- Use simple analogy: "Even if a bank robber steals the vault, they can't read the locked safety deposit boxes. MedLedger is like that."
- Mention deployment: "We're not replacing EHR systems; we're adding a cryptographic layer on top"

### For Hackers / Infosec Community
- Discuss the crypto stack: P-256, AES-256-GCM, ECIES, Shamir
- Explain the threat model: What MedLedger defends against (insider, admin, DB breach) and what it doesn't (compromised patient device, weak patient password)
- Mention the audit approach: Hash-chained append-only logs
- Acknowledge limitations: No distributed consensus, custom Shamir impl, no HSM

---

## PART 11: FINAL CONFIDENCE CHECKLIST

Before your demo / Q&A session, ensure you can answer:

- [ ] **P-256:** What curve is it? Why chosen? Key sizes? Discrete log problem?
- [ ] **ECDSA:** What does it sign? Why RFC 6979 (deterministic)? How is it verified?
- [ ] **SHA-256:** What does it produce? One-way property? Used for what in MedLedger?
- [ ] **AES-256-GCM:** How does it encrypt? What's GCM mode? How does auth tag work?
- [ ] **ECIES:** Why not just AES? How does ECDH provide shared secret? Why ephemeral key?
- [ ] **HKDF:** What's it for? Why "MedLedger-DEK-v1" info string?
- [ ] **Registration:** What's on the device? What's on the server?
- [ ] **Upload:** Six-step pipeline. What happens at each step?
- [ ] **Permission:** What's signed? Why signature prevents forgery?
- [ ] **Doctor Access:** Four checks. What order? Why signature verification?
- [ ] **Revocation:** How is it enforced? Why can't doctor replay old DEK?
- [ ] **Shamir:** Why 3-of-5? Information-theoretic security?
- [ ] **Admin Attack:** Why can't admin read plaintext? Can't forge permission? Can't delete log?
- [ ] **Demo walkthrough:** Can you explain each of the 5 demo steps clearly?

---

## PART 12: QUICK REFERENCE CHEAT SHEET

```
CRYPTOGRAPHIC PRIMITIVES USED:
────────────────────────────────────────────────────────
P-256 ECDSA       → Sign/verify permissions
SHA-256           → Hash files (fingerprint)
AES-256-GCM       → Encrypt files (confidentiality + authenticity)
ECIES (ECDH+KDF)  → Wrap encryption keys for specific recipients
HKDF-SHA256       → Derive AES key from ECDH shared secret
Shamir 3-of-5     → Recover key from 3 of 5 shares

DATA FLOW:
────────────────────────────────────────────────────────
Patient Upload:
  file → SHA256 → sign w/ private_key
  file → AES-GCM (random DEK) → ciphertext
  DEK → ECIES(patient_pub) → encrypted_DEK
  Server stores: ciphertext, encrypted_DEK, hash, sig

Grant Doctor Access:
  DEK ← ECIES_decrypt(patient_priv, encrypted_DEK)
  encrypted_DEK_for_doctor ← ECIES_encrypt(doctor_pub, DEK)
  permission ← {patient, doctor, record, time_start, time_end}
  sig ← ECDSA_sign(patient_priv, permission)
  Server stores: encrypted_DEK_for_doctor, permission, sig

Doctor View:
  Verify: permission exists, time window OK, signature valid, not revoked
  DEK ← ECIES_decrypt(doctor_priv, encrypted_DEK_for_doctor)
  plaintext ← AES_GCM_decrypt(DEK, ciphertext)

KEY SECURITY GUARANTEES:
────────────────────────────────────────────────────────
1. Admin cannot read plaintext (encrypted + no DEK on server)
2. Admin cannot forge permission (requires private key for signature)
3. Admin cannot delete audit logs (append-only, hash-chained)
4. Revocation is instant (permission validity checked on every access)
5. Patient loses key → Shamir recovery (3-of-5)

COMMON SIZES:
────────────────────────────────────────────────────────
Private key (P-256)      → 32 bytes
Public key (uncompressed) → 65 bytes
ECDSA signature (DER)    → 68-72 bytes
SHA-256 hash            → 32 bytes (64 hex chars)
AES-256-GCM IV          → 12 bytes
GCM auth tag            → 16 bytes
DEK                     → 32 bytes
```

---

## FINAL TIPS FOR DEMO PRESENTATION

1. **Go slowly.** Cryptography is dense. Pause between concepts.

2. **Use analogies:**
   - P-256 keypair: "A unique lock-unlock mechanism only you have"
   - ECDSA signature: "A mathematical stamp proving you authorized this"
   - ECIES key wrapping: "Re-locking the safe deposit box for the doctor to open with their key"
   - AES-256-GCM: "A tamper-evident seal that also encrypts"

3. **Avoid jargon (unless audience is crypto-savvy):**
   - Instead of "ECDH shared secret derivation via HKDF"
   - Say: "We combine the patient's and doctor's keys mathematically to create a shared secret, then derive an encryption key from it"

4. **Highlight the demo as proof:**
   - "This isn't a concept—this is actual encryption happening in real-time using the same library used in production TLS"

5. **When audience asks a question you don't know:**
   - "That's a great question. Let me think through the threat model... [pause]"
   - "I want to give you a precise answer. Let me check the documentation."
   - Never make up crypto. Honesty is credibility.

6. **Pre-demo preparation:**
   - Practice running the demo on your machine twice
   - Know the exact button names and navigation flow
   - Time each step to stay within time limits
   - Have a backup: screenshots or video of the demo if technical failure occurs

---

**You're ready. Go ace it.** 🚀

---
