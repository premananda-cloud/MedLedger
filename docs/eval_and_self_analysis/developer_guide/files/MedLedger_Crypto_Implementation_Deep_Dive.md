# MedLedger Cryptography Implementation Deep Dive
**Detailed walkthroughs of actual code implementations**

---

## PART 1: ECIES IMPLEMENTATION (src/crypto/ecies.py)

### What ECIES Does
Encrypts a 32-byte DEK (Data Encryption Key) for a recipient so only they can decrypt it with their private key.

### The Code Walkthrough

#### ECIES Encryption: `ecies_encrypt(recipient_public_key_hex, plaintext)`

```python
# Input: recipient_public_key_hex (65 bytes as hex string)
#        plaintext (32-byte DEK)

# Step 1: Parse recipient public key
recipient_pub = _load_public_key_hex(recipient_public_key_hex)
# This converts the hex string back to a cryptography.io EllipticCurvePublicKey object

# Step 2: Generate ephemeral keypair (one-time throwaway)
eph_private = ec.generate_private_key(_CURVE, _BACKEND)
eph_public  = eph_private.public_key()
# These are fresh random keys, used only for this one encryption
# Discarded after this function returns

# Step 3: ECDH - Compute shared secret
shared_secret = eph_private.exchange(ec.ECDH(), recipient_pub)
# Math: ephemeral_private * recipient_public = 32-byte shared_secret
# This shared_secret is the same value the recipient will compute with:
#   recipient_private * ephemeral_public

# Step 4: Derive AES key via HKDF-SHA256
aes_key = _hkdf(shared_secret)
# HKDF takes the 32-byte shared_secret and produces a 32-byte AES key
# Deterministic: same shared_secret always produces same AES key
# The info parameter "MedLedger-DEK-v1" ensures this key can't be reused elsewhere

# Step 5: AES-256-GCM encrypt the DEK
iv = os.urandom(12)                    # 12-byte random IV (nonce)
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(iv, plaintext, None)
# aesgcm.encrypt() returns: actual_ciphertext + 16-byte GCM auth tag
# We split them for clarity (though they're transmitted together in practice)
ct_body = ciphertext[:-16]             # Just the ciphertext
tag = ciphertext[-16:]                 # The 16-byte GCM tag

# Step 6: Serialize ephemeral public key (65 bytes, uncompressed)
epk_bytes = eph_public.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)
# X962 uncompressed format: 0x04 (1 byte) + x coordinate (32 bytes) + y coordinate (32 bytes)

# Step 7: Return as JSON-serializable dict
return {
    "epk": epk_bytes.hex(),    # 130 chars (65 bytes × 2)
    "iv":  iv.hex(),           # 24 chars (12 bytes × 2)
    "ct":  ct_body.hex(),      # variable length
    "tag": tag.hex(),          # 32 chars (16 bytes × 2)
}
```

**Security Properties:**
- **Ephemeral key:** Used once and discarded → forward secrecy
- **Random IV:** Each encryption produces different ciphertext → hides patterns
- **GCM tag:** Detects tampering (ciphertext, IV, or tag modified → decryption fails)
- **HKDF:** Standard-recommended KDF with domain separation

#### ECIES Decryption: `ecies_decrypt(recipient_private_key_pem, bundle)`

```python
# Input: recipient_private_key_pem (PEM-encoded EC private key)
#        bundle (dict from ecies_encrypt())

# Step 1: Extract components from bundle
epk_bytes = bytes.fromhex(bundle["epk"])   # Ephemeral public key (65 bytes)
iv = bytes.fromhex(bundle["iv"])           # IV (12 bytes)
ct_body = bytes.fromhex(bundle["ct"])      # Ciphertext
tag = bytes.fromhex(bundle["tag"])         # GCM tag (16 bytes)

# Step 2: Load recipient private key
recipient_priv = serialization.load_pem_private_key(
    recipient_private_key_pem.encode("utf-8"),
    password=None,
    backend=_BACKEND,
)
# This is the recipient's actual private key (32 bytes)
# Only the recipient has this; the sender (encryptor) never knew it

# Step 3: Load ephemeral public key
eph_public = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, epk_bytes)
# Reconstruct the ephemeral public key from the uncompressed encoding
# The sender sent this publicly in the bundle

# Step 4: ECDH - Compute shared secret
shared_secret = recipient_priv.exchange(ec.ECDH(), eph_public)
# Math: recipient_private * ephemeral_public = 32-byte shared_secret
# This is the SAME shared_secret the sender computed using:
#   ephemeral_private * recipient_public

# Step 5: Derive AES key (same way as encryption)
aes_key = _hkdf(shared_secret)
# Same HKDF process → same AES key (because same shared_secret)

# Step 6: AES-256-GCM decrypt
aesgcm = AESGCM(aes_key)
plaintext = aesgcm.decrypt(iv, ct_body + tag, None)
# GCM automatically checks the auth tag during decryption
# If tag doesn't match → raises ValueError (cryptographic authentication failure)
# If tag matches → guaranteed ciphertext wasn't tampered

# Return the original plaintext (the DEK)
return plaintext
```

**Security Properties:**
- **Private key required:** Only holder of recipient_private_key can decrypt
- **Auth tag check:** Automatic; wrong key produces garbage, not silent failure
- **Deterministic:** Same bundle + private key always produces same plaintext

#### HKDF Helper: `_hkdf(shared_secret)`

```python
def _hkdf(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),    # Hash algorithm
        length=32,                    # Output 32 bytes (for AES-256)
        salt=None,                    # No salt (ECDH shared secret is random enough)
        info=_HKDF_INFO,              # Domain separation: "MedLedger-DEK-v1"
        backend=_BACKEND,
    ).derive(shared_secret)
```

**Why HKDF?**
- Extracts randomness from shared_secret (even if slightly biased)
- Expands to desired key length (32 bytes)
- Domain separation prevents key reuse if this KDF is used elsewhere
- RFC 5869 standard (used in TLS 1.3)

---

## PART 2: ECDSA SIGNATURE IMPLEMENTATION (src/crypto/signature_verifier.py)

### What ECDSA Does
Proves a message was signed by someone with a specific private key, without revealing the private key.

### The Code Walkthrough

#### Signature Creation: `sign_permission(private_key_pem, permission_data)`

```python
# Input: private_key_pem (PEM-encoded EC private key)
#        permission_data (dict with patient_id, doctor_id, record_id, times, etc.)

# Step 1: Load private key
private_key = serialization.load_pem_private_key(
    private_key_pem.encode('utf-8'),
    password=None,
    backend=self.backend
)
# This is the patient's 32-byte private key

# Step 2: Serialize permission data deterministically
permission_json = json.dumps(
    permission_data,
    sort_keys=True,           # Critical: sorted keys for reproducibility
    separators=(',', ':')     # Compact format (no spaces)
)
# Example result:
# '{"doctor_id":"smith-456","patient_id":"alice-123","permission_level":"view_only","record_id":"cancer-diag","time_end":"2025-02-19T16:00:00Z","time_start":"2025-02-19T14:00:00Z"}'

# Why deterministic?
# If the JSON isn't identical, the signature won't verify later
# Sorted keys ensure consistency even if Python dicts reorder

# Step 3: ECDSA sign
signature_bytes = private_key.sign(
    permission_json.encode('utf-8'),  # Convert JSON string to bytes
    ec.ECDSA(self.hash_algorithm)     # ECDSA with SHA-256 (RFC 6979 deterministic)
)
# Inside the library:
#   1. SHA-256(permission_json) → 32-byte hash
#   2. ECDSA math with private_key → 70-byte DER-encoded signature
#   3. Signature contains two values (r, s) that prove the patient signed this specific data

# Step 4: Return signature as hex
return signature_bytes.hex()
# Result: "304502210099aabbcc...ffee0201abcd..." (140 hex chars)
```

**Why Deterministic ECDSA (RFC 6979)?**
- Standard ECDSA uses random nonce k, so same message produces different signatures each time
- RFC 6979 derives k deterministically from the message and private key
- Result: Same message always produces same signature
- Benefit: Better auditability; easier testing; harder to accidentally leak private key via nonce

#### Signature Verification: `verify_signature(public_key_hex, signature_hex, permission_data)`

```python
# Input: public_key_hex (65 bytes as hex string, from public_key.public_bytes())
#        signature_hex (70-byte signature as hex string)
#        permission_data (dict — must be IDENTICAL to what was signed)

try:
    # Step 1: Parse signature from hex
    signature_bytes = bytes.fromhex(signature_hex)
    # Result: raw DER-encoded signature bytes

    # Step 2: Reconstruct public key from hex
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Validate format (uncompressed: 0x04 + 64 bytes)
    if len(public_key_bytes) != 65 or public_key_bytes[0] != 0x04:
        return False, "Invalid public key format"
    
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        self.curve,
        public_key_bytes
    )
    # This is the patient's public key (65 bytes)
    # Derived from private key by: public_key = private_key * generator_point
    # It's public; anyone can have it

    # Step 3: Serialize permission data (MUST be identical to signing)
    permission_json = json.dumps(
        permission_data,
        sort_keys=True,
        separators=(',', ':')
    )
    # This JSON must be byte-for-byte identical to what was signed
    # Even one character difference → signature fails

    # Step 4: Verify signature
    public_key.verify(
        signature_bytes,
        permission_json.encode('utf-8'),
        ec.ECDSA(self.hash_algorithm)
    )
    # Inside the library:
    #   1. SHA-256(permission_json) → 32-byte hash
    #   2. ECDSA math with public_key + signature → check if valid
    #   3. If invalid: raises InvalidSignature exception
    
    return True, ""  # Valid signature

except InvalidSignature:
    return False, "Signature verification failed"

except Exception as e:
    return False, f"Verification error: {str(e)}"
```

**What Makes This Secure?**
1. **Private key required to create signature:** Only patient has their private key
2. **Cannot forge signature:** Requires solving ECDLP (elliptic curve discrete log problem)
3. **Cannot modify permission after signing:** Changes message hash → signature fails
4. **Public key is public:** Anyone can verify, but only holder of private key can sign
5. **Non-repudiable:** Patient cannot deny they signed it (they alone have the private key)

#### Permission Signing Example

```python
# Patient creates permission:
permission_data = {
    "patient_id": "alice-123",
    "doctor_id": "smith-456",
    "record_id": "cancer-diag",
    "time_start": "2025-02-19T14:00:00Z",
    "time_end": "2025-02-19T16:00:00Z",
    "permission_level": "view_only"
}

# Patient signs it:
signature = verifier.sign_permission(
    patient_private_key_pem,
    permission_data
)
# Result: "304502210086bf4e9ccb..."

# Server stores:
permission_stored = {
    "patient_id": "alice-123",
    "doctor_id": "smith-456",
    "record_id": "cancer-diag",
    "time_start": "2025-02-19T14:00:00Z",
    "time_end": "2025-02-19T16:00:00Z",
    "permission_level": "view_only",
    "signature": "304502210086bf4e9ccb..."
}

# If admin tries to change doctor_id:
tampered = permission_stored.copy()
tampered["doctor_id"] = "doctor-evil-999"  # Change who can access

# Server verifies:
is_valid, reason = verifier.verify_signature(
    alice_public_key_hex,
    signature,
    tampered  # ← Different data
)
# Result: False, "Signature verification failed"
# Why: tampered["doctor_id"] changed → JSON is different → hash is different → signature fails
```

---

## PART 3: AES-256-GCM IMPLEMENTATION

### What AES-256-GCM Does
Encrypts data + detects tampering with authenticated encryption.

### The Code Walkthrough

#### AES-256-GCM Encryption: `aes_gcm_encrypt(dek, plaintext)`

```python
def aes_gcm_encrypt(dek: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    # Input: dek (32-byte key)
    #        plaintext (any size, typically a medical record file)
    
    # Step 1: Generate random IV (nonce)
    iv = os.urandom(12)
    # 12 bytes is the recommended IV size for GCM
    # Must be unique for each encryption with the same key
    # (If you reuse IV + key, security breaks; patterns leak)
    
    # Step 2: Create AES-GCM cipher
    aesgcm = AESGCM(dek)
    # Initialize with the 32-byte key
    
    # Step 3: Encrypt
    ct = aesgcm.encrypt(iv, plaintext, None)
    # encrypt() returns: actual_ciphertext + 16-byte GCM tag
    # The GCM tag is the "authentication" part
    
    # The tag is computed over:
    # - The ciphertext (detects tampering in encrypted data)
    # - The IV (if IV is changed, tag fails)
    # - No additional authenticated data (last parameter is None)
    
    return iv, ct
    # Return: IV (12 bytes) + ciphertext + GCM tag (16 bytes)
    # All needed for decryption later
```

#### AES-256-GCM Decryption: `aes_gcm_decrypt(dek, iv, ciphertext_with_tag)`

```python
def aes_gcm_decrypt(dek: bytes, iv: bytes, ciphertext_with_tag: bytes) -> bytes:
    # Input: dek (32-byte key — SAME key used for encryption)
    #        iv (12-byte nonce from encryption)
    #        ciphertext_with_tag (ciphertext + 16-byte tag)
    
    try:
        aesgcm = AESGCM(dek)
        
        # GCM automatically checks tag during decryption
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        
        # If tag is valid:
        # - Ciphertext is decrypted
        # - IV matches
        # - Nothing was tampered
        # Returns the original plaintext
        
        # If tag is invalid (wrong key, tampered ciphertext, wrong IV):
        # - Raises cryptography.hazmat.primitives.InvalidTag exception
        
        return plaintext
    
    except Exception as exc:
        raise ValueError(f"AES-GCM decryption failed: {exc}") from exc
```

#### Attack Scenario: What Happens If Data Is Tampered?

```python
# Original encryption:
dek = os.urandom(32)
file_plaintext = b"PATIENT: John Doe\nDIAGNOSIS: Cancer"
iv, ct_with_tag = aes_gcm_encrypt(dek, file_plaintext)

# Attacker intercepts and modifies ciphertext:
ct_with_tag_tampered = ct_with_tag[:-20] + b'X' * 20  # Change last 20 bytes

# Doctor tries to decrypt with correct key:
try:
    plaintext = aes_gcm_decrypt(dek, iv, ct_with_tag_tampered)
except ValueError as e:
    print(f"Decryption failed: {e}")
    # Error: cryptography.hazmat.primitives.InvalidTag

# Why?
# The GCM tag was computed over the original ciphertext
# When we decrypt, GCM recomputes the tag and compares:
# - Original tag: "a4f3e1b2..."
# - Recomputed tag: "9f8c2d1e..."
# They don't match → REJECT
```

**Why GCM?**
- **Authenticated encryption:** Prevents ciphertext tampering
- **Automatic authentication check:** No manual verification needed
- **Nonce-based:** Different IV → different ciphertext (hides patterns)
- **Efficient:** Combines encryption and authentication in one pass
- **Standard:** Used in TLS 1.3, IPsec, WireGuard

---

## PART 4: KEY MANAGEMENT (src/crypto/key_manager.py)

### What It Does
Generates and manages P-256 keypairs; stores them securely on the client.

### The Code Walkthrough

#### Keypair Generation

```python
def generate_keypair(self) -> KeyPair:
    # Generate new EC keypair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Serialize private key (PEM format — standard format for keys)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    # Serialize public key (hex format for JSON storage)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    public_key_hex = public_key_bytes.hex()
    
    # Create hash of public key (for identification on server)
    public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
    
    return KeyPair(
        private_key_pem=private_key_pem.decode('utf-8'),
        public_key_hex=public_key_hex,
        public_key_hash=public_key_hash,
        created_at=datetime.utcnow()
    )
```

#### Key Storage (Client Side)

```python
# Private key stored locally in SQLite (medledger.db)
# Not transmitted to server

# Server stores:
# - User ID (username)
# - Public key hash (for identification)
# - Public key (for signature verification)

# Private key is never transmitted, even encrypted
# This is the security foundation of MedLedger
```

---

## PART 5: PUTTING IT ALL TOGETHER — FULL RECORD ENCRYPTION FLOW

### Patient Uploads Medical Record

```python
# Patient has: private_key_pem, public_key_hex
# File: cancer_diagnosis.pdf (binary data)

# STEP 1: Hash the file
file_hash = hashlib.sha256(file_data).hexdigest()
# Result: "e4f3a1c2d5b8a9f..." (64 hex chars)

# STEP 2: Sign the hash
verifier = SignatureVerifier()
signature = verifier.sign_permission(
    private_key_pem,
    {"file_hash": file_hash}
)
# Result: "304502210099aabbcc..." (140 hex chars)

# STEP 3: Generate DEK
dek = os.urandom(32)
# 32 random bytes

# STEP 4: Encrypt file with AES-256-GCM
from ecies import aes_gcm_encrypt
iv, ciphertext_with_tag = aes_gcm_encrypt(dek, file_data)
# Result: IV (12 bytes) + ciphertext + GCM tag (16 bytes)

# STEP 5: Wrap DEK with ECIES
from ecies import ecies_encrypt
dek_bundle = ecies_encrypt(public_key_hex, dek)
# Result: {"epk": "...", "iv": "...", "ct": "...", "tag": "..."}

# STEP 6: Store on server
record = {
    "patient_id": "alice-123",
    "record_id": "cancer-diag",
    "file_hash": file_hash,
    "signature": signature,
    "iv": iv.hex(),
    "ciphertext": ciphertext_with_tag.hex(),
    "dek_bundle": dek_bundle,
    "uploaded_at": datetime.utcnow().isoformat()
}
```

### Doctor Decrypts Record

```python
# Doctor has: private_key_pem, patient_public_key_hex
# Server provides: record (from above)

# STEP 1: Verify signature
verifier = SignatureVerifier()
is_valid, _ = verifier.verify_signature(
    patient_public_key_hex,
    record["signature"],
    {"file_hash": record["file_hash"]}
)
if not is_valid:
    raise ValueError("Signature verification failed")

# STEP 2: Decrypt DEK
from ecies import ecies_decrypt
dek = ecies_decrypt(
    doctor_private_key_pem,
    record["dek_bundle"]
)
# Result: 32-byte DEK

# STEP 3: Decrypt file
from ecies import aes_gcm_decrypt
iv = bytes.fromhex(record["iv"])
ciphertext_with_tag = bytes.fromhex(record["ciphertext"])
plaintext = aes_gcm_decrypt(dek, iv, ciphertext_with_tag)
# Result: Original file data

# STEP 4: Verify file integrity
verified_hash = hashlib.sha256(plaintext).hexdigest()
if verified_hash != record["file_hash"]:
    raise ValueError("File integrity check failed")

# STEP 5: Show plaintext to doctor
print(f"Decrypted file: {plaintext}")
```

---

## PART 6: COMMON CRYPTOGRAPHIC PITFALLS (AND HOW MEDLEDGER AVOIDS THEM)

### Pitfall 1: Reusing IV in GCM

❌ **Wrong:**
```python
iv = b"fixed12bytes!!!"  # Same IV every time
for plaintext in [data1, data2, data3]:
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
```
**Problem:** Same plaintext encrypts identically every time. Patterns leak.

✓ **Right (MedLedger):**
```python
iv = os.urandom(12)  # Random IV for each encryption
ciphertext = aesgcm.encrypt(iv, plaintext, None)
```

### Pitfall 2: Not Verifying GCM Tag

❌ **Wrong:**
```python
ciphertext_without_tag = encrypted_data[:-16]
plaintext = aesgcm.decrypt(iv, ciphertext_without_tag, None)
# Skips authentication; decryption succeeds even if tampered
```

✓ **Right (MedLedger):**
```python
ciphertext_with_tag = encrypted_data  # Include tag
plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
# Automatic: GCM verifies tag; raises error if tampered
```

### Pitfall 3: Non-Deterministic JSON Serialization

❌ **Wrong:**
```python
permission_json = json.dumps(permission_data)  # Order can vary
signature = sign(permission_json)
# Later verification:
permission_json2 = json.dumps(permission_data)  # Order might differ
verify(signature, permission_json2)  # Might fail (different JSON)
```

✓ **Right (MedLedger):**
```python
permission_json = json.dumps(
    permission_data,
    sort_keys=True,      # Deterministic order
    separators=(',', ':')  # Compact format
)
signature = sign(permission_json)
# Later verification always uses same serialization
```

### Pitfall 4: Storing Private Keys on Server

❌ **Wrong:**
```python
# Server stores private keys in database
database.insert({
    "user_id": "alice",
    "private_key": private_key_pem
})
# Admin can steal all private keys
```

✓ **Right (MedLedger):**
```python
# Private key stored ONLY on client device
# Server stores only:
database.insert({
    "user_id": "alice",
    "public_key_hex": public_key_hex,
    "public_key_hash": public_key_hash
})
# Admin cannot read private keys (they're not on server)
```

### Pitfall 5: Allowing Admin to Forge Permissions

❌ **Wrong:**
```python
# Admin can insert permission without signature
database.insert({
    "patient_id": "alice",
    "doctor_id": "evil-admin",
    "record_id": "cancer-diag"
})
# Admin grants self access directly
```

✓ **Right (MedLedger):**
```python
# Every permission must be ECDSA-signed by patient
permission = {
    "patient_id": "alice",
    "doctor_id": "smith",
    "record_id": "cancer-diag",
    "time_start": "...",
    "time_end": "..."
}
signature = patient_private_key.sign(permission_json)

# Server verifies:
public_key.verify(signature, permission_json)
# If admin tries to change doctor_id:
permission["doctor_id"] = "evil-admin"  # ← Modified
public_key.verify(signature, permission_json)  # ← FAILS
# Signature doesn't match changed data
```

---

## PART 7: PERFORMANCE CHARACTERISTICS

### Cryptographic Operation Timings (on modern hardware)

| Operation | Time | Notes |
|-----------|------|-------|
| P-256 keypair generation | 10-50 ms | One-time on registration |
| ECDSA signature (RFC 6979) | 5-10 ms | Per permission grant |
| ECDSA signature verification | 5-10 ms | Per record access |
| SHA-256 hashing | <1 ms per MB | Hash file once on upload |
| AES-256-GCM encryption | <1 ms per MB | Encrypt large files fast |
| ECIES encryption (32-byte DEK) | <1 ms | Small payload |
| ECIES decryption (32-byte DEK) | <1 ms | Small payload |
| Shamir 3-of-5 share reconstruction | 10-100 ms | Key recovery (rare) |

**Practical Impact:**
- File upload: Dominated by network, not crypto
- Doctor access: Signature verification is <10 ms
- No bottlenecks from cryptography

---

## PART 8: DEBUGGING COMMON CRYPTO ERRORS

### Error: "Failed to load private key"
**Cause:** PEM format incorrect (wrong encoding, corruption, newlines)
**Fix:** Ensure private key is stored exactly as generated; preserve PEM format

### Error: "Signature verification failed"
**Cause 1:** Permission data changed after signing (different doctor_id, time_end, etc.)
**Fix:** Serialize permission identically (sorted keys, compact separators)
**Cause 2:** Wrong public key used for verification
**Fix:** Use patient's public key, not doctor's

### Error: "Decryption failed (wrong key or tampered data)"
**Cause 1:** Wrong DEK used for decryption
**Fix:** Ensure correct DEK is decrypted from ECIES bundle first
**Cause 2:** Ciphertext or IV or GCM tag modified in transit
**Fix:** Use HTTPS to prevent tampering in transit

### Error: "Invalid public key format"
**Cause:** Public key not in uncompressed format (0x04 + 64 bytes)
**Fix:** Ensure public key is serialized with Encoding.X962 + UncompressedPoint

---

## FINAL REMINDERS

1. **Private keys are sacred:** Never transmit, log, or store on server
2. **Signatures are proofs:** Verify them on every access
3. **GCM tags are mandatory:** Never skip authentication checks
4. **JSON must be deterministic:** Sort keys, use compact separators
5. **IVs must be random:** Different IV for each AES-256-GCM encryption
6. **ECIES ephemeral keys are one-time:** Generate fresh for each encryption
7. **Public keys are safe to share:** They prove ownership but don't reveal secrets

---
