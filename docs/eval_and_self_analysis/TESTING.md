# MedLedger – Testing Guide

## Overview

MedLedger's test suite validates the core security and cryptographic logic without requiring a running server, database, or network connection. All tests run against the real library code — no mocks except for the `qrcode` package (which is only used to generate a visual backup image at registration, not in any security path).

The test file is: `test_medledger.py` in the project root.

---

## Running the Tests

### Prerequisites

Only the `cryptography` package is required. Everything else (`hashlib`, `json`, `uuid`, `os`) is Python stdlib.

```bash
# From the project root, with your venv active:
pip install cryptography

python3 test_medledger.py
```

### If `qrcode` is not installed

The `KeyManager` module imports `qrcode` at the top level for its QR backup feature. If it isn't installed, stub it out before running:

```bash
python3 - << 'EOF'
import sys, types
qr = types.ModuleType("qrcode")
qr.QRCode = None
qr.constants = type("c", (), {"ERROR_CORRECT_H": None})()
sys.modules["qrcode"] = qr

exec(open("test_medledger.py").read())
EOF
```

The stub has zero effect on any security behaviour — `generate_key_qr_code()` is only called during registration to produce a PNG for the user to save offline.

---

## What Is Tested

### Section 1 – KeyManager

Validates keypair generation using ECDSA P-256 (secp256r1).

| Check | Why it matters |
|---|---|
| Patient and doctor keypairs generated | Confirms the curve and serialisation work end-to-end |
| Public keys are distinct | Sanity check — two calls must never collide |
| `get_public_key_from_private` round-trips | Used server-side to verify a private key belongs to a registered user |

---

### Section 2 – SignatureVerifier (client-side flow)

This section tests the core of the access control model: the patient signs a permission payload **on their device**, and the server verifies the signature against the patient's stored public key. The private key never travels over the network.

| Check | Why it matters |
|---|---|
| Signature produced client-side | Confirms the signing path works |
| Server verifies valid signature | The grant is only stored if this passes |
| Tampered payload rejected | Changing any field (e.g. `doctor_id`) invalidates the signature — proves the grant cannot be forged |
| Wrong public key rejected | A different user's public key cannot verify the signature |

---

### Section 3 – Signature Length Edge Cases

DER-encoded ECDSA P-256 signatures are **68–72 bytes** depending on how many leading zeros the `r` and `s` integers have. An earlier version of the code contained a hard check (`< 70 or > 72 bytes → reject`) which would silently drop valid signatures.

This section signs 50 different payloads and verifies all of them, confirming the fix holds across the full natural length distribution.

---

### Section 4 – ECIES DEK Wrapping

The Data Encryption Key (DEK) is a random 32-byte AES key generated per record. It is never stored in plaintext — it is ECIES-encrypted for the patient's public key at upload time. During a permission grant, the patient decrypts the DEK client-side and re-encrypts it for the doctor.

| Check | Why it matters |
|---|---|
| ECIES encrypt produces a valid bundle | Bundle format `{epk, iv, ct, tag}` must be correct for storage |
| Patient decrypts their own DEK | Core download flow |
| Doctor decrypts re-encrypted DEK | Core doctor-access flow |
| Wrong private key throws `ValueError` | Confirms the GCM auth tag catches key mismatches |

---

### Section 5 – AES-GCM File Encryption

Validates the symmetric encryption layer used to protect the actual file bytes on disk.

| Check | Why it matters |
|---|---|
| Encrypt + decrypt round-trip | Confirms the file survives the encryption cycle intact |
| Tampered ciphertext rejected | GCM authentication tag detects any modification to the stored file |

---

### Section 6 – Full Permission Grant → Verify Flow

End-to-end simulation of the complete access control sequence, without a database.

| Step | What happens |
|---|---|
| A | Patient builds the canonical payload and signs it locally |
| B | Server receives the signature and verifies it before persisting |
| C | Doctor requests access — time window is checked, signature re-verified |
| D | Access to a different record (simulating revocation) is correctly denied |

This is the most important section. It proves that the system works correctly even without a live API or database.

---

### Section 7 – main.py Regressions

Static checks on the fixed source files to ensure previously identified bugs do not reappear.

| Check | Bug it guards against |
|---|---|
| No duplicate `add_middleware` call | Second CORS block that re-registered hardcoded IPs |
| No hardcoded `192.168.29.239` | Local dev IP left in production CORS config |
| `create_all_tables` not imported in `main.py` | Import that broke startup (`ImportError` on boot) |
| `init_db()` used in startup handler | Correct function from `connection.py` |
| `create_all_tables` defined in `models.py` | Symbol expected by `database/__init__.py` |

---

## Known Warnings

```
DeprecationWarning: datetime.datetime.utcnow() is deprecated
```

Python 3.12 flags `utcnow()` as deprecated in favour of timezone-aware datetimes. This does not affect correctness — all timestamps are compared against each other consistently. It will be addressed in a future cleanup pass by replacing `utcnow()` with `datetime.now(timezone.utc)` throughout.

---

## What Is Not Tested Here

| Area | Reason |
|---|---|
| FastAPI route handlers | Require a running ASGI server — covered manually via `/docs` Swagger UI |
| SQLAlchemy DB persistence | Require a live DB session — tested by running the server against SQLite |
| JWT token generation/verification | Depends on `PyJWT` — tested manually via `/auth/login` |
| Frontend signing (SubtleCrypto) | Browser API — tested in the browser dev console |
| Shamir secret sharing recovery | Standalone module, not wired into the main flow yet |

These areas are candidates for a second test pass using `pytest` with `httpx` (async test client) and an in-memory SQLite fixture.
