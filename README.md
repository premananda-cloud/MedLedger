# MedLedger

**Patient-controlled healthcare data. Enforced by cryptography, not policy.**

> *"Cryptography doesn't have insider threats. Math doesn't take bribes."*

---
> 📹 **[Watch the demo video](https://drive.google.com/file/d/1dNzt7CWriF2SZSG9TrRjf6icgA_1NobG/view?usp=sharing)**

## The Problem

58% of healthcare data breaches involve insiders — staff with legitimate system access who shouldn't have been there, or shouldn't have stayed that long. In every traditional hospital system, an administrator can override access controls. The audit log that would prove it? An admin can delete it too.

Current healthcare IT is built on trust: trust that the admin won't look, trust that the policy will hold, trust that the log won't be touched. That's not a security model. That's an assumption.

---

## What MedLedger Does

MedLedger replaces trust with math.

When a patient registers, the app generates a P-256 EC keypair **locally on their device**. The private key never leaves. When a doctor needs access to a record, the patient grants it with a **cryptographic signature** — specifying exactly who, what record, and for how long. The server verifies that signature on every access attempt. No signature, no access — not because of a policy rule that an admin could override, but because of mathematics.

**The core guarantee:** a database administrator with full server access still cannot read a patient's record without the patient's private key.

---

## ⚡ Quickstart — Run the Demo (2 minutes)

The fastest way to see MedLedger is the self-contained single-file demo. It requires no server, no database, and no configuration. Everything — crypto, UI, the full patient-to-doctor flow — runs in one Python script.

### Prerequisites

```bash
pip install cryptography
```

That's the only dependency. `tkinter` ships with standard Python on Windows, macOS, and most Linux distros.

### Run it

```bash
python medledger_demo.py
```

### Demo walkthrough

**Step 1 — Register a patient**
- Click **Create account**
- Enter any name, email, and password
- Select **Patient**
- Watch the animated key generation — a real P-256 keypair is generated live using `cryptography.hazmat`

**Step 2 — Register a doctor** *(open a second account in the same session)*
- Log out, click **Create account** again
- Enter different credentials
- Select **Doctor**

**Step 3 — Log in as the patient**
- Go to **Upload Record**
- Click **✨ Generate Demo PDF** to create a fake lab report instantly — or browse to any real file
- Watch the 6-step encryption pipeline animate:
  1. SHA-256 hash of the file
  2. ECDSA-P256 signature with your private key
  3. Random 256-bit DEK generated
  4. AES-256-GCM file encryption
  5. ECIES DEK wrapping with your public key
  6. Encrypted blob stored
- Go to **My Records** → select the record → **Grant Doctor Access**
- Pick the doctor's email from the dropdown
- Watch the 5-step ECIES key-rewrap animate — the DEK is decrypted with your key and re-encrypted for the doctor

**Step 4 — Log in as the doctor**
- See the granted record in the patient list
- Click **Decrypt & View**
- Watch the 5-step decryption animate
- The actual plaintext appears in the viewer — content verified, integrity confirmed

> **What's real:** The encryption is genuine AES-256-GCM. The key wrapping is genuine ECIES over P-256. The signatures are genuine ECDSA. The demo uses the exact same `cryptography` library primitives as the full server-backed system.

---

## Full System (Server + Desktop Client)

For the complete backend + client architecture:

```bash
# Terminal 1 — FastAPI server
pip install -r requirements.txt
uvicorn src.api.main:app --reload --port 8000

# Terminal 2 — Desktop client
cd medledger-client
pip install -r requirements.txt
python main.py

# API docs / Swagger UI
# http://localhost:8000/docs
```

Or use the convenience script:

```bash
bash run_demo.sh
```

---

## How the Cryptography Works

```
REGISTRATION
  → P-256 keypair generated locally on client device
  → Public key registered with server; private key stays on device
  → Private key never transmitted

UPLOAD A RECORD
  → File hashed (SHA-256), hash signed (ECDSA-P256) with patient's private key
  → Random 256-bit DEK generated; file encrypted with AES-256-GCM
  → DEK wrapped with patient's public key (ECIES: ECDH + HKDF-SHA256 + AES-256-GCM)
  → Server stores only ciphertext — it cannot decrypt

GRANT DOCTOR ACCESS
  → Patient decrypts DEK with own private key
  → Patient re-encrypts DEK for doctor's public key (ECIES rewrap)
  → Patient signs a permission payload: { doctor_id, record_id, valid_from, valid_until }
  → Server stores doctor's DEK bundle + patient's ECDSA signature

DOCTOR VIEWS RECORD
  → Server verifies: permission exists, not revoked, within time window, signature valid
  → Doctor receives encrypted file + their DEK bundle
  → Doctor decrypts DEK with their private key, decrypts file

REVOCATION
  → Patient revokes; server clears the doctor's DEK bundle immediately
  → Doctor's next request is denied — the key is gone, not just flagged
```

**Why the admin can't cheat:** Every permission is cryptographically bound to a specific patient, doctor, record, and time window by the patient's ECDSA signature. Even if an admin inserts a fake permission row into the database, signature verification will fail — they don't have the patient's private key, so they can't produce a valid signature. The access is denied by arithmetic, not by access controls.

---

## Security Model

| Threat | Defence |
|--------|---------|
| Admin accesses record without permission | No patient signature → access denied by crypto |
| Admin deletes audit log | Append-only table; no delete endpoint; hash-chained entries |
| Admin inserts fake permission into database | Signature verification fails — no private key, no valid signature |
| Admin modifies permission time window | Signature hash mismatch → verification fails |
| Database breach | AES-256-GCM ciphertext + ECIES-wrapped keys; neither decryptable without private key |
| Expired permission replayed | `valid_from`/`valid_until` verified on every access |
| Doctor retains access after revocation | Doctor's DEK bundle cleared server-side; decryption is impossible |
| Patient loses private key | Shamir 3-of-5 secret sharing — any 3 of 5 chosen trustees reconstruct the key |
| Compromised doctor account | Still requires patient signature; doctor credentials alone give nothing |

---

## What the Tests Show

The full crypto and permission logic is covered by 26 integration checks in `test_medledger.py` — all passing as of the submission date.

Key things verified:

- ECDSA signatures of valid DER lengths 68–72 bytes all verify correctly (regression on an edge-case bug fix)
- Tampered permission payloads are rejected
- Wrong public key is rejected
- ECIES DEK wrapping and unwrapping round-trip correctly
- Wrong private key for decryption raises `ValueError` (GCM auth tag working)
- AES-256-GCM tampered ciphertext is rejected
- Full grant → verify → revoke flow without a database or API server
- A valid permission for record A cannot be replayed to access record B

Full annotated output: [`docs/eval_and_self_analysis/TEST_RESULTS.md`](docs/eval_and_self_analysis/TEST_RESULTS.md)

---

## Architecture

The production client uses an **Orchestrator** pattern — the UI never touches crypto directly, and if the server is unreachable the app falls back to an encrypted local queue automatically.

```
UI (tkinter screens)
        │
        ▼
  Orchestrator (core/orchestrator.py)
  ├── online  → APIClient → HTTP → FastAPI server
  └── offline → OfflineClient → local encrypted store
```

The server is a layered FastAPI application:

```
FastAPI routes (src/api/routes/)
        │
        ▼
Service layer (src/services/)      ← business logic, no HTTP concerns
        │
        ▼
Crypto layer (src/crypto/)         ← ECDSA, ECIES, Shamir — no DB concerns
        │
        ▼
SQLAlchemy ORM (src/database/)     ← SQLite dev / PostgreSQL prod
```

---

## Project Structure

```
├── medledger_demo.py           ← Self-contained demo (start here)
│
├── src/                        ← FastAPI server
│   ├── api/routes/             ← auth, records, permissions
│   ├── crypto/                 ← ECIES, ECDSA, Shamir secret sharing
│   ├── database/               ← SQLAlchemy models
│   └── services/               ← Registration, records, permissions logic
│
├── medledger-client/           ← Python desktop app
│   ├── main.py
│   ├── core/
│   │   ├── crypto.py           ← All crypto operations (P-256, AES-GCM, ECIES)
│   │   ├── keystore.py         ← Local key + session storage (SQLite)
│   │   └── orchestrator.py     ← Central logic; routes to online/offline
│   ├── client/
│   │   ├── api_client.py       ← HTTP client
│   │   └── offline_client.py   ← Offline fallback
│   └── ui/screens/             ← tkinter screens
│
├── docs/
│   ├── presentation/           ← Judge-facing materials
│   │   ├── SECURITY.md         ← Honest security analysis and threat model
│   │   ├── MedLedger_Technical_Documentation.docx
│   │   ├── MedLedger_Solution.docx
│   │   └── proposal/           ← PDFs, architecture diagram
│   └── eval_and_self_analysis/
│       ├── CODE_REVIEW.md      ← Component-by-component grades and notes
│       ├── SYSTEM_ANALYSIS.md  ← Full architecture and data flow documentation
│       ├── TEST_RESULTS.md     ← Annotated test output (26/26 passing)
│       └── TESTING.md          ← Test strategy and what's covered
│
├── requirements.txt
└── run_demo.sh
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI · SQLAlchemy · SQLite / PostgreSQL |
| Desktop client | Python · tkinter · requests |
| Build | PyInstaller → `MedLedger.exe` (Windows) |
| Cryptography | P-256 ECDSA · ECIES (ECDH + HKDF-SHA256 + AES-256-GCM) · Shamir 3-of-5 Secret Sharing |
| Audit trail | Hash-chained append-only `AuditLog` table |

---

## Compared to Traditional EHR Systems

| Feature | Traditional EHR | MedLedger |
|---------|----------------|-----------|
| Patient controls access | No | Yes |
| Admin can override | Yes (risk) | No — blocked by math |
| Audit logs deletable | Yes (risk) | No — append-only, hash-chained |
| Time-limited access | Rarely | Yes — enforced in signature |
| Instant revocation | Rarely | Yes — DEK cleared immediately |
| Proof of authorization | Policy document | Cryptographic signature |

---

## Honest Limitations

This is a hackathon project. Before any clinical deployment it would need:

- Independent cryptographic audit of the Shamir GF-256 implementation
- Hardware-backed key storage (iOS Secure Enclave, Android Keystore, or TPM)
- Distributed consensus for the audit chain (current implementation is single-node)
- HIPAA compliance review
- Penetration testing
- HTTPS / TLS everywhere (currently HTTP in development)

Full analysis in [`docs/presentation/SECURITY.md`](docs/presentation/SECURITY.md).

---

## Presentation Materials

All judge-facing documents are in [`docs/presentation/`](docs/presentation/):

- [`SECURITY.md`](docs/presentation/SECURITY.md) — precise security properties, threat model, and honest limitations
- [`MedLedger_Solution.docx`](docs/presentation/MedLedger_Solution.docx) — solution overview
- [`MedLedger_Technical_Documentation.docx`](docs/presentation/MedLedger_Technical_Documentation.docx) — full technical writeup
- [`MedLedger_client_Reference.docx`](docs/presentation/MedLedger_client_Reference.docx) — client API reference
- [`proposal/medledger_architecture.html`](docs/presentation/proposal/medledger_architecture.html) — interactive architecture diagram
- [`proposal/MedLedger_Proposal.pdf`](docs/presentation/proposal/MedLedger_Proposal.pdf) — project proposal
- [`proposal/Problem_Statement.pdf`](docs/presentation/proposal/Problem_Statement.pdf) — problem framing and statistics

Self-evaluation and code review: [`docs/eval_and_self_analysis/`](docs/eval_and_self_analysis/)

---

## Team — Praxis

| Name | Role |
|------|------|
| Mayanglambam Premananda | Blockchain architecture · Backend · Cryptography |
| Korounganba Thokchom | Frontend · Healthcare domain |
| Thajaba Naoroibam | Frontend · Healthcare domain |

---

