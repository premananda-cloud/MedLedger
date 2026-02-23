# MedLedger

**Patient-controlled healthcare data. Enforced by cryptography, not policy.**

> 📹 **Presentation Video:** [Watch on Google Drive](https://drive.google.com/drive/folders/1E2nfH2up5BBV9a7kZd_50SgWbdqm3JKW?usp=sharing)

---

## The Problem

58% of healthcare data breaches involve insiders — someone with legitimate system access who shouldn't have been there, or shouldn't have stayed that long. The audit log that would prove it? An admin can delete it. The access control that would have stopped it? An admin can override it.

Current healthcare systems are built on trust: trust that the admin won't look, trust that the log won't be touched, trust that policy will hold. That's not a security model. That's an assumption.

---

## What MedLedger Does

MedLedger replaces trust with math.

When a patient registers, the app generates a P-256 EC keypair **locally on their device**. The private key never leaves. When a doctor needs access to a record, the patient grants it with a **cryptographic signature** specifying exactly who, what, and for how long. The server verifies the signature on every access. If the signature isn't there, access is denied — not by a policy rule someone could override, but by math.

**The core guarantee:** a database administrator with full server access still cannot read a patient's record without the patient's private key.

---

## Two Ways to Run

### 1. Clone the Repo (Development / Demo)

Run both the FastAPI server and the Python client on the same machine.

```bash
# Server
pip install -r requirements.txt
uvicorn src.api.main:app --reload --port 8000

# Client (separate terminal)
cd medledger-client
pip install -r requirements.txt
python main.py

# API docs
http://localhost:8000/docs
```

Or use the demo script:
```bash
bash run_demo.sh
```

### 2. Download the App (End Users)

When the server is deployed, users just download and run `MedLedger.exe`. No Python install required. The app connects to the hosted server automatically.

**Build the Windows executable:**
```bash
cd medledger-client
build.bat
# Output: dist/MedLedger.exe
```

To point the app at your server, set `SERVER_URL` in `config.py` before building, or set the `MEDLEDGER_SERVER` environment variable at runtime.

---

## How It Works

```
Registration
  → P-256 keypair generated locally on the client
  → Public key sent to server, private key saved to keys/<user_id>.pem
  → Private key never touches the server

Upload a record
  → File hashed (SHA-256) and signed (ECDSA) with patient's private key
  → Random DEK generated, file encrypted with AES-256-GCM
  → DEK wrapped with patient's public key (ECIES)
  → Server receives only ciphertext — cannot decrypt

Grant doctor access
  → Patient fetches doctor's public key from server
  → Patient decrypts DEK with own private key, re-encrypts for doctor (ECIES)
  → Patient signs a permission payload: doctor ID + record ID + time window
  → Server stores the doctor's DEK bundle and the patient's signature

Doctor views record
  → Server verifies: permission exists, not revoked, in time window, signature valid
  → Doctor receives encrypted file + doctor's DEK bundle
  → Doctor decrypts DEK with their private key, decrypts file

Revocation
  → Patient revokes; server nulls the doctor's DEK bundle instantly
  → Doctor's next access attempt is denied — the DEK is gone
```

---

## Architecture

The client app uses an **Orchestrator** pattern: the UI talks only to the Orchestrator, which handles all routing and crypto. If the server is unreachable, it falls back automatically to **OfflineClient** — files are still encrypted and queued locally.

```
UI (tkinter screens)
        │
        ▼
  Orchestrator (core/orchestrator.py)
  ├── online  → APIClient  → HTTP → FastAPI server
  └── offline → OfflineClient → local encrypted store
```

---

## Security Model

| Threat | How MedLedger Handles It |
|---|---|
| Admin views record without authorisation | Impossible — no patient signature, no access |
| Admin deletes audit log | Impossible — append-only, no delete endpoint |
| Doctor retains access after revocation | Server nulls doctor DEK instantly |
| Database breach exposes records | AES-256-GCM ciphertext; DEKs ECIES-encrypted; neither decryptable without private key |
| Expired permission replayed | valid_from/valid_until checked on every access |
| Patient loses private key | Shamir 3-of-5 secret sharing (any 3 of 5 trustees reconstruct the key) |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) · SQLAlchemy · SQLite / PostgreSQL |
| Desktop Client | Python · tkinter · requests |
| Build (Windows) | PyInstaller via `build.bat` → single `MedLedger.exe` |
| Cryptography | P-256 ECDSA · ECIES (ECDH + HKDF-SHA256 + AES-256-GCM) · Shamir Secret Sharing |
| Audit Trail | Hash-chained AuditLog table (append-only) |

---

## Project Structure

```
├── src/                        # FastAPI server
│   ├── api/routes/             # auth, records, permissions
│   ├── crypto/                 # ECIES, signatures, Shamir sharing
│   ├── database/               # SQLAlchemy models
│   └── services/               # Business logic (registration, records, permissions)
│
├── medledger-client/           # Python desktop app
│   ├── main.py                 # Entry point
│   ├── config.py               # SERVER_URL and constants
│   ├── build.bat               # Windows build (PyInstaller)
│   ├── core/
│   │   ├── crypto.py           # All crypto operations
│   │   ├── keystore.py         # .pem and session.json management
│   │   └── orchestrator.py     # Central logic layer
│   ├── client/
│   │   ├── api_client.py       # HTTP client (requests)
│   │   └── offline_client.py   # Offline fallback
│   └── ui/screens/             # tkinter UI screens
│
├── docs/                       # Presentation materials and guides
├── requirements.txt
└── run_demo.sh
```

---

## Presentation Materials

All judge-facing documents are in [`docs/presentation/`](docs/presentation/):

- [`MedLedger_Proposal.pdf`](docs/presentation/MedLedger_Proposal.pdf) — project proposal
- [`MedLedger_Technical_Report.docx`](docs/presentation/MedLedger_Technical_Report.docx) — full technical writeup
- [`Problem_Statement.pdf`](docs/presentation/Problem_Statement.pdf) — problem framing and statistics
- [`Proposed_Solution.pdf`](docs/presentation/Proposed_Solution.pdf) — solution design
- [`medledger_architecture.html`](docs/presentation/medledger_architecture.html) — interactive architecture diagram

---

## Team — Praxis

| Name | Role |
|---|---|
| Mayanglambam Premananda | Blockchain Architecture · Backend |
| Korounganba Thokchom | Frontend · Healthcare Domain |
| Thajaba Naoroibam | Frontend · Healthcare Domain |

---

*"Cryptography doesn't have insider threats. Math doesn't take bribes."*
