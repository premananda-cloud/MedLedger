# MedLedger

**Zero-knowledge medical record sharing. We store what we cannot read.**

MedLedger is a sharing conduit for medical records, not a vault. Files are encrypted client-side before they ever reach the server; the server stores only ciphertext it is mathematically unable to decrypt, for a bounded time, then deletes it. No plaintext record, private key, or data-encryption key ever touches the backend.

![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-async-336791?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Flyway](https://img.shields.io/badge/migrations-Flyway-CC0200?logo=flyway&logoColor=white)
![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)
![Status](https://img.shields.io/badge/status-hackathon%20submission-A6192E)

---

## Live API

The backend is deployed and reachable at:

```
https://medledger-bg04.onrender.com
```

Interactive API docs (Swagger UI) are available at `/docs` on that base URL. This deployment covers the API only — the frontend is designed (see `FONTEND/frontend/`) and integration is in progress; it is not yet deployed.

---

## Why MedLedger

Most "secure" file-sharing tools ask you to trust the provider. MedLedger is built so that trust is unnecessary:

- **Two independent layers.** Layer 1 (account) is a conventional email/password/TOTP gate that keeps the system usable. Layer 2 (vault) is an Ed25519/X25519 keypair generated in your browser and never transmitted. Losing Layer 1 is recoverable. Losing Layer 2 is not, by design — because if we could recover it, we'd be a key-escrow service.
- **Structural, not promised, confidentiality.** A database breach, a subpoena, or a fully compromised server yields only public keys, password hashes, and ciphertext — nothing decryptable, because the keys needed to decrypt it were never on our infrastructure.
- **Ephemeral by default.** Shares expire (30-day default, 90-day maximum), can be set to delete on download, and nothing is designed to accumulate.

Full design rationale is in [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md); the formal threat model is in [`docs/02-SECURITY_SPEC.md`](docs/02-SECURITY_SPEC.md).

---

## Architecture at a Glance

```
┌─────────────────────────┐         ┌──────────────────────────┐
│         BROWSER          │         │           SERVER          │
│                          │         │                          │
│  Layer 2 — Vault         │         │  Layer 1 — Gate           │
│  Ed25519 / X25519        │         │  Auth, PoW, TOTP,         │
│  keypair, generated      │         │  rate limiting, JWT       │
│  locally, never sent     │         │                          │
│         │                │         │         │                │
│  libsodium.js            │  HTTPS  │  FastAPI + asyncpg        │
│  encrypt / sign / seal   │◄──────► │  stores only:             │
│         │                │         │   - public keys           │
│  plaintext record        │         │   - ciphertext             │
│  never leaves device     │         │   - sealed DEK bundles     │
└─────────────────────────┘         │   - audit log              │
                                     └──────────────────────────┘
                                                 │
                                          ┌──────────────┐
                                          │  PostgreSQL   │
                                          │  (Flyway-     │
                                          │   migrated)   │
                                          └──────────────┘
```

The server never holds a key capable of decrypting a record. See [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) for the full data-flow diagrams and [`docs/04-CRYPTO_SPEC.md`](docs/04-CRYPTO_SPEC.md) for the exact cryptographic primitives.

---

## Quick Start (Docker)

The fastest way to run the full stack — API and database — is Docker Compose.

**Requirements:** Docker and Docker Compose installed.

```bash
git clone <repository-url>
cd medledger

# Copy the Docker environment template and fill in real values
cp .env.docker.example .env.docker

# Build and start the API and database containers
docker compose up --build
```

The API will be available at `http://localhost:8000`, with interactive docs at `http://localhost:8000/docs`. The database container is reachable inside the Docker network as `db`; `.env.docker` should point `DB_HOST` there, not at `localhost`.

**Environment variables (`.env.docker`):**

| Variable | Purpose | Notes |
|---|---|---|
| `DB_HOST` | Postgres hostname | `db` inside Docker Compose |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD` | Postgres credentials | Set your own — do not reuse the values in version control |
| `JWT_SECRET` | Signs access tokens | Generate a fresh 32+ byte random secret per environment |
| `JWT_ALGORITHM` | Token signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token TTL | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token TTL | `7` |
| `CORS_ORIGINS` | Allowed frontend origins | JSON array, e.g. `["http://localhost:5173"]` |
| `COOKIE_SECURE`, `COOKIE_SAMESITE`, `COOKIE_DOMAIN` | Cookie hardening flags | See `docs/03-AUTH_SPEC.md` §9 for the planned cookie migration |
| `PORT`, `HOST`, `DEBUG` | Server bind settings | `8000`, `0.0.0.0`, `true` for local dev |

Run database migrations with Flyway against the same database once the container is up:

```bash
flyway -configFiles=flyway.conf migrate
```

`flyway.conf` targets `sql/`, which contains versioned migrations `V1` through `V6`. Update the `flyway.url` port in `flyway.conf` to match whatever host port Docker Compose maps the `db` service to, if it differs from the default.

---

## Manual Setup (Without Docker)

**Requirements:** Python 3.11, PostgreSQL 14+, `pip`.

```bash
git clone <repository-url>
cd medledger

python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — set DATABASE_URL, JWT_SECRET, and CORS_ORIGINS for your local setup

# Run migrations
flyway -configFiles=flyway.conf migrate

# Start the API
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

`config.py` loads settings via `pydantic-settings` from `.env` in the project root — see that file for the full list of recognized variables and their defaults.

---

## Tech Stack

| Layer | Technology |
|---|---|
| API framework | FastAPI, Uvicorn (with `uvloop`) |
| Database | PostgreSQL, accessed via SQLAlchemy 2.0 (async) and `asyncpg` |
| Migrations | Flyway |
| Authentication | JWT (`PyJWT`), Argon2id password hashing (`argon2-cffi`), TOTP (`pyotp`, QR via `qrcode`) |
| Client-side cryptography | libsodium.js — Ed25519 signing, X25519 key exchange, XSalsa20-Poly1305 |
| Validation | Pydantic v2 |
| Testing | pytest, pytest-asyncio, pytest-cov, pytest-mock |
| Containerization | Docker, Docker Compose |
| Deployment | Render (API) |

Full dependency list: [`requirements.txt`](requirements.txt).

---

## API Overview

All request/response bodies are JSON; protected routes require `Authorization: Bearer <access_token>`.

| Area | Endpoints |
|---|---|
| Proof of Work | `POST /auth/pow/challenge`, `POST /auth/pow/verify` |
| Registration & verification | `POST /auth/register`, `POST /auth/verify-email`, `POST /auth/resend-verification` |
| Login | `POST /auth/login`, `POST /auth/verify-totp-login` |
| Tokens | `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all` |
| Password | `POST /auth/change-password`, `POST /auth/request-password-reset`, `POST /auth/confirm-password-reset` |
| Two-factor | `POST /auth/totp/setup`, `POST /auth/totp/confirm`, `POST /auth/totp/disable` |
| Profile | `GET /auth/me` |
| Keys | `GET /keys/my`, `GET /keys/{user_id_hex}`, `GET /keys/{user_id_hex}/exchange`, `GET /keys/{user_id_hex}/signing`, `PUT /keys/update` |

Full request/response schemas and the recommended frontend call sequence: [`docs/06-API_REFERENCE.md`](docs/06-API_REFERENCE.md). Live interactive docs: `/docs` on the deployed API.

---

## Project Structure

```
.
├── config.py               Application settings (pydantic-settings)
├── docker-compose.yml       API + database container orchestration
├── Dockerfile               API container build
├── flyway.conf              Database migration configuration
├── main.py                  FastAPI application entry point
├── requirements.txt
├── docs/                    Architecture, security, auth, crypto, and API specs
├── FONTEND/frontend/         Frontend screen designs (HTML + mockups), integration in progress
├── sql/                     Flyway migrations (V1–V6)
└── src/
    ├── auth/                Password, PoW, TOTP, email verification, tokens
    ├── database/             Repository layer, exceptions
    ├── middleware/           JWT auth middleware
    ├── models/               Pydantic schemas
    ├── routes/               auth, keys, vault, grants, shares
    ├── services/             auth, key, grant, relay, audit services
    └── tests/                Unit and integration tests (112 files)
```

---

## Security Posture

MedLedger's threat model (full detail in [`docs/02-SECURITY_SPEC.md`](docs/02-SECURITY_SPEC.md)) is written against named attacker scenarios rather than general claims. Summary for the two most severe:

| Scenario | Attacker gains | Attacker cannot |
|---|---|---|
| **Database breach** | Password hashes, public key hashes, ciphertext, sealed DEK bundles, anonymized audit log | Decrypt any medical record; derive private keys from public keys; forge a share; impersonate a user |
| **Full server compromise** | Everything above, plus code execution and traffic interception | Decrypt past or future uploads (encryption happens in the browser); forge a valid share (signing happens in the browser) |

This is a structural guarantee: the server is never in possession of a key capable of decrypting a record, so there is nothing to compel, leak, or misuse on that front. Non-negotiable design invariants are listed in full in the security spec, §10.

---

## Testing

```bash
pytest
```

Coverage report:

```bash
pytest --cov=src --cov-report=term-missing
```

The suite covers authentication (`test_auth/`), the database and repository layer (`test_database/`), middleware (`test_middleware/`), and the service layer (`test_services/`), including dedicated coverage for password handling, proof-of-work, TOTP, rate limiting, and token lifecycle.

---

## Status

| Component | Status |
|---|---|
| Cryptographic core (keyset, sealed boxes, signing) | Complete |
| Authentication API (register, login, TOTP, password reset, tokens) | Complete, deployed |
| Vault / grant / share API | In progress |
| Docker Compose environment | Complete |
| Frontend | Screens designed, integration in progress |
| HttpOnly cookie migration | Planned (see `docs/03-AUTH_SPEC.md` §9) |

---

## Documentation

| Document | Covers |
|---|---|
| [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md) | Why MedLedger is designed the way it is |
| [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | System architecture and data flow |
| [`docs/02-SECURITY_SPEC.md`](docs/02-SECURITY_SPEC.md) | Threat model, cryptographic specification, compliance posture |
| [`docs/03-AUTH_SPEC.md`](docs/03-AUTH_SPEC.md) | Authentication implementation, current vs. planned |
| [`docs/04-CRYPTO_SPEC.md`](docs/04-CRYPTO_SPEC.md) | Cryptographic primitives and parameters |
| [`docs/05-KEYSET_MANAGER.md`](docs/05-KEYSET_MANAGER.md) | Client-side key management code guide |
| [`docs/06-API_REFERENCE.md`](docs/06-API_REFERENCE.md) | Full endpoint reference |
| [`docs/MODULES.md`](docs/MODULES.md) | Module-by-module code map |

---

## License

Hackathon submission — Hack4Humanity 2026, JCTS Cyber Security track. License to be finalized.

## Team

Team Praxis
