# MedLedger Backend Documentation

## 1. Project Overview

MedLedger is a privacy-focused file sharing and vault application with end-to-end encryption. The backend is built with **FastAPI** + **asyncpg** (async PostgreSQL) and implements:

- **Argon2id** password hashing
- **JWT** access tokens (HttpOnly cookies) + refresh token rotation
- **TOTP** 2FA for registration
- **Proof-of-Work** anti-spam for account creation
- **Encrypted shares** — ephemeral file sharing between users
- **Encrypted vault** — personal encrypted record storage with time-bound grants

---

## 2. Repository Layout

```
/home/premananda/projects/m/
├── main.py                 # FastAPI app entry point (root)
├── client.py               # Standalone test client / CLI tool
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (gitignored)
├── schema.sql              # Full PostgreSQL schema (tables, indexes, constraints)
├── init_db.sh              # DB bootstrap script
├── load_env.py             # Pre-import env loader
├── docs/                   # Additional documentation
├── UI/                     # Frontend application (separate)
├── venv/                   # Python virtual environment
└── src/
    ├── middleware/
    │   └── auth_middleware.py    # JWT cookie validation, CurrentUser dependency
    ├── models/
    │   └── schemas.py            # Pydantic v2 request/response models
    ├── routes/
    │   ├── auth.py               # Registration (PoW → Email → TOTP → Account), login, logout, refresh, /me, keys
    │   ├── shares.py             # Create, list, retrieve, revoke encrypted shares
    │   └── vault.py              # Vault records, ciphertext streaming, grants
    └── services/
        ├── auth_service.py       # Password hashing (Argon2), JWT create/decode, refresh token rotation
        ├── config.py             # Pydantic-Settings (.env → Settings)
        └── database.py           # asyncpg pool init/close, DB context manager
```

---

## 3. Architecture

### 3.1 Authentication Flow

Registration is a **5-step progressive verification**:

```
POST /api/auth/pow            → Returns challenge_id + challenge
POST /api/auth/verify-pow     → Client solves SHA-256 PoW, gets session_token
POST /api/auth/submit-email   → Sends 6-digit code (logged in dev)
POST /api/auth/verify-email   → Verifies code, returns TOTP QR + manual key
POST /api/auth/verify-totp    → Verifies TOTP token
POST /api/auth/create-account → Sets username + password (Argon2id)
POST /api/users/keys          → Uploads Ed25519/X25519 public keys
```

Login:
```
POST /api/login               → Validates password, issues access_token + refresh_token cookies
```

Session Management:
- **Access token**: JWT in HttpOnly cookie (30 min)
- **Refresh token**: Rotated on every use, SHA-256 hashed in DB, 7-day expiry
- **Logout**: Revokes access token JTI + all refresh tokens for user

### 3.2 Authorization

`auth_middleware.py` provides:
- `get_current_user` — dependency for protected routes; validates JWT, checks revocation table, verifies user is active
- `get_current_user_optional` — same but returns `None` instead of 401

### 3.3 Shares

- Ciphertext stored as `bytea` in PostgreSQL
- DEK encrypted to grantee via sealed box (`dek_bundle`)
- XSalsa20 nonce + Ed25519 signature stored with metadata
- **Short codes** for easy lookup
- **Delete-on-download** option for ephemeral shares
- Ciphertext streamed via `StreamingResponse` (no memory bloat)

### 3.4 Vault

- Owner uploads encrypted records with `record_id` (client-generated UUID)
- `vault_ciphertext` table stores actual bytes separately from metadata
- **Grants**: time-bound access to other users with re-encrypted DEK bundles
- Grant revocation sets `revoked = TRUE` without deleting history

---

## 4. Environment Setup

### 4.1 Prerequisites

- Python 3.11+
- PostgreSQL 14+ (running locally or via Docker)
- `venv` module

### 4.2 PostgreSQL Setup

Create the database and user:

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE medledger_db;
CREATE USER medledger WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE medledger_db TO medledger;
\c medledger_db
GRANT ALL ON SCHEMA public TO medledger;
```

### 4.3 Python Environment

From the project root (`~/projects/m`):

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Key dependencies (ensure these are in `requirements.txt`):
```
fastapi
uvicorn[standard]
asyncpg
pydantic-settings
python-jose[cryptography]
argon2-cffi
pyotp
qrcode[pil]
python-multipart
```

### 4.4 Environment Variables

Create/edit `.env` in the project root:

```bash
# Database
DATABASE_URL=postgresql://medledger:your_secure_password@localhost:5432/medledger_db

# JWT (generate a 64+ byte random string for production)
JWT_SECRET=dev_secret_change_in_production_32bytes_min
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Cookies
COOKIE_SECURE=false          # true when serving over HTTPS
COOKIE_SAMESITE=lax
COOKIE_DOMAIN=localhost

# CORS (add your frontend origin)
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000"]

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=true
```

> **Security note**: Never commit `.env`. The repo already has it in `.gitignore`.

---

## 5. Database Initialization

### 5.1 Run Schema

```bash
cd ~/projects/m
source venv/bin/activate

# Option A: via psql directly
psql -U medledger -d medledger_db -f schema.sql

# Option B: via the provided script
chmod +x init_db.sh
./init_db.sh
```

`schema.sql` should define:
- `users` (with `user_id_hex`, `public_key_hash`, `signing_public_key`, `exchange_public_key`)
- `refresh_tokens` (with `token_hash`, `family_id`, `revoked_at`, `replaced_by_token_hash`)
- `token_revocations` (blacklist for access token JTIs)
- `active_shares` + `audit_log`
- `vault_records` + `vault_ciphertext` + `grants`
- `user_audit`

### 5.2 Verify Connection

```bash
python3 -c "
import asyncio
from src.services.database import init_pool, close_pool, get_pool
from src.services.config import get_settings

async def test():
    await init_pool()
    pool = get_pool()
    async with pool.acquire() as conn:
        val = await conn.fetchval('SELECT 1')
        print('DB connected:', val)
    await close_pool()

asyncio.run(test())
"
```

---

## 6. Running the Application

### 6.1 Development Mode

```bash
cd ~/projects/m
source venv/bin/activate

# If main.py uses uvicorn directly
python3 main.py

# Or explicitly
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

With `--reload`, FastAPI auto-restarts on code changes.

### 6.2 Production Mode

```bash
# Use a proper ASGI server with workers
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

# Or behind Gunicorn + Uvicorn workers
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### 6.3 Verify It’s Running

```bash
curl http://localhost:8000/api/auth/pow -X POST -H "Content-Type: application/json" -d '{}'
# Should return challenge_id, challenge, difficulty
```

Visit `http://localhost:8000/docs` for interactive Swagger UI.

---

## 7. API Route Map

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/pow` | No | Get PoW challenge |
| POST | `/api/auth/verify-pow` | No | Verify PoW, start session |
| POST | `/api/auth/submit-email` | No | Submit email for code |
| POST | `/api/auth/verify-email` | No | Verify email code |
| POST | `/api/auth/verify-totp` | No | Verify TOTP |
| POST | `/api/auth/create-account` | No | Finalize registration |
| POST | `/api/login` | No | Password login (sets cookies) |
| POST | `/api/auth/logout` | Yes | Revoke tokens & clear cookies |
| POST | `/api/auth/refresh` | Cookie | Rotate refresh token |
| GET | `/api/me` | Yes | Current user profile |
| POST | `/api/users/keys` | Yes | Upload public keys |
| GET | `/api/users/{username}/keys` | Yes | Fetch user public keys |
| GET | `/api/users/search` | Yes | Search recipients by username |
| POST | `/api/shares` | Yes | Create encrypted share |
| GET | `/api/shares/sent` | Yes | List sent shares |
| GET | `/api/shares/received` | Yes | List received shares |
| GET | `/api/shares/{share_id}` | Yes | Share metadata + DEK bundle |
| GET | `/api/shares/{share_id}/ciphertext` | Yes | Stream ciphertext |
| DELETE | `/api/shares/{share_id}` | Yes | Revoke share |
| GET | `/api/shares/code/{code}` | Yes | Resolve short code |
| POST | `/api/vault/records` | Yes | Upload vault record |
| GET | `/api/vault/records` | Yes | List my records |
| GET | `/api/vault/records/{id}` | Yes | Record metadata |
| GET | `/api/vault/records/{id}/ciphertext` | Yes | Stream ciphertext |
| DELETE | `/api/vault/records/{id}` | Yes | Delete record |
| POST | `/api/vault/grants` | Yes | Create time-bound grant |
| GET | `/api/vault/grants/{record_id}` | Yes | List grants |
| DELETE | `/api/vault/grants/{grant_id}` | Yes | Revoke grant |

---

## 8. Security Checklist

Before deploying:

- [ ] Change `JWT_SECRET` to a cryptographically random 64+ byte string
- [ ] Set `COOKIE_SECURE=true` (HTTPS only)
- [ ] Restrict `CORS_ORIGINS` to exact production frontend URLs
- [ ] Run PostgreSQL with SSL/TLS in production
- [ ] Enable `init_pool()` SSL if needed: `ssl="require"` in `asyncpg.create_pool()`
- [ ] Review `POW_DIFFICULTY` — increase to 5+ for production
- [ ] Add rate limiting (SlowAPI or nginx) on `/api/login` and `/api/auth/*`
- [ ] Ensure `schema.sql` has proper indexes on `user_id_hex`, `token_hash`, `short_code`
- [ ] Rotate database credentials and restrict DB user privileges

---

## 9. Common Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: src.services.config` | Running from wrong directory | Always run from `~/projects/m` (root), not `src/` |
| `RuntimeError: Database pool not initialised` | `init_pool()` not called | Ensure `main.py` calls `init_pool()` on startup |
| JWT 401 after restart | Token valid but `token_revocations` table missing | Run `schema.sql` fully; table must exist |
| CORS errors from frontend | Origin not in `CORS_ORIGINS` | Add `http://localhost:5173` (or your UI port) to `.env` |
| `argon2` install fails | Missing C compiler / libffi | `sudo apt install build-essential libffi-dev` |
| Email codes not received | Dev mode logs only | Check console logs; production needs SMTP integration |

---

## 10. Development Workflow

1. **Start Postgres**: `sudo systemctl start postgresql`
2. **Activate venv**: `source venv/bin/activate`
3. **Run backend**: `uvicorn main:app --reload --port 8000`
4. **Start UI**: `cd UI && npm run dev` (or equivalent)
5. **Test API**: Use Swagger at `http://localhost:8000/docs` or `client.py`

---

*Generated for MedLedger backend (`m/src`).*
