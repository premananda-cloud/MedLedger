# CypherAegis / MedLedger

Patient-controlled healthcare data vault with P-256 cryptography.

## Setup

```bash
pip install -r requirements.txt
```

## Run server

```bash
uvicorn main:app --reload --port 8000
# Docs → http://localhost:8000/docs
```

## CLI client

```bash
# 1. Register
python client.py register --email you@example.com --password pass1234 --username you

# 2. Verify email (paste token printed by register)
python client.py verify --token <token>

# 3. Login
python client.py login --email you@example.com --password pass1234

# 4. Upload a file
python client.py upload --file ./report.pdf

# 5. Download it back
python client.py download --record-id <uuid> --out ./out.pdf

# 6. Grant another user access (need their public_key_hex)
python client.py grant --record-id <uuid> --grantee-key <hex> --hours 48

# 7. See what you've granted
python client.py perms

# 8. See what you've received
python client.py inbox

# 9. Revoke a grant
python client.py revoke --grant-id <uuid>

# 10. Rotate your keypair
python client.py rotate-key
```

## File layout

```
main.py                  FastAPI app entrypoint
client.py                CLI client
requirements.txt
src/
  config.py              (deleted — canonical config is src/database/config.json)
  services/
    config.py            AppConfig loader → reads src/database/config.json
    store.py             User store factory (routes to database/user_store)
    registration.py      Register / verify-email / login logic
    auth.py              FastAPI auth router  (/api/auth/*)
    transceiver.py       Vault operations wired to VaultStore
    json_store.py        Legacy JSON store (unused by default)
  api/
    deps.py              require_auth dependency → CallerIdentity
    vault.py             FastAPI vault router  (/api/vault/*)
  database/
    config.json          ← canonical config (db paths, JWT, server)
    user_store.py        UserStore  (data/users.json)
    vault_store.py       VaultStore (database/vault.json)
  schemas/
    user_schema.py       UserRecord, AuditEntry
    vault_schema.py      VaultRecord, CiphertextRecord
    grant_schema.py      Grant, VaultAuditEntry
  crypto/
    key_manager.py       P-256 keygen, encrypt/decrypt backup
    ecies.py             ECIES encrypt/decrypt, AES-GCM helpers
    signature_verifier.py ECDSA sign/verify permissions
    secret_sharing.py
    recovery_key_manager.py
```

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/register | — | Create account |
| POST | /api/auth/verify | — | Verify email, get private key |
| POST | /api/auth/login | — | Get JWT |
| GET  | /api/auth/me | JWT | Current user profile |
| POST | /api/vault/upload | JWT | Encrypt + store file |
| POST | /api/vault/download/{id} | JWT | Decrypt + return file |
| GET  | /api/vault/records | JWT | List owned records |
| POST | /api/vault/grant | JWT | Grant access to a record |
| POST | /api/vault/revoke | JWT | Revoke a grant |
| POST | /api/vault/permissions | JWT | Outbox — grants you issued |
| POST | /api/vault/inbox | JWT | Inbox — grants you received |
| POST | /api/vault/rotate-key | JWT | Re-wrap all DEKs under new keypair |
