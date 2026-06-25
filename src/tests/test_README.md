# MedLedger Test Suite

240 tests across all layers. All pass against the source in `src/`.

## Quick start

```bash
# Install dependencies
pip install pytest pytest-asyncio aiosqlite sqlalchemy[asyncio] httpx \
            pyotp PyJWT disposable-email-domains pydantic pydantic-settings \
            fastapi uvicorn wholemail

# Run everything
PYTHONPATH=src pytest tests/

# Run a specific layer
PYTHONPATH=src pytest tests/test_auth/        # 85 pure unit tests
PYTHONPATH=src pytest tests/test_database/    # 91 SQLite integration tests
PYTHONPATH=src pytest tests/test_services/    # 49 service unit tests (mocked)
PYTHONPATH=src pytest tests/test_middleware/  # 15 middleware tests
```

## Layer map

| Directory | Strategy | Dependencies | Count |
|---|---|---|---|
| `test_auth/` | Pure unit tests | None (no mocks) | 85 |
| `test_database/` | Integration, SQLite in-memory | `aiosqlite` | 91 |
| `test_services/` | Unit tests | Mocked DB + auth modules | 49 |
| `test_middleware/` | Unit + integration | `FastAPI TestClient` | 15 |

## File layout

```
tests/
├── conftest.py                        # Shared fixtures, SQLite DDL, mocks
├── test_auth/
│   ├── test_password.py               # PasswordModule: hashing, verify, strength
│   ├── test_totp.py                   # TOTPModule: secrets, codes, backup codes
│   ├── test_pow.py                    # POWModule: challenge generation, verify
│   └── test_email_verification.py     # EmailVerification: validate, generate, verify
├── test_database/
│   ├── test_users.py                  # CRUD + soft delete + pagination
│   ├── test_tokens.py                 # Refresh tokens + JTI revocations
│   ├── test_pow.py                    # PoW challenge storage
│   ├── test_rate_limit.py             # Upsert, block, reset
│   ├── test_vault.py                  # Vault records + ciphertext
│   ├── test_grants.py                 # Grant lifecycle + revocation
│   └── test_audit.py                  # audit_log + vault_audit
├── test_services/
│   ├── test_auth_service.py           # Register, login, refresh, logout, password
│   ├── test_key_service.py            # Store, fetch, update public keys
│   ├── test_relay_service.py          # Share request, payload relay, reject
│   └── test_grant_service.py          # Create, revoke, check_access, list
└── test_middleware/
    └── test_auth_middleware.py        # JWT verify, JTI revoke, public paths
```

## Key design notes

### SQLite compatibility shim
The production repo targets PostgreSQL (JSONB, `RETURNING *`, boolean columns).
`conftest.py` wraps `AsyncSession` with `_SQLiteCompatSession` which auto-serializes
`dict`/`list` values to JSON strings before executing. All DDL uses SQLite-compatible
types.

### Test isolation
Database tests use a session-scoped engine (schema created once) and a
function-scoped session that rolls back after each test — so tests never
depend on execution order.

### Auth module tests need no mocks
`auth/` modules are pure functions with zero I/O. Every test in `test_auth/`
constructs a real module instance and calls it directly.

### Service tests use AsyncMock
`test_services/` tests mock `DatabaseRepository` and `AuditService` as
`AsyncMock` objects, leaving the service's orchestration logic as the
only thing under test.
