# MedLedger Authentication Specification

**Version:** 1.0 | **Date:** June 2026 | **Status:** Draft — Aligned with 01-ARCHITECTURE.md + 02-SECURITY_SPEC.md**

**Architecture:** BFF (Backend-for-Frontend) + HttpOnly Cookies + CSRF Protection
**Primary Client:** Confidential web application (browser-based SPA)
**Data Classification:** Ephemeral encrypted shares (no PHI on server)

---

## 1. Decision: Option A — BFF + HttpOnly Cookies

### 1.1 Why This Pattern

| Requirement | How Option A Satisfies It |
|-------------|---------------------------|
| **Confidential client** | Web app is the only first-party client; no public API exposure |
| **XSS resistance** | Tokens in HttpOnly cookies — JavaScript cannot access them |
| **Zero-knowledge sharing** | Short-lived access tokens minimize window of compromise |
| **Anti-spam posture** | CAPTCHA + PoW gate registration; JWT gates all other operations |
| **Simple frontend** | No token management logic; `credentials: 'include'` only |

### 1.2 What We Rejected

| Alternative | Why Rejected |
|-------------|--------------|
| **Bearer tokens in localStorage** | XSS steals tokens instantly; unacceptable |
| **Bearer tokens in memory** | Complex refresh logic, token theft on XSS, harder to revoke |
| **Session cookies (stateful)** | Harder to scale horizontally, no built-in token rotation |
| **OAuth 2.0 PKCE for first-party** | Overkill; no third-party clients, adds redirect complexity |
| **JWT in Authorization header** | Requires custom header handling, XSS risk if leaked |
| **Email verification links** | Violates "email is anti-spam only" principle; adds recovery vector |
| **Password reset flow** | Violates "no account recovery" principle |

### 1.3 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER (SPA)                              │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────┐ │
│  │  React UI   │      │ Keyset Mgr  │      │  Web Crypto API │ │
│  │             │      │ (JS Module) │      │                 │ │
│  │ • Register  │      │ • generate()│      │ • P-256 keygen  │ │
│  │ • Login     │      │ • load()    │      │ • ECDSA sign    │ │
│  │ • Share UI  │      │ • encrypt() │      │ • ECDH / ECIES  │ │
│  │ • Inbox     │      │ • decrypt() │      │ • AES-256-GCM   │ │
│  │ • Download  │      │ • clear()   │      │ • PBKDF2        │ │
│  └──────┬──────┘      └──────┬──────┘      └─────────────────┘ │
│         │                    │                                   │
│         └────────────────────┘                                   │
│                    │                                              │
│         HTTPS + Cookies (credentials: 'include')                  │
│         + X-CSRF-Token header                                   │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────┼────────────────────────────────────────────┐
│               BFF BACKEND (FastAPI)                               │
│  ┌─────────────────┴─────────────────┐  ┌─────────────────────┐ │
│  │         Gate Router               │  │    Share Router       │ │
│  │  /api/*                           │  │  /api/share/*         │ │
│  │                                   │  │                       │ │
│  │  • POST /register  → CAPTCHA+PoW  │  │  • POST /share        │ │
│  │  • POST /login     → set cookies  │  │  • POST /:id/retrieve │ │
│  │  • POST /refresh   → rotate       │  │  • GET /outbox        │ │
│  │  • POST /logout    → revoke       │  │  • GET /inbox         │ │
│  │  • GET /me         → check state  │  │  • DELETE /:id        │ │
│  │  • DELETE /account → destroy      │  │                       │ │
│  └───────────────────────────────────┘  └─────────────────────┘ │
│         │                                    │                    │
│         └────────────────────────────────────┘                    │
│                      │                                            │
│  ┌───────────────────┴─────────────────────────────────────────┐ │
│  │  Store Layer (PostgreSQL)                                    │ │
│  │  • users (email_hash, password_hash, public_key_hash)        │ │
│  │  • active_shares (ciphertext, DEK bundle, TTL)              │ │
│  │  • refresh_tokens (token_hash, user_id, expiry, revoked)    │ │
│  │  • audit_log (immutable actions)                             │ │
│  └─────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Cookie Specification

### 2.1 Access Token Cookie

| Property | Value | Rationale |
|----------|-------|-----------|
| **Name** | `access_token` | Standard naming |
| **Value** | JWT (RS256 or ES256 signed) | Self-contained, stateless verification |
| **HttpOnly** | `true` | Prevents JavaScript access (XSS protection) |
| **Secure** | `true` | HTTPS only |
| **SameSite** | `Lax` | Sent on top-level navigation + same-site requests; blocks cross-site POSTs |
| **Max-Age** | 900 seconds (15 minutes) | Short-lived, limits compromise window |
| **Path** | `/` | Available to all API endpoints |
| **Domain** | `api.medledger.com` | Scoped to backend domain |

**Why SameSite=Lax (not Strict):** Strict would block the cookie on top-level GET navigations from external links (e.g., user clicks share URL to `app.medledger.com`). Lax allows these while still blocking cross-site POSTs.

### 2.2 Refresh Token Cookie

| Property | Value | Rationale |
|----------|-------|-----------|
| **Name** | `refresh_token` | Standard naming |
| **Value** | Opaque random string (256 bits) | Not a JWT — stored hashed in DB |
| **HttpOnly** | `true` | Prevents JavaScript access |
| **Secure** | `true` | HTTPS only |
| **SameSite** | `Strict` | Never sent on cross-site requests (even top-level) |
| **Max-Age** | 604800 seconds (7 days) | Long-lived, but rotatable and revocable |
| **Path** | `/api/refresh` | Only sent to refresh endpoint (minimizes exposure) |
| **Domain** | `api.medledger.com` | Scoped to backend domain |

**Why SameSite=Strict:** Refresh token is the most sensitive credential. Strict ensures it is never sent in any cross-site context.

**Why Path=/api/refresh:** Limits cookie exposure. The refresh token is only needed for one endpoint.

### 2.3 CSRF Token Cookie

| Property | Value | Rationale |
|----------|-------|-----------|
| **Name** | `csrf_token` | Standard naming |
| **Value** | Opaque random string (128 bits) | Readable by JavaScript |
| **HttpOnly** | `false` | JavaScript must read this to send as header |
| **Secure** | `true` | HTTPS only |
| **SameSite** | `Strict` | Prevents cross-site leakage |
| **Max-Age** | 900 seconds (matches access token) | Rotated with access token |
| **Path** | `/` | Available to all endpoints |
| **Domain** | `api.medledger.com` | Scoped to backend domain |

**Double-Submit Pattern:** Frontend reads `csrf_token` from cookie, sends as `X-CSRF-Token` header. Backend verifies header value matches cookie value. This proves the request originated from our domain.

### 2.4 Cookie Summary Table

| Cookie | HttpOnly | SameSite | Path | Lifetime | Purpose |
|--------|----------|----------|------|----------|---------|
| `access_token` | Yes | Lax | `/` | 15 min | Session identity |
| `refresh_token` | Yes | Strict | `/api/refresh` | 7 days | Session renewal |
| `csrf_token` | No | Strict | `/` | 15 min | CSRF protection |

---

## 3. Authentication Flows

### 3.1 Registration Flow (Single Step)

```
Browser → User enters email + password
       → Completes CAPTCHA (Turnstile)
       → Browser solves PoW (~1 second, background)
       → Browser calls Keyset Manager.generate(password)
           1. Web Crypto API: generateKey(ECDSA, P-256) → keypair
           2. Export private key as JWK
           3. PBKDF2: derive AES key from password + random salt (310k+ iter)
           4. AES-256-GCM: encrypt private key JWK
           5. Package: { version, public_key_hex, public_key_hash, encrypted_private_key, created_at }
       → Browser triggers download: "medledger-keyset-{timestamp}.json"
       → Browser calls POST /api/register
           Body:
           {
             "email": "alice@example.com",
             "password": "correct-horse-battery-staple",
             "public_key_hash": "sha256:abc123...",
             "encrypted_private_key_blob": { salt, iv, ciphertext, tag, pbkdf2_iterations },
             "captcha_token": "turnstile_token_123...",
             "pow_nonce": "server_provided_nonce_456...",
             "pow_solution": "found_solution_789..."
           }

Server → Validate CAPTCHA token with Turnstile
       → Validate PoW solution (SHA-256(nonce || solution) has 20 leading zero bits)
       → Check rate limits (IP: 5/day, email_domain: 20/day)
       → Hash email → email_hash (SHA-256, for lookups)
       → Check email_hash uniqueness
       → Hash password with Argon2id (memory=64MB, iterations=3, parallelism=4)
       → Create user record:
           user_id, email_hash, password_hash, public_key_hash,
           encrypted_private_key_blob, captcha_token_used, pow_nonce,
           created_at, last_login
       → Generate access_token (JWT, 15 min)
       → Generate refresh_token (opaque, 7 days, store hash in DB)
       → Generate csrf_token (opaque, 15 min)

Response: 201 Created + Set-Cookie headers
Set-Cookie: access_token=<jwt>; HttpOnly; Secure; SameSite=Lax; Max-Age=900; Path=/
Set-Cookie: refresh_token=<opaque>; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/api/refresh
Set-Cookie: csrf_token=<opaque>; Secure; SameSite=Strict; Max-Age=900; Path=/

Body:
{
  "user_id": "uuid",
  "public_key_hash": "sha256:abc123...",
  "status": "active",
  "keyset_downloaded": true  // Reminder: browser already downloaded
}

Security Notes:
• Email is NOT verified via link. It is verified syntactically and via MX check only.
• Email is used for rate limiting and anti-spam, NOT for recovery.
• The encrypted_private_key_blob is stored server-side for convenience
  (patient can re-download if they lose the file while still logged in).
  However, the server cannot decrypt it without the password.
• The browser download of the keyset file happens BEFORE the API call,
  ensuring the patient has a local copy even if registration fails.
```

### 3.2 Login Flow (Layer 1 Only)

```
POST /api/login
Content-Type: application/json

Body:
{
  "email": "alice@example.com",
  "password": "correct-horse-battery-staple"
}

Server Actions:
1. Hash email → email_hash (SHA-256)
2. Fetch user by email_hash (constant-time to prevent enumeration)
3. Argon2id verify(password, stored_hash)
4. If invalid: 401 + exponential backoff (1s, 2s, 4s, 8s, max 30s)
5. If valid:
   a. Generate access_token (JWT, 15 min)
   b. Generate refresh_token (opaque, 7 days, store hash in DB)
   c. Generate csrf_token (opaque, 15 min)
   d. Update last_login

Response: 200 OK + Set-Cookie headers
Set-Cookie: access_token=<jwt>; HttpOnly; Secure; SameSite=Lax; Max-Age=900; Path=/
Set-Cookie: refresh_token=<opaque>; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/api/refresh
Set-Cookie: csrf_token=<opaque>; Secure; SameSite=Strict; Max-Age=900; Path=/

Body:
{
  "user_id": "uuid",
  "public_key_hash": "sha256:abc123...",
  "status": "active"
}

UI State After Login:
• Dashboard shows: "Vault Locked"
• Share operations disabled
• Prompt: "Upload your keyset file to unlock"
```

### 3.3 Keyset Loading (Unlocking Layer 2 — Client-Side Only)

```
Browser → User clicks "Unlock Vault"
       → Uploads keyset file + enters password
       → Keyset Manager.load(keysetFile, password)
           1. Read JSON package
           2. PBKDF2 with stored salt → derive AES key
           3. AES-256-GCM decrypt → private key JWK
           4. Import into Web Crypto API → CryptoKey object (non-extractable)
           5. Hold in memory only
       → Keyset Manager verifies public_key_hash matches logged-in user's public_key_hash
           (from /api/me response or JWT claim)
       → If mismatch: "This keyset does not belong to this account"
       → If match: Dashboard shows "Vault Unlocked"
       → Share / download operations now available

NO SERVER CALL REQUIRED FOR KEYSET UNLOCK.
This is intentional — the server never sees the private key, password, or decrypted keyset.

UI State After Unlock:
• Dashboard shows: "Vault Unlocked"
• Share operations enabled
• Keyset Manager has private key in memory (loaded from user's file)
• Optional: "Remember for this session" → store in sessionStorage (cleared on tab close)
```

### 3.4 Session State Machine

```
                    ┌─────────────┐
                    │   LOGGED OUT │
                    └──────┬──────┘
                           │ Register or Login
                           ▼
                    ┌─────────────┐
                    │  LAYER 1 ONLY │
                    │  (JWT active) │
                    │  Vault: LOCKED
                    └──────┬──────┘
                           │ Upload Keyset + Password
                           ▼
                    ┌─────────────┐
                    │  FULLY ACTIVE │
                    │  (Layer 1 + 2) │
                    │  Vault: UNLOCKED
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ Refresh │  │ Logout  │  │ Lock    │
        │ Token   │  │         │  │ Vault   │
        └────┬────┘  └────┬────┘  └────┬────┘
             │            │            │
             ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ LAYER 1 │  │ LOGGED  │  │ LAYER 1 │
        │ ONLY    │  │ OUT     │  │ ONLY    │
        │ (new    │  │         │  │ (needs  │
        │ access  │  │         │  │ re-upload)
        │ token)  │  │         │  │         │
        └─────────┘  └─────────┘  └─────────┘
```

**State Transitions:**
- `LOGGED OUT → LAYER 1 ONLY`: Register or Login (server validates credentials, sets JWT)
- `LAYER 1 ONLY → FULLY ACTIVE`: Client-side keyset load (no server call)
- `FULLY ACTIVE → LAYER 1 ONLY`: Lock vault (client-side, clears CryptoKey memory)
- `FULLY ACTIVE → LOGGED OUT`: Logout (server revokes refresh token, clears cookies)
- `LAYER 1 ONLY → LOGGED OUT`: Logout or token expiry without refresh

### 3.5 Token Refresh Flow

```
POST /api/refresh
Cookie: refresh_token=<opaque> (auto-sent, Path=/api/refresh)
X-CSRF-Token: <csrf_from_cookie>

Server Actions:
1. Lookup refresh_token hash in DB
2. Check: not expired, not revoked, not already used
3. If used before → TOKEN REUSE DETECTED:
   a. Revoke ALL refresh tokens for this user
   b. Clear all sessions
   c. Return 403: "Session invalidated. Please log in again."
4. If valid:
   a. Mark old refresh_token as "used" in DB
   b. Generate new refresh_token (opaque, 7 days)
   c. Generate new access_token (JWT, 15 min)
   d. Generate new csrf_token (opaque, 15 min)
   e. Store new refresh_token hash in DB

Response: 200 OK + Set-Cookie headers
Set-Cookie: access_token=<new_jwt>; HttpOnly; Secure; SameSite=Lax; Max-Age=900; Path=/
Set-Cookie: refresh_token=<new_opaque>; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/api/refresh
Set-Cookie: csrf_token=<new_opaque>; Secure; SameSite=Strict; Max-Age=900; Path=/

Body:
{
  "refreshed": true
}

Frontend Behavior:
• TanStack Query intercepts 401 responses
• Automatically calls /api/refresh
• Retries original request with new cookies
• User sees no interruption
• Vault lock state is preserved (Layer 2 is client-side, unaffected by token refresh)
```

### 3.6 Logout Flow

```
POST /api/logout
Cookie: access_token=<jwt>, refresh_token=<opaque> (auto-sent)
X-CSRF-Token: <csrf_from_cookie>

Server Actions:
1. Verify access_token (extract user_id, even if expired)
2. Revoke refresh_token in DB (mark as revoked)
3. Clear all cookies (set expired):
   a. access_token: Max-Age=0
   b. refresh_token: Max-Age=0
   c. csrf_token: Max-Age=0
4. Log audit event: logout, IP, timestamp

Response: 200 OK + Clear-Cookie headers
{
  "logged_out": true
}

Client-Side Actions:
• React: clear all state (auth context, query cache)
• Keyset Manager: delete CryptoKey references, clear memory, clear sessionStorage
• Redirect to /login
```

### 3.7 Session Check Flow

```
GET /api/me
Cookie: access_token=<jwt> (auto-sent)
X-CSRF-Token: <csrf_from_cookie>

Server Actions:
1. Verify access_token (signature, expiry, not revoked)
2. Extract claims: user_id, public_key_hash, email_hash
3. If expired but refresh_token valid → auto-refresh (return new cookies)
4. If fully expired → 401 (trigger login redirect)

Response: 200 OK
{
  "user_id": "uuid",
  "public_key_hash": "sha256:abc123...",
  "email_hash": "sha256:def456...",
  "created_at": "2026-06-07T23:10:00Z",
  "last_login": "2026-06-09T10:30:00Z"
}

Note: Server does NOT know if vault is unlocked. That is client-side state only.
The frontend tracks vault lock state independently (React state + sessionStorage).
```

---

## 4. Token Specifications

### 4.1 Access Token (JWT)

```json
{
  "sub": "user_uuid",
  "public_key_hash": "sha256:abc123...",
  "email_hash": "sha256:def456...",
  "iat": 1717800000,
  "exp": 1717800900,
  "jti": "unique_token_id",
  "session_id": "session_uuid"
}
```

| Claim | Description |
|-------|-------------|
| `sub` | User UUID (subject) |
| `public_key_hash` | Identity anchor — links JWT to keyset |
| `email_hash` | For display/debug (not auth) |
| `iat` | Issued at (Unix timestamp) |
| `exp` | Expires at (Unix timestamp, 15 min from iat) |
| `jti` | JWT ID — for revocation lists |
| `session_id` | Unique session identifier |

**Signing:** RS256 (RSA 2048-bit) or ES256 (ECDSA P-256). Server holds private key, public key published at `/.well-known/jwks.json`.

**Why RS256/ES256 over HS256:**
- Asymmetric: public key can verify without exposing secret
- Key rotation: publish new public key, old tokens still verifiable
- Microservices: any service can verify with public key, no shared secret

### 4.2 Refresh Token (Opaque)

| Property | Value |
|----------|-------|
| **Format** | Random 256-bit string (base64url encoded) |
| **Storage** | Hashed with SHA-256 in DB (`refresh_tokens` table) |
| **Plaintext** | Never stored — only exists in cookie and DB hash |
| **Linking** | user_id, created_at |
| **Expiry** | 7 days from creation |
| **Revocation** | Boolean flag + revoked_at timestamp |
| **Rotation** | New token issued on each use, old marked "used" |
| **Reuse Detection** | If "used" token presented → revoke all sessions |

**Database Schema:**
```sql
CREATE TABLE refresh_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,  -- SHA-256 of plaintext
    user_id UUID REFERENCES users(user_id),
    session_id UUID,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP
);
```

### 4.3 CSRF Token

| Property | Value |
|----------|-------|
| **Format** | Random 128-bit string (base64url encoded) |
| **Storage** | Cookie (readable by JS) + memory (React state) |
| **Lifetime** | Matches access token (15 min) |
| **Rotation** | New token issued with each access token refresh |
| **Validation** | Header value must equal cookie value |

---

## 5. Proof-of-Work Specification

### 5.1 Challenge Generation

```
GET /api/pow-challenge

Server Actions:
1. Generate random 32-byte nonce
2. Store nonce in ephemeral storage (Redis or in-memory, 5-min TTL)
3. Return nonce + difficulty

Response: 200 OK
{
  "nonce": "base64url_encoded_32_bytes",
  "difficulty": 20,
  "expires_at": "2026-06-09T12:05:00Z"
}
```

### 5.2 Solution Verification

**Client (Browser):**
```javascript
// Find solution such that SHA-256(nonce + solution) has 'difficulty' leading zero bits
function solvePoW(nonce, difficulty) {
    let solution = 0;
    const target = Array(difficulty).fill('0').join('');
    while (true) {
        const hash = sha256(nonce + intToBytes(solution));
        if (hash.startsWith(target)) return solution;
        solution++;
    }
}
```

**Server:**
```python
def verify_pow(nonce: str, solution: str, difficulty: int) -> bool:
    # Check nonce exists and not expired
    if not nonce_store.exists(nonce):
        return False
    # Compute hash
    hash_result = sha256(nonce.encode() + solution.encode()).hexdigest()
    # Check leading zero bits
    binary = bin(int(hash_result, 16))[2:].zfill(256)
    return binary.startswith('0' * difficulty)
```

**Parameters:**
| Parameter | Value |
|-----------|-------|
| Difficulty | 20 (2^20 ≈ 1,048,576 iterations on average) |
| Time cost | ~1 second on modern desktop, ~3-5 seconds on mobile |
| Nonce expiry | 5 minutes |
| Nonce reuse | Rejected (single-use) |

---

## 6. Security Headers

### 6.1 Required Headers (All Responses)

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self'; connect-src 'self' https://api.medledger.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), accelerometer=(), gyroscope=(), magnetometer=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

### 6.2 CSP Evolution Path

| Phase | CSP | Timeline |
|-------|-----|----------|
| **MVP** | `unsafe-inline` for styles (development speed) | v1.0 launch |
| **Hardened** | Nonce-based CSP (`script-src 'nonce-abc123'`) | v1.1 (1 month post-launch) |
| **Strict** | Hash-based CSP, no inline scripts | v1.2 (3 months post-launch) |

---

## 7. Edge Cases and Failure Modes

### 7.1 Concurrent Sessions (Multiple Devices)

| Scenario | Behavior |
|----------|----------|
| **User logs in on Device A + Device B** | Each gets independent refresh token. Both sessions valid. |
| **User logs out on Device A** | Only Device A's refresh token revoked. Device B remains active. |
| **User revokes all sessions** | All refresh tokens for user marked revoked. All devices logged out. |
| **Refresh token reuse detected** | All sessions revoked. User must re-login on all devices. |

**UI:** "You have 3 active sessions. Log out all?" (settings page, future feature)

### 7.2 Password Change

```
POST /api/change-password
Cookie: access_token + X-CSRF-Token
Body: { old_password, new_password }

Server Actions:
1. Verify old_password (Argon2id)
2. Hash new_password (Argon22id)
3. Update users.password_hash
4. Revoke ALL refresh tokens for user (force re-login everywhere)
5. Issue new access_token + refresh_token + csrf_token

Response: 200 OK + new cookies
{
  "password_changed": true,
  "sessions_revoked": 3
}

Keyset Impact:
• Password change does NOT affect keyset (Layer 2).
• Keyset is encrypted with the user's chosen password, NOT the account password.
• If user wants to re-encrypt keyset with new password, they must:
  1. Download current keyset file
  2. Decrypt with old password
  3. Re-encrypt with new password
  4. Download new keyset file
  5. This is a client-side Keyset Manager operation, not a server endpoint.
```

### 7.3 Account Deletion (Absolute)

```
DELETE /api/account
Cookie: access_token + X-CSRF-Token
Body: { password_confirmation }

Server Actions:
1. Verify password (Argon2id)
2. Revoke ALL tokens
3. Hard delete:
   - user record
   - all active_shares (cascade)
   - all refresh_tokens (cascade)
4. Anonymize audit_log:
   - Replace user_id with hash of user_id
   - Replace email_hash with hash of email_hash
   - Keep action types and timestamps for compliance
5. Clear all cookies (set expired)

Response: 200 OK + Clear-Cookie headers
{
  "deleted": true,
  "shares_destroyed": 12,
  "audit_records_anonymized": 45
}

No grace period. No "are you sure?" bypass. No recovery.
Patient can immediately register a new account with a new keypair.
```

### 7.4 Inactivity Timeout

| Layer | Timeout | Behavior |
|-------|---------|----------|
| **Keyset (Layer 2)** | 30 minutes idle | Clear private key from memory. Vault locks. Account still logged in. |
| **Access token (Layer 1)** | 15 minutes | Auto-refresh via refresh token. User sees no interruption. |
| **Refresh token (Layer 1)** | 7 days | If expired, user must re-login with password. |

**UI Flow:**
- 25 min idle: Warning modal "Vault will lock in 5 minutes. Stay active?"
- 30 min idle: Vault locks. "Upload keyset to continue."
- 7 days: Full logout. "Session expired. Please log in."

---

## 8. Rate Limiting

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| GET /api/pow-challenge | 20 | Per IP, per hour | Prevents nonce exhaustion |
| POST /api/register | 5 | Per IP, per day | Prevents spam |
| POST /api/login | 10 | Per IP, per hour | Prevents brute force |
| POST /api/refresh | 30 | Per user, per hour | Prevents token abuse |
| POST /api/change-password | 3 | Per user, per hour | Prevents account lockout |
| DELETE /api/account | 1 | Per user, per day | Prevents accidental deletion |
| POST /api/share | 100 | Per user, per hour | General protection |
| POST /api/share/:id/retrieve | 200 | Per user, per hour | General protection |
| DELETE /api/share/:id | 50 | Per user, per hour | General protection |
| All other endpoints | 1000 | Per user, per hour | General protection |

**Email Domain Rate Limiting (Registration Only):**
| Domain Type | Limit | Window |
|-------------|-------|--------|
| Disposable (temp-mail, etc.) | 1 | Per domain, per day |
| Free (gmail, yahoo, etc.) | 20 | Per domain, per day |
| Custom / Corporate | 100 | Per domain, per day |

**Rate Limit Response:**
```json
{
  "error": "RateLimitExceeded",
  "message": "Too many requests. Try again in 42 minutes.",
  "retry_after": 2520
}
```

---

## 9. CORS Configuration

```python
# FastAPI CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.medledger.com"],  # Production frontend
    allow_credentials=True,  # CRITICAL: allows cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-CSRF-Token",
        "X-Requested-With",
        "Accept",
        "Origin"
    ],
    expose_headers=["X-Request-Id"],  # For tracing
    max_age=600  # Preflight cache
)
```

**Development CORS:**
```python
# Only in development
allow_origins=[
    "https://app.medledger.com",
    "http://localhost:5173",  # Vite dev server
    "http://localhost:3000"   # Alternative dev port
]
```

**Never allow `*` with `allow_credentials=True`** — this is a security vulnerability.

---

## 10. Implementation Checklist

### Backend (FastAPI)

- [ ] Cookie parser middleware (extract cookies from request)
- [ ] JWT verification middleware (RS256/ES256, check expiry, revocation)
- [ ] CSRF validation middleware (compare header vs cookie)
- [ ] Rate limiting middleware (SlowAPI or custom)
- [ ] Refresh token rotation logic (mark used, issue new, detect reuse)
- [ ] Session revocation endpoint (logout, password change, account deletion)
- [ ] Audit logging for all auth events
- [ ] `/.well-known/jwks.json` endpoint (public key for JWT verification)
- [ ] Secure cookie settings (HttpOnly, Secure, SameSite, Path, Domain)
- [ ] Argon2id password hashing (verify against OWASP 2023 parameters)
- [ ] CAPTCHA verification (Turnstile server-side check)
- [ ] PoW challenge generation (32-byte nonce, 5-min expiry, single-use)
- [ ] PoW solution verification (SHA-256, 20 leading zero bits)
- [ ] Email domain classification (disposable vs free vs custom)

### Frontend (React + Vite)

- [ ] `credentials: 'include'` on all `fetch` calls
- [ ] CSRF token extraction from cookie (helper function)
- [ ] TanStack Query interceptor: 401 → auto-refresh → retry
- [ ] TanStack Query interceptor: refresh fails → redirect to login
- [ ] Keyset Manager integration: generate on registration, load on unlock
- [ ] Inactivity timer: 30-minute idle detection for vault lock
- [ ] Logout handler: clear state, redirect, call /api/logout
- [ ] Session check on app mount: call /api/me
- [ ] "Vault Locked" UI state: prompt for keyset upload
- [ ] "Vault Unlocked" UI state: enable share operations
- [ ] Password change form: old + new password, show sessions_revoked count
- [ ] Account deletion form: password confirmation + type "DELETE", show consequences

### Database

- [ ] `users` table: email_hash, password_hash, public_key_hash, encrypted_private_key_blob, timestamps
- [ ] `refresh_tokens` table: token_hash, user_id, session_id, expiry, revoked, used
- [ ] `active_shares` table: owner_key_hash, grantee_key_hash, ciphertext, dek_bundle, TTL
- [ ] `audit_log` table: actor_key_hash, action, IP, timestamp, details (anonymized)

---

## 11. Remaining Decisions (For Research)

### 11.1 JWT Signing Algorithm

| Option | Pros | Cons | Status |
|--------|------|------|--------|
| **RS256 (RSA 2048)** | Widely supported, mature libraries | Slower, larger signatures | **Candidate** |
| **ES256 (ECDSA P-256)** | Faster, smaller signatures, same curve as keyset | Slightly less library support | **Candidate** |
| **EdDSA (Ed25519)** | Fastest, modern, no nonce issues | Newer, not in Web Crypto API | **Future** |

**Decision needed:** ES256 aligns with our P-256 keyset curve but may complicate JWT libraries. RS256 is safest for v1.0.

### 11.2 Session Storage (Redis vs PostgreSQL)

| Option | Pros | Cons | Status |
|--------|------|------|--------|
| **PostgreSQL only** | Single database, simpler ops | Slower for high-frequency token checks | **Current** |
| **Redis for sessions** | Fast, TTL built-in, atomic operations | Additional infrastructure | **Future** |

**Decision needed:** PostgreSQL sufficient for MVP. Redis if scaling beyond 10k concurrent sessions.

### 11.3 Encrypted Private Key Blob on Server

| Option | Pros | Cons | Status |
|--------|------|------|--------|
| **Store on server** | User can re-download if they lose file while logged in | Server holds encrypted blob (brute-forceable if password weak) | **Current** |
| **Client-side only** | Zero server responsibility for key recovery | User must never lose keyset file | **Alternative** |

**Decision needed:** Store on server for v1.0 (convenience). Consider client-side-only for v1.1 if threat model shifts.

### 11.4 Multi-Factor Authentication (MFA)

| Option | Pros | Cons | Status |
|--------|------|------|--------|
| **None (Layer 2 = MFA)** | Key possession is strong proof | No fallback if key lost | **Current** |
| **TOTP (Google Authenticator)** | Industry standard, offline | Additional setup friction | **Future** |
| **WebAuthn (FIDO2)** | Phishing-resistant, modern | Limited hardware support | **Future** |
| **SMS** | Easy adoption | SIM swap attacks, insecure | **Rejected** |

**Decision needed:** None for v1.0. The two-layer auth (password + key possession) is already strong MFA.

### 11.5 Mobile App Authentication

| Option | Pros | Cons | Status |
|--------|------|------|--------|
| **Same cookie-based auth** | Consistent with web | Mobile WebViews handle cookies poorly | **Problematic** |
| **OAuth 2.0 + PKCE** | Mobile-native, secure | Additional complexity, different flow | **Future** |
| **Custom token-based** | Mobile-optimized | Diverges from web security model | **Risky** |

**Decision needed:** Mobile app is out of scope for v1.0. When needed, OAuth 2.0 + PKCE with same backend.

---

## 12. References

| Standard | Application |
|----------|-------------|
| [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Cookie settings, session lifecycle |
| [OWASP Cheat Sheet: Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | CSRF token pattern |
| [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) | JWT structure and claims |
| [RFC 7518: JSON Web Algorithms](https://tools.ietf.org/html/rfc7518) | RS256, ES256 signing |
| [RFC 9106: Argon2id](https://tools.ietf.org/html/rfc9106) | Password hashing parameters |
| [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) | Authentication requirements |

---

## 13. Alignment with Architecture Documents

| Concept | 01-ARCHITECTURE.md | 02-SECURITY_SPEC.md | This Document |
|---------|-------------------|---------------------|---------------|
| **Email purpose** | Anti-spam only | Anti-spam only | Anti-spam only (no verification, no recovery) |
| **Account recovery** | None | None | None (delete and restart) |
| **Keyset generation** | Browser-side | Browser-side | Browser-side, during registration |
| **Layer 2 unlock** | Client-side only | Client-side only | Client-side only (no server challenge) |
| **Account deletion** | Absolute, immediate | Absolute, immediate | Absolute, immediate (no grace period) |
| **JWT claims** | public_key_hash, email_hash | public_key_hash, email_hash | public_key_hash, email_hash (no role, no username) |
| **PoW** | 2^20 SHA-256 | 2^20 SHA-256 | 2^20 SHA-256, 5-min nonce expiry |
| **CAPTCHA** | Turnstile | Turnstile | Turnstile, server-side verification |
| **Password hashing** | Argon2id | Argon2id | Argon2id, 64MB, 3 iter, 4 parallel |
| **Cookie security** | HttpOnly, Secure, SameSite | HttpOnly, Secure, SameSite | HttpOnly, Secure, SameSite=Lax/Strict |

---

*Document: 03-AUTH_SPEC.md | Author: Premananda (Team Praxis) | Status: Draft v1.0 — Aligned*
*Architecture: BFF + HttpOnly Cookies + CSRF Protection*
*Aligned with: 01-ARCHITECTURE.md (Sharing Conduit) + 02-SECURITY_SPEC.md (Zero-Knowledge)*
