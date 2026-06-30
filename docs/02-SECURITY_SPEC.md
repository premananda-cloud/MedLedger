# MedLedger Security Specification

**Version:** 2.1 | **Date:** June 2026 | **Status:** Current — Reflects Deployed System

**WARNING:** This document defines what "secure" means for MedLedger. Any implementation that violates these specifications is considered broken, regardless of whether it functions correctly.

**Change from v2.0:** Argon2id is now implemented (no longer a target). TOTP is retained (not removed as previously planned). Password reset flow exists (documented as a known divergence from original "no recovery" principle). Bearer JWT is current auth pattern (HttpOnly cookies are a future hardening step).

---

## 1. Threat Model

### 1.1 Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **External Attacker** | Network access, phishing, XSS | Steal data, impersonate users, spam |
| **Malicious Insider** | Database access, server logs | Curiosity, fraud, sale of data |
| **Compromised Server** | Full backend control | Mass data exfiltration, serve malicious JS |
| **Compromised Browser** | XSS, malicious extension | Session hijacking, key theft |
| **User Error** | Lost keypair, weak password | Self-inflicted data loss |
| **Nation State** | Compulsion, legal pressure | Mass surveillance |
| **Spam Operator** | Botnets, automation | Account flooding, resource exhaustion |

### 1.2 Assets and Protection Goals

| Asset | Protection | Against |
|-------|-----------|---------| 
| **Medical records (plaintext)** | Confidentiality | Everyone except owner and grantee |
| **Medical records (integrity)** | Integrity | Tampering, forgery |
| **Private keys** | Confidentiality | Everyone including server |
| **Share permissions** | Integrity + Non-repudiation | Forgery, replay |
| **User credentials** | Confidentiality | External attackers, insiders |
| **Audit logs** | Integrity | Tampering, deletion |
| **Service availability** | Availability | Spam, DDoS, resource exhaustion |

### 1.3 Threat Scenarios

#### Scenario A: Database Breach

**Attacker gains:** `users` table (Argon2id hashes, emails, public keys), `active_shares` (ciphertext, sealed DEK bundles), `audit_log`.

**Attacker cannot:**
- Decrypt medical records (no private key, no plaintext DEK)
- Derive private keys from public keys (Ed25519/X25519 security)
- Forge shares (no owner private key)
- Crack passwords efficiently (Argon2id with 64MB memory cost)

**Note:** Argon2id parameters (m=65536, t=3, p=4) make offline brute force economically unviable for strong passwords. Weak passwords remain vulnerable to dictionary attacks.

#### Scenario B: Server Compromise (Full Control)

**Attacker cannot:**
- Decrypt past medical records (private keys never on server)
- Decrypt future uploads (browser encrypts, server only stores)
- Forge valid shares (browser signs, server verifies)

**Attacker can:**
- Delete data (mitigated: patient holds physical originals)
- Serve malicious JavaScript → steal keys from browser memory (mitigated by CSP)
- Read JWT secrets → forge access tokens (mitigate: rotate JWT secret immediately)

#### Scenario C: XSS in Browser

**Attacker can with XSS:**
- Steal JWT from localStorage / memory (if not HttpOnly cookie — current implementation uses Bearer tokens in JS; this is a known risk, see §Known Limitations)
- Access `Uint8Array` key material in memory if script runs in same origin

**Mitigated by:** Strict CSP, no eval(), SRI on all CDN scripts.

**Current auth pattern risk:** Because access tokens are used as Bearer tokens (managed by JS), a successful XSS can steal the token for up to its 15-minute lifetime. Migration to HttpOnly cookies eliminates this. See §Known Limitations.

#### Scenario D: Lost Keypair File

**Result:** Vault permanently locked. No server-side recovery possible.
**Recovery:** Delete account and re-register with new keypair.

**Note:** Password reset (Layer 1) does NOT restore keypair access (Layer 2). These are independent.

#### Scenario E: Password Compromise (Layer 1 Only)

**Attacker can:** Log in, see share metadata, delete shares.
**Attacker cannot:** Decrypt shares (needs keypair file too).

This is the two-layer design working as intended. Password alone is insufficient for data access.

#### Scenario F: Nation State Compulsion

We cannot provide: private keys (never transmitted), DEK plaintext (always sealed), plaintext records (never stored). We can provide: ciphertext (useless without key), password hashes (Argon2id, not crackable without private key), audit logs.

#### Scenario G: Spam / Bot Attack

**Mitigation layers in order:**
1. **Proof-of-work** (SHA-256): CPU cost per registration
2. **Rate limiting**: per-IP per-email lockout via `rate_limit` table
3. **Email verification**: 6-digit code required before account is functional
4. **Login lockout**: after 5 failures, 15-minute block

---

## 2. Cryptographic Specifications

### 2.1 Algorithm Registry

| Purpose | Algorithm | Parameters | Library | Status |
|---------|-----------|------------|---------|--------|
| Signing keypair | Ed25519 | 32-byte public, 64-byte private | libsodium.js | **Active** |
| Encryption keypair | X25519 | 32-byte public, 32-byte private | libsodium.js | **Active** |
| Symmetric file encryption | XSalsa20-Poly1305 | 32-byte key, 24-byte nonce | libsodium.js | **Active** |
| Sealed-box DEK encryption | X25519 + XSalsa20-Poly1305 | crypto_box_seal | libsodium.js | **Active** |
| Grant signing | Ed25519 | 64-byte signature | libsodium.js | **Active** |
| Content hashing | BLAKE2b | 256-bit output | libsodium.js | **Active** |
| Identity hashing | BLAKE2b | 128-bit output → user_id_hex | libsodium.js | **Active** |
| Password hashing (server) | Argon2id | m=65536, t=3, p=4, salt=16B | argon2-cffi | **Active** |
| Password hashing (legacy) | PBKDF2-SHA512 | 600,000 iter, 64B key | Python hashlib | **Verify-only, rehash on login** |
| CSPRNG | randombytes_buf | — | libsodium.js | **Active** |
| Memory zeroing | memzero | — | libsodium.js | **Active** |

### 2.2 Password Hashing: Argon2id (Current)

Argon2id is now fully implemented. The `hash_password_argon2()` method returns a self-contained string:

```
$argon2id$v=19$m=65536,t=3,p=4$<salt_base64>$<hash_base64>
```

The salt is embedded in this string. No separate salt column is needed or used. `set_password_hash()` is a single-column update.

**Rehash on login:** If a user's stored hash is PBKDF2 (from before the migration), the system verifies with the legacy 4-argument PBKDF2 path, then transparently rehashes to Argon2id on successful login. No user action required.

**Parameters meet OWASP 2023 recommendations.** Revisit if OWASP updates guidance.

### 2.3 Key Hierarchy

```
User Keypair File (.medledger-key.json)
    │
    ├──► Ed25519 signing keypair
    │         ├──► Sign share grants
    │         ├──► Sign share retrievals
    │         └──► Identity: user_id_hex = BLAKE2b-128(signingPublicKey)
    │
    └──► X25519 exchange keypair
              ├──► Seal DEK for recipient (crypto_box_seal)
              └──► Open sealed DEK as recipient (crypto_box_seal_open)

Per-share ephemeral key material:
    Random 256-bit DEK (generated per share)
        ├──► XSalsa20-Poly1305 encrypts file → ciphertext + nonce
        └──► crypto_box_seal(DEK, recipientExchangePublicKey) → dek_bundle
    DEK wiped from memory after encryption (memzero)
```

### 2.4 Proof-of-Work

- Server generates: random `challenge` string, `difficulty` (leading zero bits)
- Client finds: `solution` such that `SHA-256(challenge + solution)` has `difficulty` leading zero bits
- Server verifies: one SHA-256 call, check leading zeros, mark challenge solved (replay protection)
- Challenges expire (configurable TTL in POWModule)

**Current difficulty** is set in `POWModule` configuration. Increase for stronger anti-spam as needed.

---

## 3. Authentication Specifications

### 3.1 Layer 1: Gate (Current Implementation)

| Property | Value |
|----------|-------|
| **Password hashing** | Argon2id (argon2-cffi), self-contained string |
| **Session** | JWT access token (15 min) + opaque refresh token (30 days) |
| **Token delivery** | `Authorization: Bearer <token>` header — JS-managed |
| **Refresh token storage** | SHA-256 hash in `refresh_tokens` table |
| **Refresh rotation** | New token issued on each use; reuse detection revokes whole family |
| **2FA** | TOTP (pyotp), optional |
| **Email** | Verification required (6-digit code, 10-min TTL, hash stored) |
| **Password reset** | Supported (6-digit code to email, 15-min TTL) |

**Planned hardening (not yet implemented):** HttpOnly cookies instead of Bearer tokens. This eliminates the XSS token theft risk. See §Known Limitations.

### 3.2 Layer 2: Keypair Unlock (Client-Side Only)

Keypair state is never sent to the server. It is a pure client-side concern.

```
User logs in (Layer 1) → JWT issued → Account accessible
                                 │
                                 ▼
                        Dashboard: "Vault Locked"
                                 │
                        User uploads .medledger-key.json
                                 │
                        KeysetManager.loginUser(username, keypair)
                        → Private keys in module memory only
                                 │
                                 ▼
                        Dashboard: "Vault Unlocked"
                        Share / decrypt operations available
```

Private keys are held as `Uint8Array` in a JS module closure. On `window.beforeunload`, explicit logout, or 30-minute inactivity: `sodium.memzero()` then null.

### 3.3 Login Security

- Rate limit checked **before** `verify_password()` — prevents locked-out users from learning whether their guess is correct via timing.
- Dummy Argon2id hash used when user not found — `verify_password()` always runs the full hash computation to prevent user-enumeration via response time.
- On 5 consecutive failures: 15-minute lockout stored in `rate_limit` table.
- On success: rate limit reset, new tokens issued, `last_login_at` updated.
- Opportunistic rehash: if stored hash uses PBKDF2, rehashed to Argon2id after successful verify.

### 3.4 Logout

**Single device:** Refresh token revoked in DB. Access token expires naturally (15 min).
**All devices:** All refresh tokens for user revoked via `revoke_all_user_refresh_tokens()`.
**Password change / TOTP disable:** All refresh tokens revoked (forces re-login everywhere).

---

## 4. Known Limitations (Current Code)

| Issue | Location | Severity | Status |
|-------|----------|----------|--------|
| **Bearer tokens in JS memory** (XSS can steal) | Frontend auth | Medium | Planned: migrate to HttpOnly cookies |
| **TOTP backup codes hashed with SHA-256** (not Argon2id) | auth_service.py | Low | Acceptable for backup codes |
| **PoW difficulty configurable** — ensure production value is meaningful | POWModule | Varies | Set appropriately in config |
| **Password reset exists** (partial recovery vector) | routes/auth.py | Low | Documented divergence from "no recovery" principle — Layer 2 still non-recoverable |
| **Keypair file unencrypted** | key_manager.js | Medium | Planned: password-encrypt private keys in file |
| **No CAPTCHA** | Registration | Medium | Add Turnstile in v1.1 |
| **JWT secret in env var** (not HSM) | TokenModule | Low | Acceptable for MVP; HSM for production |

---

## 5. Browser Security

### 5.1 Required Headers

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' https://api.medledger.com; frame-ancestors 'none'; base-uri 'self'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

### 5.2 HTTPS

- TLS 1.3 minimum (TLS 1.2 acceptable for older clients)
- HSTS preload registered
- No mixed content

---

## 6. Server Security

### 6.1 Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /auth/register | 5 | Per IP, per day |
| POST /auth/login | 5 failures | Per email, then 15-min lockout |
| POST /auth/request-password-reset | 3 | Per user, per hour |
| All other endpoints | Configurable | Per user, per hour |

### 6.2 Input Validation

All request bodies validated by Pydantic v2 before reaching services. Username: `^[a-zA-Z0-9_]{3,30}$`. Password: minimum 8 characters at schema level, full strength scoring in `PasswordModule.validate_strength()`. TOTP codes: `^\d{6}$`. Email: Pydantic `EmailStr`.

### 6.3 Audit Logging

Every auth event logged to `audit_log` with actor, action, IP, and timestamp. No plaintext passwords, no PHI, no private keys in logs.

---

## 7. Compliance Posture

### 7.1 HIPAA

| HIPAA Rule | Implementation |
|------------|---------------|
| Access Control (164.312(a)) | Two-layer auth, JWT, audit logs |
| Audit Controls (164.312(b)) | Immutable audit_log, all events recorded |
| Integrity (164.312(c)) | XSalsa20-Poly1305 authentication tag, Ed25519 signatures |
| Transmission Security (164.312(e)) | TLS 1.3 |
| Breach Notification (164.404) | Encrypted data breach = not reportable under HIPAA Safe Harbor |

### 7.2 GDPR

- **Data minimization:** Only public keys, ciphertext, and metadata stored server-side.
- **Right to erasure:** Account deletion removes all shares and anonymizes audit logs.
- **Right to portability:** User holds keypair file; open algorithms (Ed25519, X25519, XSalsa20).

---

## 8. Security Checklist (Pre-Production)

- [ ] No `console.log` with keys, passwords, or tokens
- [ ] No `localStorage` for keys or JWT
- [ ] No `eval()` or `Function()` constructor
- [ ] JWT stored as Bearer (current) — plan migration to HttpOnly cookie
- [ ] `sodium.memzero()` on all private material after use
- [ ] CSP deployed and tested
- [ ] Rate limiting active on all public endpoints
- [ ] JWT secret rotated from default — stored in Railway env var
- [ ] Database SSL/TLS connection verified
- [ ] Argon2id parameters match spec (m=65536, t=3, p=4) — verified in `_PH` constant
- [ ] PoW difficulty set appropriately for production
- [ ] Email delivery working (Gmail SMTP credentials in env)
- [ ] CORS `allow_origins` lists only production frontend domain

---

## 9. Invariants (Non-Negotiable)

1. **Private keys never leave the browser.**
2. **Server stores only public material and ciphertext.**
3. **We cannot decrypt medical data.** Mathematical guarantee.
4. **DEKs are always sealed.** Plaintext DEK never exists server-side.
5. **Argon2id for all new password hashes.** No new PBKDF2 hashes created.
6. **Lockout check before password verify.** No timing oracle for locked accounts.
7. **Verification tokens stored as SHA-256 hashes.** Plain codes never persisted.
8. **Refresh token reuse triggers full family revocation.** All sessions invalidated.
9. **Audit everything.** Every auth event logged.
10. **Honest UI.** No false recovery promises.

---

*Document: 02-SECURITY_SPEC.md | Version: 2.1 | June 2026*
*Argon2id is now implemented. TOTP retained. Bearer JWT is current (HttpOnly cookies planned).*
