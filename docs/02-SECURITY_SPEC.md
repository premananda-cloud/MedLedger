# MedLedger Security Specification

**Version:** 1.0 | **Date:** June 2026 | **Status:** Draft — Foundation Document

**WARNING:** This document defines what "secure" means for MedLedger. Any implementation that violates these specifications is considered broken, regardless of whether it functions correctly.

---

## 1. Threat Model

### 1.1 Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **External Attacker** | Network access, phishing, XSS | Steal data, impersonate users, spam |
| **Malicious Insider** | Database access, server logs | Curiosity, fraud, sale of data |
| **Compromised Server** | Full backend control | Mass data exfiltration, serve malicious JS |
| **Compromised Browser** | XSS, malicious extension | Session hijacking, key theft |
| **User Error** | Lost keyset, weak password | Self-inflicted data loss |
| **Nation State** | Compulsion, legal pressure | Mass surveillance |
| **Spam Operator** | Botnets, automation | Account flooding, resource exhaustion |

### 1.2 Assets and Protection Goals

| Asset | Protection | Against |
|-------|-----------|---------|
| **Medical records (plaintext)** | Confidentiality | Everyone except owner and grantee |
| **Medical records (integrity)** | Integrity | Tampering, forgery |
| **Private keys** | Confidentiality | Everyone (including server) |
| **Share permissions** | Integrity + Non-repudiation | Forgery, replay |
| **User credentials** | Confidentiality | External attackers, insiders |
| **Audit logs** | Integrity | Tampering, deletion |
| **Service availability** | Availability | Spam, DDoS, resource exhaustion |

### 1.3 Threat Scenarios

#### Scenario A: Database Breach

**Attacker gains:** `users` table (password hashes, emails, public key hashes), `active_shares` (ciphertext, encrypted DEK bundles), `audit_log` (anonymized actions).

**Attacker cannot:**
- Decrypt medical records (no DEK, no private key)
- Derive private keys from encrypted blobs (no password, PBKDF2 + AES-GCM)
- Forge shares (no owner private key, ECDSA verification fails)
- Impersonate users (Argon2id password hashes, no plaintext passwords)
- Link shares to real identities (email hashes only, no plaintext emails in shares)

**Mitigation:** Zero-knowledge architecture. Server breach reveals only public material and properly encrypted ciphertext.

#### Scenario B: Server Compromise (Full Control)

**Attacker gains:** Everything in Scenario A + ability to modify code, read memory, intercept traffic.

**Attacker cannot:**
- Decrypt past medical records (private keys never on server)
- Decrypt future uploads (browser encrypts, server only stores)
- Forge valid shares (browser signs, server verifies)

**Attacker can:**
- Delete data (availability attack — mitigated by patient holding originals)
- Serve malicious JavaScript (mitigated by CSP, SRI, code signing)
- Log traffic (mitigated by TLS 1.3)
- Spam (mitigated by CAPTCHA + PoW + rate limiting)

**Critical:** If attacker serves malicious JS, they can steal keys from browser memory. This is why CSP and SRI are mandatory.

#### Scenario C: XSS in Browser

**Attacker injects:** JavaScript via compromised dependency, user input, or CDN.

**Attacker can:**
- Steal JWT from cookies (if not HttpOnly — prevented by design)
- Read localStorage/IndexedDB (if keys stored there — prevented by design)
- Keylog password inputs (if on malicious page — prevented by CSP)
- Access `CryptoKey` objects in memory (if script runs in same origin — mitigated by strict CSP)

**Mitigation:**
- JWT in HttpOnly cookie (not accessible to JS)
- Private keys in `CryptoKey` memory only (not in storage APIs)
- Strict CSP: `default-src 'self'; script-src 'self'`
- Subresource Integrity (SRI) on all CDN scripts
- No `eval()`, no inline scripts

#### Scenario D: Lost Keyset File

**User loses:** `medledger-keyset-2026.json` file.

**Result:**
- Account still accessible (Layer 1: email + password)
- Vault permanently locked (Layer 2: no private key)
- Medical records still held by patient physically (MedLedger is a conduit, not a vault)
- Old shares irretrievable (server deletes them anyway after TTL)

**Recovery:**
- **Delete account and start over.** Generate new keypair, re-upload records, re-share.
- No Shamir recovery in v1.0. No cloud backup. No paper backup.

**UI Messaging:**
- Clear, honest, no false hope: "Without your keyset file, you cannot decrypt shared data. We cannot recover it. Your physical records are safe. Delete this account and start over if needed."
- Proactive: "Save your keyset file like a passport."

#### Scenario E: Password Compromise

**Attacker gains:** User's Layer 1 password.

**Attacker can:**
- Log into account (impersonate user)
- See metadata (share history, file names, recipient public key hashes)
- Delete shares (availability attack)
- Delete account (availability attack)

**Attacker cannot:**
- Decrypt shared files (private key encrypted with password, but keyset file needed)
- Create valid shares (private key needed)
- Access keyset without keyset file

**Mitigation:** Two-layer security. Password alone is insufficient for data access.

#### Scenario F: Nation State Compulsion

**Actor demands:** Decrypt user medical records.

**Our response:** Mathematically impossible. We do not possess:
- User's private key (never transmitted)
- User's password (Argon2id hash only)
- DEK plaintext (always ECIES-wrapped)
- Plaintext medical records (never on server)

**What we can provide:**
- Ciphertext (useless without key)
- Public key hashes (already public)
- Encrypted private key blobs (useless without password)
- Audit logs (anonymized after account deletion)

**Legal posture:** We are a sharing conduit, not a data processor. Patient is the data controller. We store encrypted data we cannot read, for a limited time, at the patient's direction.

#### Scenario G: Spam / Bot Attack

**Attacker floods:** Registration endpoint with fake accounts.

**Mitigation layers:**
1. **CAPTCHA** (Turnstile): Human verification, privacy-preserving
2. **Proof-of-work** (SHA-256, 2^20 iterations): ~1 second CPU cost per registration
3. **Rate limiting**: 5 per IP per day, 20 per email domain per day
4. **Email verification**: Verified but not used for recovery — just a rate-limiting key

**Result:** Spam is economically unviable. Legitimate users experience ~1 second delay.

---

## 2. Cryptographic Specifications

### 2.1 Algorithm Registry

| Purpose | Algorithm | Parameters | Standard |
|---------|-----------|------------|----------|
| Keypair generation | ECDSA | P-256 (secp256r1) | NIST FIPS 186-5 |
| Key exchange | ECDH | P-256 (secp256r1) | NIST SP 800-56A |
| File encryption | AES-256-GCM | 256-bit key, 96-bit IV, 128-bit tag | NIST SP 800-38D |
| DEK wrapping | ECIES | ECDH + HKDF-SHA256 + AES-256-GCM | SECG SEC 1 |
| Grant signing | ECDSA | P-256, SHA-256 | NIST FIPS 186-5 |
| Password hashing | Argon2id | Memory=64MB, iterations=3, parallelism=4 | RFC 9106 |
| Key encryption | PBKDF2 | SHA-256, 310,000 iterations, 32-byte salt | NIST SP 800-132 |
| Key derivation | HKDF | SHA-256, info="MedLedger-DEK-v1" | RFC 5869 |
| Hashing | SHA-256 | — | FIPS 180-4 |
| Random generation | CSPRNG | `crypto.getRandomValues` (browser), `os.urandom` (server) | — |
| Proof-of-work | SHA-256 | 2^20 iterations (1,048,576) | — |

### 2.2 Key Hierarchy

```
User Password (memorized)
    │
    ├──► Argon2id ──► Account Auth (Layer 1)
    │
    └──► PBKDF2 + Salt ──► AES Key ──► Decrypt Private Key JWK
                                              │
                                              ▼
                                    Private Key (CryptoKey, memory only)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
                    ▼                         ▼                         ▼
              ECDSA Sign              ECDH + HKDF              ECDH + HKDF
              (shares)              (encrypt DEK)            (decrypt DEK)
                    │                         │                         │
                    ▼                         ▼                         ▼
              Signature           DEK Bundle (ECIES)          DEK (plaintext)
                                                                  │
                                                                  ▼
                                                           AES-256-GCM
                                                           (file encrypt/decrypt)
```

### 2.3 ECIES Implementation (Browser)

ECIES is not a single standard. MedLedger uses this construction:

**Encryption (Browser):**
1. Generate ephemeral P-256 keypair: `(ephemeral_private, ephemeral_public)`
2. ECDH: `shared_secret = ephemeral_private × recipient_public` (point multiplication)
3. HKDF-SHA256(shared_secret, salt="", info="MedLedger-DEK-v1") → `wrap_key` (32 bytes)
4. AES-256-GCM(plaintext=DEK, key=wrap_key, iv=random_12_bytes) → `(ciphertext, tag)`
5. Return bundle: `{ epk: ephemeral_public_hex, iv: iv_hex, ct: ciphertext_hex, tag: tag_hex }`

**Decryption (Browser):**
1. ECDH: `shared_secret = recipient_private × ephemeral_public` (from bundle.epk)
2. HKDF-SHA256(shared_secret, salt="", info="MedLedger-DEK-v1") → `wrap_key`
3. AES-256-GCM(ciphertext=bundle.ct, key=wrap_key, iv=bundle.iv, tag=bundle.tag) → DEK

**Forward Secrecy:** Each encryption uses a fresh ephemeral keypair. Compromise of the recipient's long-term private key does not expose past DEKs (but does expose future ones if not rotated — mitigated by account deletion and re-creation).

### 2.4 Proof-of-Work (Registration Anti-Spam)

**Challenge:**
- Server provides: `nonce` (32-byte random), `difficulty` (default 20)
- Client must find: `solution` such that `SHA-256(nonce || solution)` has `difficulty` leading zero bits

**Verification:**
- Server computes `SHA-256(nonce || solution)` once
- Checks leading zero bits ≥ difficulty
- Rejects if nonce already used (replay prevention)

**Parameters:**
- Difficulty: 20 (2^20 = ~1,048,576 iterations on average)
- Time cost: ~1 second on modern desktop, ~3-5 seconds on mobile
- Nonce expiry: 5 minutes
- Rate limit: 5 registrations per IP per day, 20 per email domain per day

### 2.5 Keyset Encryption (Private Key Protection)

**Encryption (Browser, during keyset generation):**
1. Generate random 32-byte salt
2. PBKDF2(password, salt, iterations=310000, keylen=32, hash=SHA-256) → `aes_key`
3. Generate random 12-byte IV
4. AES-256-GCM(plaintext=private_key_jwk, key=aes_key, iv=iv) → `(ciphertext, tag)`
5. Store: `{ salt, iv, ciphertext, tag, pbkdf2_iterations: 310000 }`

**Decryption (Browser, during keyset load):**
1. PBKDF2(password, stored_salt, stored_iterations, keylen=32, hash=SHA-256) → `aes_key`
2. AES-256-GCM(ciphertext, key=aes_key, iv=stored_iv, tag=stored_tag) → private_key_jwk
3. Import JWK into Web Crypto API → `CryptoKey` object (non-extractable for operations, extractable only for export if needed)

**Security note:** PBKDF2 iterations are stored in the keyset package. If we increase the minimum in the future, old keysets still work (backward compatible). We can recommend re-encryption with higher iterations during account re-creation.

---

## 3. Authentication Specifications

### 3.1 Layer 1: Gate (Anti-Spam + Session)

**Registration:**
- Email validation: RFC 5322 compliant, MX record check (optional), disposable domain check (configurable)
- CAPTCHA: Cloudflare Turnstile (privacy-preserving, free tier)
- Proof-of-work: SHA-256, 2^20 iterations, verified server-side
- Password requirements: minimum 12 characters, entropy check (zxcvbn or similar)
- Password hashing: Argon2id (memory=64MB, iterations=3, parallelism=4, salt=16 bytes random)
- Hash format: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
- No email verification link. Email is verified syntactically and via MX, but no "click to confirm" flow.

**Login:**
1. Client POST `{ email, password }`
2. Server fetches user by email_hash (constant-time to prevent enumeration)
3. Argon2id verify(password, stored_hash)
4. If valid: issue JWT, update last_login, log audit event
5. If invalid: 401, exponential backoff (1s, 2s, 4s, 8s, max 30s)

**JWT Specification:**
| Property | Value |
|----------|-------|
| Algorithm | RS256 (asymmetric) or ES256 |
| Key | Server holds private key, public key published |
| Claims | `sub` (user_id), `email_hash`, `role`, `iat`, `exp`, `jti` |
| Expiry | 15 minutes (access token) |
| Refresh | 7 days (refresh token, rotation on use) |
| Storage | HttpOnly, SameSite=Strict, Secure cookie |

**Why RS256/ES256 instead of HS256:**
- Server can verify tokens without storing secrets in every service
- Public key can be rotated without invalidating all sessions
- Prevents token forgery if single secret leaks

**Refresh Token Rotation:**
1. Client sends refresh token (HttpOnly cookie)
2. Server verifies, issues new access token + new refresh token
3. Old refresh token invalidated (stored in DB, marked used)
4. Refresh token reuse detection: if used token is presented again, revoke ALL sessions for user (token theft detection)

### 3.2 Layer 2: Keyset Unlock

Keyset is NOT authenticated via JWT. It is a **client-side state** that unlocks share operations.

**State Machine:**
```
User logs in (Layer 1) → JWT cookie set → Account accessible
                                    │
                                    ▼
                           Dashboard shows: "Vault Locked"
                                    │
                                    ▼
                           User uploads keyset file + password
                                    │
                                    ▼
                           Keyset Manager decrypts private key
                           → Memory only (CryptoKey)
                                    │
                                    ▼
                           Dashboard shows: "Vault Unlocked"
                           Share operations now available
```

**Session Binding:**
- JWT cookie authenticates the user (who)
- Keyset in memory authorizes share operations (what they can decrypt)
- If keyset is not loaded, share endpoints return 403: "Keyset required. Upload your keyset file."

**Memory Management:**
- Private key held as `CryptoKey` object in browser memory
- On `window.beforeunload` or explicit logout: `crypto.subtle.deleteKey()` or let GC collect
- On page refresh: keyset must be re-uploaded (intentional — prevents accidental persistence)
- Optional: "Remember for this session" checkbox → store in `sessionStorage` (cleared on tab close, NOT localStorage)

### 3.3 Logout

**Full Logout:**
1. Clear JWT cookie (server sets expired cookie)
2. Clear refresh token from DB
3. Client-side: clear memory (delete CryptoKey references)
4. Client-side: clear sessionStorage
5. Redirect to login page

**Keyset-Only Lock:**
1. Client-side: delete CryptoKey references
2. Client-side: clear sessionStorage
3. Dashboard returns to "Vault Locked" state
4. Account still logged in (JWT cookie valid)

---

## 4. Browser Security

### 4.1 Content Security Policy (CSP)

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  connect-src 'self' https://api.medledger.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

**Notes:**
- No `unsafe-inline` for scripts (use nonce-based CSP in production)
- No external scripts except Web Crypto API (browser native)
- No `eval()`, no `Function()`, no `setTimeout(string)`

### 4.2 Subresource Integrity (SRI)

All CDN resources (if any) must include integrity hashes:

```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-abc123..."
        crossorigin="anonymous"></script>
```

### 4.3 HTTPS Requirements

- TLS 1.3 minimum (TLS 1.2 acceptable for older clients)
- HSTS: `max-age=31536000; includeSubDomains; preload`
- Certificate pinning (optional, for mobile apps)
- No mixed content (all resources HTTPS)

### 4.4 Secure Headers

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

### 4.5 Web Crypto API Constraints

**Supported Operations:**
| Operation | Browser Support | Notes |
|-----------|----------------|-------|
| `generateKey(ECDSA, P-256)` | All modern browsers | Chrome 37+, Firefox 35+, Safari 7+ |
| `deriveBits(ECDH, P-256)` | All modern browsers | For ECIES shared secret |
| `encrypt(AES-GCM)` | All modern browsers | 256-bit key, 96-bit IV |
| `sign(ECDSA)` | All modern browsers | For share signatures |
| `digest(SHA-256)` | All modern browsers | For hashing and PoW |
| `importKey(PBKDF2)` | All modern browsers | For key derivation |

**Not Supported (must polyfill or avoid):**
- HKDF directly (must implement via `deriveBits` + HMAC)
- ECIES (must compose from ECDH + HKDF + AES-GCM)
- Argon2id (not in Web Crypto — use PBKDF2 for browser-side key encryption)

**Fallback:** If Web Crypto API is unavailable (old browser, insecure context), show error: "Your browser does not support the cryptographic features required by MedLedger. Please use Chrome, Firefox, Safari, or Edge (latest versions)."

---

## 5. Server Security

### 5.1 Password Storage

- Argon2id with parameters: memory=64MB, iterations=3, parallelism=4
- Salt: 16 bytes (128 bits), random per user
- Hash length: 32 bytes
- Format: Modular Crypt Format (MCF) — `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
- Verification: `argon2.verify(hash, password)` with constant-time comparison

### 5.2 Database Security

- PostgreSQL with SSL/TLS connection (verify-full mode)
- Connection pooling with prepared statements (prevent SQL injection)
- Row-level security (RLS) policies for multi-tenant isolation (future)
- Encrypted at rest (AWS RDS encryption, or LUKS for self-hosted)
- Automated backups: encrypted, tested, off-site
- No plaintext secrets in DB: JWT signing key in HSM or env var, not DB

### 5.3 API Security

**Rate Limiting:**
| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /api/register | 5 | Per IP, per day |
| POST /api/login | 10 | Per IP, per hour |
| POST /api/share | 100 | Per user, per hour |
| POST /api/share/:id/retrieve | 200 | Per user, per hour |
| DELETE /api/share/:id | 50 | Per user, per hour |
| DELETE /api/account | 1 | Per user, per day |
| All other | 1000 | Per user, per hour |

**Email Domain Rate Limiting:**
| Domain Type | Limit | Window |
|-------------|-------|--------|
| Disposable (temp-mail, etc.) | 1 | Per domain, per day |
| Free (gmail, yahoo, etc.) | 20 | Per domain, per day |
| Custom / Corporate | 100 | Per domain, per day |

**Input Validation:**
- All request bodies: Pydantic v2 models with strict validation
- File uploads: size limits (max 100MB), MIME type validation
- SQL injection: ORM + parameterized queries only
- XSS prevention: Output encoding, no user input in HTML without sanitization

### 5.4 Audit Logging

**Log Everything:**
| Event | Data Logged |
|-------|-------------|
| Account registration | IP, timestamp, email_hash |
| Login success | IP, timestamp, user_id |
| Login failure | IP, timestamp, email_hash, reason |
| Share created | IP, timestamp, owner_key_hash, share_id, size |
| Share retrieved | IP, timestamp, recipient_key_hash, share_id |
| Share revoked | IP, timestamp, owner_key_hash, share_id |
| Account deleted | IP, timestamp, user_id |
| Logout | IP, timestamp, user_id |

**Log Storage:**
- Immutable: append-only, no deletion (compliance requirement)
- Retention: 7 years (HIPAA standard)
- Encryption: AES-256-GCM at rest
- Access: Role-based, dual-control for admin access
- Anonymization: After account deletion, strip email_hash from logs (replace with hash of hash)

---

## 6. Recovery and Disaster Scenarios

### 6.1 Lost Password (Layer 1)

**Flow:**
- There is no password reset.
- User must delete account and start over.

**UI Messaging:**
> "We do not store your password. If you forget it, you cannot access this account. Delete it and register a new one."

### 6.2 Lost Keyset File (Layer 2)

**Result:** Vault permanently locked. No server-side recovery possible.

**Recovery:**
- Delete account and start over with new keypair.
- Physical records are still with the patient (MedLedger is a conduit, not a vault).
- Old shares expire naturally (TTL) or are deleted with account.

**UI Messaging:**
> "Without your keyset file, you cannot decrypt shared data. We cannot recover it. Your physical records are safe. Delete this account and start over if needed."

### 6.3 Compromised Keyset File

**Scenario:** Attacker obtains keyset file + password.

**Impact:**
- Attacker can decrypt shares addressed to that public key
- Attacker can create new shares (sign with private key)
- Attacker cannot change account password (Layer 1 separate)

**Mitigation:**
1. User deletes account immediately
2. All shares are destroyed
3. User registers new account with new keypair
4. Re-shares necessary records with new public key

### 6.4 Server Compromise + Database Leak

**Immediate Actions:**
1. Rotate JWT signing keys (invalidate all sessions)
2. Force all users to re-authenticate (Layer 1)
3. Notify users: "No medical data was exposed. Ciphertext is secure without your keyset file."
4. Keyset re-creation recommended but not mandatory (ciphertext still secure)
5. Audit log analysis: what did attacker access?

**Communication:**
- Transparent: "We detected unauthorized access. Your encrypted data was not compromised."
- Actionable: "As a precaution, consider deleting your account and re-registering with a new keyset."
- No false reassurance: "We cannot decrypt your data, but an attacker with your keyset file could."

---

## 7. Compliance Posture

### 7.1 HIPAA (Health Insurance Portability and Accountability Act)

**MedLedger as Business Associate:**
- We store encrypted PHI (Protected Health Information) temporarily
- We cannot decrypt it (zero-knowledge)
- We are a "conduit" rather than "data processor"
- Patient is the data controller

**Required Safeguards:**
| HIPAA Rule | MedLedger Implementation |
|------------|-------------------------|
| Access Control (164.312(a)) | Two-layer auth, role-based access, audit logs |
| Audit Controls (164.312(b)) | Immutable audit log, 7-year retention |
| Integrity (164.312(c)) | AES-256-GCM authentication tag, ECDSA signatures |
| Transmission Security (164.312(e)) | TLS 1.3, certificate pinning |
| Breach Notification (164.404) | 72-hour notification, encrypted data = not reportable |

**Breach Assessment:**
- If encrypted data is stolen but keys are not: **Not a reportable breach** (HIPAA Safe Harbor for encryption)
- If keyset files are also stolen: **Reportable** (attacker can decrypt)
- Our architecture maximizes the "not reportable" scenario

### 7.2 GDPR (General Data Protection Regulation)

**Data Minimization:**
- We store only what is necessary: public key hashes, ciphertext, metadata
- No plaintext medical data on server
- User can delete account → delete all shares, anonymize audit logs

**Right to Erasure:**
- Account deletion: immediate, absolute
- Ciphertext deletion: immediate
- Audit logs: retained for 7 years (legal obligation override), anonymized after 7 years

**Right to Portability:**
- User can download their keyset file (encrypted private key)
- User can download their share metadata (no ciphertext without keyset)
- No lock-in: open algorithms, patient holds physical records

### 7.3 SOC 2 Type II (Future)

**Controls:**
- Access control: Role-based, MFA for admin
- Change management: Code review, CI/CD, signed commits
- Monitoring: Intrusion detection, anomaly alerting
- Incident response: 24-hour response SLA, documented playbooks

---

## 8. Security Checklist (Pre-Production)

### 8.1 Code Review

- [ ] No `console.log` with sensitive data (keys, passwords, tokens)
- [ ] No `localStorage` usage for keys or tokens
- [ ] No `eval()` or `Function()` constructor
- [ ] All API calls use HTTPS (no `http://` anywhere)
- [ ] JWT stored in HttpOnly cookie, not `localStorage`
- [ ] Private key never serialized to JSON/string except encrypted form
- [ ] All crypto operations use Web Crypto API, not JavaScript libraries
- [ ] ECIES implementation matches test vectors
- [ ] Argon2id parameters meet OWASP 2023 recommendations
- [ ] PBKDF2 iterations ≥ 310,000
- [ ] PoW difficulty = 20, verified server-side
- [ ] CAPTCHA token single-use, verified server-side

### 8.2 Infrastructure

- [ ] TLS 1.3 enabled, TLS 1.2 minimum
- [ ] HSTS header with preload
- [ ] CSP deployed and tested (report-uri for monitoring)
- [ ] Rate limiting active on all endpoints
- [ ] Database SSL/TLS with certificate verification
- [ ] JWT signing key in HSM or secure vault (not in code or env)
- [ ] Database backups encrypted, tested, off-site
- [ ] Logging centralized, immutable, monitored

### 8.3 Testing

- [ ] Penetration test: external firm, annual
- [ ] Bug bounty program: HackerOne or similar
- [ ] Automated security scanning: Snyk, Dependabot, OWASP ZAP
- [ ] Fuzz testing: API endpoints with malformed input
- [ ] Cryptographic test vectors: ECIES encrypt/decrypt round-trip, signature verify
- [ ] PoW test: verify difficulty, reject replay, reject invalid
- [ ] Disaster recovery test: restore from backup, verify no plaintext exposure

### 8.4 Documentation

- [ ] Security spec complete and reviewed
- [ ] Incident response playbook written
- [ ] User-facing security guide (how to protect your keyset)
- [ ] Admin security guide (how to handle compromise)
- [ ] Third-party audit report (annual)

---

## 9. Invariants (Non-Negotiable)

1. **Private keys never leave the browser.** Not in cookies, not in storage, not in logs.
2. **Server stores only public material and ciphertext.** Public key hashes, ciphertext, encrypted DEK bundles, signatures.
3. **We cannot decrypt medical data.** Mathematical guarantee, not policy.
4. **Every share is cryptographically targeted.** DEK is ECIES-wrapped for a specific recipient public key.
5. **DEKs are always ECIES-wrapped.** Plaintext DEK never exists server-side.
6. **No account recovery.** Lost email, password, or keyset = delete account and start over. We cannot help.
7. **Email is anti-spam only.** Verified for filtering, not for recovery. Disposable emails allowed.
8. **All shares have TTL.** Maximum 90 days, default 30 days. After expiry, server deletes.
9. **Account deletion is absolute.** Hard delete all shares, anonymize audit logs.
10. **Audit everything.** Every share, every retrieve, every registration logged.
11. **Honest UI.** "We cannot recover your keyset. We cannot read your data. We are not a storage company."

---

*Document: 02-SECURITY_SPEC.md | Author: Premananda (Team Praxis) | Status: Draft v1.0*
*Review required before any implementation begins.*
