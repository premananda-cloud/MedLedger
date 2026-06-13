# MedLedger Security Specification

**Version:** 2.0 | **Date:** June 2026 | **Status:** Draft — Foundation Document

**WARNING:** This document defines what "secure" means for MedLedger. Any implementation that violates these specifications is considered broken, regardless of whether it functions correctly.

**Scope:** This document covers the integrated system (auth/ + key_manager/ + shared/). The auth domain has known limitations that are documented and scheduled for remediation.

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
| **Private keys** | Confidentiality | Everyone (including server) |
| **Share permissions** | Integrity + Non-repudiation | Forgery, replay |
| **User credentials** | Confidentiality | External attackers, insiders |
| **Audit logs** | Integrity | Tampering, deletion |
| **Service availability** | Availability | Spam, DDoS, resource exhaustion |

### 1.3 Threat Scenarios

#### Scenario A: Database Breach

**Attacker gains:** `users` table (password hashes, emails, public key hashes), `active_shares` (ciphertext, sealed DEK bundles), `audit_log` (anonymized actions).

**Attacker cannot:**
- Decrypt medical records (no DEK, no private key)
- Derive private keys from public keys (Ed25519/X25519 security)
- Forge shares (no owner private key, Ed25519 verification fails)
- Impersonate users (PBKDF2/Argon2id password hashes, no plaintext passwords)
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
- Access `Uint8Array` key material in memory (if script runs in same origin — mitigated by strict CSP)

**Mitigation:**
- JWT in HttpOnly cookie (not accessible to JS)
- Private keys in module memory only (not in storage APIs)
- Strict CSP: `default-src 'self'; script-src 'self'`
- Subresource Integrity (SRI) on all CDN scripts
- No `eval()`, no inline scripts

#### Scenario D: Lost Keypair File

**User loses:** `alice.medledger-key.json` file.

**Result:**
- Account still accessible (Layer 1: username + password)
- Vault permanently locked (Layer 2: no private key)
- Medical records still held by patient physically (MedLedger is a conduit, not a vault)
- Old shares irretrievable (server deletes them anyway after TTL)

**Recovery:**
- **Delete account and start over.** Generate new keypair, re-upload records, re-share.
- No Shamir recovery in v1.0. No cloud backup. No paper backup.

**UI Messaging:**
- Clear, honest, no false hope: "Without your keypair file, you cannot decrypt shared data. We cannot recover it. Your physical records are safe. Delete this account and start over if needed."
- Proactive: "Save your keypair file like a passport."

#### Scenario E: Password Compromise

**Attacker gains:** User's Layer 1 password.

**Attacker can:**
- Log into account (impersonate user)
- See metadata (share history, file names, recipient public key hashes)
- Delete shares (availability attack)
- Delete account (availability attack)

**Attacker cannot:**
- Decrypt shared files (private key needed, held in keypair file)
- Create valid shares (private key needed)
- Access keypair without keypair file

**Mitigation:** Two-layer security. Password alone is insufficient for data access.

#### Scenario F: Nation State Compulsion

**Actor demands:** Decrypt user medical records.

**Our response:** Mathematically impossible. We do not possess:
- User's private key (never transmitted)
- User's keypair file (client-side only)
- DEK plaintext (always sealed with crypto_box_seal)
- Plaintext medical records (never on server)

**What we can provide:**
- Ciphertext (useless without key)
- Public key hashes (already public)
- Password hashes (useless without password)
- Audit logs (anonymized after account deletion)

**Legal posture:** We are a sharing conduit, not a data processor. Patient is the data controller. We store encrypted data we cannot read, for a limited time, at the patient's direction.

#### Scenario G: Spam / Bot Attack

**Attacker floods:** Registration endpoint with fake accounts.

**Mitigation layers:**
1. **CAPTCHA** (Turnstile): Human verification, privacy-preserving
2. **Proof-of-work** (SHA-256, 2^20 iterations): ~1 second CPU cost per registration
3. **Rate limiting**: 5 per IP per day, 20 per email domain per day
4. **Email**: Used for rate-limiting, not verification — disposable emails allowed

**Result:** Spam is economically unviable. Legitimate users experience ~1 second delay.

---

## 2. Cryptographic Specifications

### 2.1 Algorithm Registry

| Purpose | Algorithm | Parameters | Library | Status |
|---------|-----------|------------|---------|--------|
| Signing keypair | Ed25519 | 32-byte seed → 64-byte private, 32-byte public | libsodium.js | **Active** |
| Encryption keypair | X25519 | 32-byte seed → 32-byte private, 32-byte public | libsodium.js | **Active** |
| Key exchange | X25519 ECDH | Sealed boxes (ephemeral + static) | libsodium.js | **Active** |
| Symmetric file encryption | XSalsa20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte tag | libsodium.js | **Active** |
| Sealed-box encryption | X25519 + XSalsa20-Poly1305 | crypto_box_seal | libsodium.js | **Active** |
| Grant signing | Ed25519 | 64-byte signature | libsodium.js | **Active** |
| Content hashing | BLAKE2b | 256-bit output | libsodium.js | **Active** |
| Identity hashing | BLAKE2b | 128-bit output (user_id) | libsodium.js | **Active** |
| Password hashing (server) | PBKDF2-SHA512 | 600,000 iterations, 64-byte key | Node crypto | **Current — migrate to Argon2id** |
| CSPRNG | randombytes_buf | — | libsodium.js | **Active** |
| Proof-of-work | SHA-256 | 2^20 iterations (1,048,576) | Node crypto | **Target: increase from current 2^4** |

### 2.2 Key Hierarchy

```
User Keypair File (.medledger-key.json)
    │
    ├──► Ed25519 signing keypair
    │         │
    │         ├──► Sign share grants (create_share payload)
    │         ├──► Sign share retrievals (retrieve_share payload)
    │         └──► Identity: user_id_hex = BLAKE2b-128(publicKey)
    │
    └──► X25519 exchange keypair
              │
              ├──► Seal DEK for recipient (crypto_box_seal)
              ├──► Open sealed DEK as recipient (crypto_box_seal_open)
              └──► Derive shared secret for ECIES-like operations

File Encryption (per share):
    │
    ├──► Random 256-bit DEK (generated per share)
    │         │
    │         ├──► XSalsa20-Poly1305 encrypt file → ciphertext + nonce
    │         └──► crypto_box_seal(DEK, recipientExchangePublicKey) → dek_bundle
    │
    └──► DEK wiped from memory after encryption (sodium.memzero)
```

### 2.3 Sealed Box Implementation (Browser)

**Encryption (Browser):**
1. Generate random 32-byte DEK: `sodium.randombytes_buf(32)`
2. XSalsa20-Poly1305 encrypt file: `crypto_secretbox_easy(plaintext, nonce, dek)`
3. Seal DEK for recipient: `crypto_box_seal(dek, recipientPublicKey)`
4. Wipe DEK: `sodium.memzero(dek)`
5. Return: `{ ciphertext, nonce, dek_bundle, file_hash }`

**Decryption (Browser):**
1. Open sealed DEK: `crypto_box_seal_open(dek_bundle, publicKey, privateKey)`
2. Decrypt file: `crypto_secretbox_open_easy(ciphertext, nonce, dek)`
3. Wipe DEK: `sodium.memzero(dek)`
4. Return plaintext

**Forward Secrecy:** Each share uses a fresh random DEK. Compromise of the recipient's long-term private key exposes only shares addressed to that key (not past shares using different DEKs, since DEKs are random per share). However, all future shares to that key would be compromised — mitigated by account deletion and re-creation.

### 2.4 Proof-of-Work (Registration Anti-Spam)

**Current Implementation:**
- Difficulty: 4 leading zeros (2^4 = 16 iterations — **TOO WEAK**)
- Time cost: ~1 millisecond (insignificant)

**Target Implementation:**
- Difficulty: 20 leading zeros (2^20 ≈ 1,048,576 iterations)
- Time cost: ~1 second on modern desktop, ~3-5 seconds on mobile
- Nonce expiry: 5 minutes
- Rate limit: 5 registrations per IP per day, 20 per email domain per day

**Challenge:**
- Server provides: `nonce` (32-byte random), `difficulty` (default 20)
- Client must find: `solution` such that `SHA-256(nonce || solution)` has `difficulty` leading zero bits

**Verification:**
- Server computes `SHA-256(nonce || solution)` once
- Checks leading zero bits ≥ difficulty
- Rejects if nonce already used (replay prevention)

### 2.5 Password Hashing (Server-Side)

**Current (auth/modules/user.js):**
- Algorithm: PBKDF2-SHA512
- Iterations: 600,000
- Salt: 16 random bytes
- Key length: 64 bytes
- Status: **OWASP-compliant but inferior to Argon2id**

**Target:**
- Algorithm: Argon2id
- Memory: 64MB
- Iterations: 3
- Parallelism: 4
- Salt: 16 random bytes
- Format: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`

**Migration path:** See MIGRATION_PLAN.md Phase 2.

---

## 3. Authentication Specifications

### 3.1 Layer 1: Gate (Anti-Spam + Session)

**Current Implementation (auth/):**
- Password hashing: PBKDF2-SHA512, 600k iterations
- Session: Server-side Map with session tokens
- 2FA: TOTP with speakeasy
- Email verification: 6-digit code

**Target Implementation:**
- Password hashing: Argon2id
- Session: JWT in HttpOnly cookie + opaque refresh token
- 2FA: Keypair possession (no TOTP)
- Email: Rate-limiting only (no verification)

**JWT Specification (Target):**
| Property | Value |
|----------|-------|
| Algorithm | RS256 (asymmetric) or ES256 |
| Key | Server holds private key, public key published |
| Claims | `sub` (user_id), `user_id_hex`, `iat`, `exp`, `jti` |
| Expiry | 15 minutes (access token) |
| Refresh | 7 days (refresh token, rotation on use) |
| Storage | HttpOnly, SameSite=Strict, Secure cookie |

### 3.2 Layer 2: Keypair Unlock

Keypair is NOT authenticated via JWT. It is a **client-side state** that unlocks share operations.

**State Machine:**
```
User logs in (Layer 1) → JWT cookie set → Account accessible
                                    │
                                    ▼
                           Dashboard shows: "Vault Locked"
                                    │
                                    ▼
                           User uploads keypair file
                                    │
                                    ▼
                           Integration layer reconstructs keypair
                           KeysetManager.loginUser() validates
                           → Private keys in module memory only
                                    │
                                    ▼
                           Dashboard shows: "Vault Unlocked"
                           Share operations now available
```

**Session Binding:**
- JWT cookie authenticates the user (who)
- Keypair in memory authorizes share operations (what they can decrypt)
- If keypair is not loaded, share endpoints return 403: "Keypair required. Upload your keypair file."

**Memory Management:**
- Private keys held as `Uint8Array` in module closure (key_manager.js)
- On `window.beforeunload` or explicit logout: `sodium.memzero()` then null
- On page refresh: keypair must be re-uploaded (intentional — prevents accidental persistence)

### 3.3 Logout

**Full Logout:**
1. Clear JWT cookie (server sets expired cookie)
2. Clear refresh token from DB
3. Client-side: `KeysetManager.logoutUser()` — memzero private keys
4. Client-side: clear any keypair file from memory
5. Redirect to login page

**Vault-Only Lock:**
1. Client-side: `KeysetManager.logoutUser()` — memzero private keys
2. Dashboard returns to "Vault Locked" state
3. Account still logged in (JWT cookie valid)

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
- No external scripts except libsodium.js (loaded from `self` or SRI-verified CDN)
- No `eval()`, no `Function()`, no `setTimeout(string)`

### 4.2 Subresource Integrity (SRI)

If loading libsodium.js from CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/libsodium-wrappers-sumo@0.8.4/dist/modules-sumo/libsodium-sumo.min.js"
        integrity="sha384-..."
        crossorigin="anonymous"></script>
```

**Recommendation:** Bundle libsodium.js into your build instead of CDN to avoid SRI complexity.

### 4.3 HTTPS Requirements

- TLS 1.3 minimum (TLS 1.2 acceptable for older clients)
- HSTS: `max-age=31536000; includeSubDomains; preload`
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

---

## 5. Server Security

### 5.1 Password Storage

**Current:** PBKDF2-SHA512, 600k iterations, 16-byte random salt
**Target:** Argon2id, memory=64MB, iterations=3, parallelism=4

**Migration:** See MIGRATION_PLAN.md Phase 2.

### 5.2 Database Security

- PostgreSQL with SSL/TLS connection (verify-full mode)
- Connection pooling with prepared statements (prevent SQL injection)
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
- All request bodies: strict validation (Pydantic v2 or Joi)
- File uploads: size limits (max 100MB), MIME type validation
- SQL injection: ORM + parameterized queries only
- XSS prevention: Output encoding, no user input in HTML without sanitization

### 5.4 Audit Logging

**Log Everything:**
| Event | Data Logged |
|-------|-------------|
| Account registration | IP, timestamp, user_id_hex |
| Login success | IP, timestamp, user_id |
| Login failure | IP, timestamp, username_hash, reason |
| Share created | IP, timestamp, owner_id_hex, share_id, size |
| Share retrieved | IP, timestamp, grantee_id_hex, share_id |
| Share revoked | IP, timestamp, owner_id_hex, share_id |
| Account deleted | IP, timestamp, user_id_hex |
| Logout | IP, timestamp, user_id |

**Log Storage:**
- Immutable: append-only, no deletion (compliance requirement)
- Retention: 7 years (HIPAA standard)
- Encryption: AES-256-GCM at rest
- Access: Role-based, dual-control for admin access
- Anonymization: After account deletion, strip user_id_hex from logs (replace with hash of hash)

---

## 6. Recovery and Disaster Scenarios

### 6.1 Lost Password (Layer 1)

**Flow:**
- There is no password reset.
- User must delete account and start over.

**UI Messaging:**
> "We do not store your password. If you forget it, you cannot access this account. Delete it and register a new one."

### 6.2 Lost Keypair File (Layer 2)

**Result:** Vault permanently locked. No server-side recovery possible.

**Recovery:**
- Delete account and start over with new keypair.
- Physical records are still with the patient (MedLedger is a conduit, not a vault).
- Old shares expire naturally (TTL) or are deleted with account.

**UI Messaging:**
> "Without your keypair file, you cannot decrypt shared data. We cannot recover it. Your physical records are safe. Delete this account and start over if needed."

### 6.3 Compromised Keypair File

**Scenario:** Attacker obtains keypair file.

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
3. Notify users: "No medical data was exposed. Ciphertext is secure without your keypair file."
4. Keypair re-creation recommended but not mandatory (ciphertext still secure)
5. Audit log analysis: what did attacker access?

**Communication:**
- Transparent: "We detected unauthorized access. Your encrypted data was not compromised."
- Actionable: "As a precaution, consider deleting your account and re-registering with a new keypair."
- No false reassurance: "We cannot decrypt your data, but an attacker with your keypair file could."

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
| Integrity (164.312(c)) | XSalsa20-Poly1305 authentication tag, Ed25519 signatures |
| Transmission Security (164.312(e)) | TLS 1.3, certificate pinning |
| Breach Notification (164.404) | 72-hour notification, encrypted data = not reportable |

**Breach Assessment:**
- If encrypted data is stolen but keys are not: **Not a reportable breach** (HIPAA Safe Harbor for encryption)
- If keypair files are also stolen: **Reportable** (attacker can decrypt)
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
- User can download their keypair file (contains private keys)
- User can download their share metadata (no ciphertext without keypair)
- No lock-in: open algorithms (Ed25519, X25519, XSalsa20), patient holds physical records

---

## 8. Security Checklist (Pre-Production)

### 8.1 Code Review

- [ ] No `console.log` with sensitive data (keys, passwords, tokens)
- [ ] No `localStorage` usage for keys or tokens
- [ ] No `eval()` or `Function()` constructor
- [ ] All API calls use HTTPS (no `http://` anywhere)
- [ ] JWT stored in HttpOnly cookie, not `localStorage`
- [ ] Private key never serialized to JSON/string except in keypair file
- [ ] All crypto operations use libsodium.js, not custom implementations
- [ ] Sealed box implementation matches test vectors
- [ ] Argon2id parameters meet OWASP 2023 recommendations (when migrated)
- [ ] PoW difficulty = 20, verified server-side (when migrated)
- [ ] CAPTCHA token single-use, verified server-side (when migrated)
- [ ] `sodium.memzero()` called on all private material after use
- [ ] `sodium.memzero()` in `finally` blocks for decryption failures

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
- [ ] Cryptographic test vectors: sealed box round-trip, signature verify
- [ ] PoW test: verify difficulty, reject replay, reject invalid
- [ ] Disaster recovery test: restore from backup, verify no plaintext exposure

### 8.4 Documentation

- [ ] Security spec complete and reviewed (this document)
- [ ] Incident response playbook written
- [ ] User-facing security guide (how to protect your keypair)
- [ ] Admin security guide (how to handle compromise)
- [ ] Third-party audit report (annual)

---

## 9. Known Limitations (Current Code)

| Issue | Location | Severity | Remediation |
|-------|----------|----------|-------------|
| PBKDF2 instead of Argon2id | auth/modules/user.js | Medium | Phase 2 of migration |
| PoW difficulty 4 (too weak) | auth/modules/pow.js | High | Phase 2: increase to 20 |
| TOTP creates recovery vector | auth/modules/totp.js | Medium | Phase 2: remove TOTP |
| Email verification code | auth/modules/email.js | Low | Phase 2: remove verification |
| Server-side session map | auth/orchestrator/authFlow.js | Medium | Phase 2: JWT + cookies |
| No CAPTCHA | auth/modules/ | High | Phase 2: add Turnstile |
| Keypair file not encrypted | key_manager/key_manager.js | Medium | Future: password-encrypt private keys in file |
| No share API | Server | High | Phase 3: implement |
| No audit logging | Server | High | Phase 3: implement |

---

## 10. Invariants (Non-Negotiable)

1. **Private keys never leave the browser.** Not in cookies, not in storage, not in logs.
2. **Server stores only public material and ciphertext.** Public keys, ciphertext, sealed DEK bundles, signatures.
3. **We cannot decrypt medical data.** Mathematical guarantee, not policy.
4. **Every share is cryptographically targeted.** DEK is sealed for a specific recipient public key.
5. **DEKs are always sealed.** Plaintext DEK never exists server-side.
6. **No account recovery.** Lost email, password, or keypair = delete account and start over. We cannot help.
7. **Email is anti-spam only.** Used for rate-limiting, not for recovery. Disposable emails allowed.
8. **All shares have TTL.** Maximum 90 days, default 30 days. After expiry, server deletes.
9. **Account deletion is absolute.** Hard delete all shares, anonymize audit logs.
10. **Audit everything.** Every share, every retrieve, every registration logged.
11. **Honest UI.** "We cannot recover your keypair. We cannot read your data. We are not a storage company."

---

*Document: 02-SECURITY_SPEC.md | Author: Premananda (Team Praxis) | Status: Draft v2.0*
*Review required before any production deployment.*
