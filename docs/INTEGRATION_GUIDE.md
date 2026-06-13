# MedLedger UI — Integration Guide
## Wiring auth/ to key_manager/

**Version:** 1.0 | **Date:** June 2026 | **Status:** Implementation Bridge

---

## 1. The Problem

You have two working systems that don't talk to each other:

| System | Produces | Consumes |
|--------|----------|----------|
| `auth/` | A user record with username, email, password hash, TOTP secret | Nothing cryptographic |
| `key_manager/` | Ed25519/X25519 keypairs, encrypted shares, signatures | A username and a keypair |

**The gap:** After a user registers via `authFlow.createAccount()`, they have no cryptographic identity. They cannot encrypt files, create shares, or verify signatures because `key_manager/` was never invoked.

**The solution:** A thin binding layer that calls `KeysetManager.createUser()` immediately after successful account creation, persists the public keys server-side, and prompts the user to save their private keypair.

---

## 2. Integration Points

### 2.1 Registration Flow (New)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REGISTRATION FLOW (INTEGRATED)                      │
│                                                                             │
│  Step 1: CAPTCHA (Turnstile) ──► Step 2: PoW (SHA-256, diff 20)            │
│         │                         │                                         │
│         ▼                         ▼                                         │
│  Step 3: Email (rate-limiting only, no verification)                       │
│         │                                                                   │
│         ▼                                                                   │
│  Step 4: Username + Password (Argon2id) ──► authFlow.createAccount()      │
│         │                         │                                         │
│         │                         ▼                                         │
│         │              ┌─────────────────────┐                              │
│         │              │ KeysetManager.      │                              │
│         │              │ createUser(username)  │                              │
│         │              │ ──► Ed25519 + X25519 │                              │
│         │              │     keypair generated │                              │
│         │              └─────────────────────┘                              │
│         │                         │                                         │
│         ▼                         ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ CRITICAL: User must save private keypair NOW                       │    │
│  │                                                                      │    │
│  │  Download: {                                                          │    │
│  │    username,                                                          │    │
│  │    signingPublicKey,   // base64url                                   │    │
│  │    exchangePublicKey,  // base64url                                   │    │
│  │    userIdHex,          // 32-char hex                                 │    │
│  │    signingPrivateKey,  // base64url — SAVE THIS                       │    │
│  │    exchangePrivateKey   // base64url — SAVE THIS                      │    │
│  │  }                                                                    │    │
│  │                                                                      │    │
│  │  File: alice.medledger-key.json                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│         │                                                                   │
│         ▼                                                                   │
│  POST /api/register ──► Server stores:                                    │
│    { username, email_hash, password_hash(Argon2id),                        │
│      signingPublicKey, exchangePublicKey, userIdHex }                      │
│                                                                             │
│  Server does NOT store: signingPrivateKey, exchangePrivateKey              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Code: Registration Bridge

Create `shared/registerBridge.js`:

```javascript
// shared/registerBridge.js
import { KeysetManager } from '../key_manager/key_manager.js';
import { authFlow } from '../auth/orchestrator/authFlow.js';

/**
 * Full registration: auth + crypto key generation
 * @param {string} email - For rate-limiting (not verification)
 * @param {string} username - Becomes crypto identity
 * @param {string} password - Used for Argon2id (not PBKDF2)
 * @param {string} powChallengeId - From authFlow.initPOW()
 * @param {string} powNonce - Client-computed solution
 * @returns {Promise<{authResult, keypairResult}>}
 */
export async function registerUser(email, username, password, powChallengeId, powNonce) {
  // Step 1: Verify PoW (anti-spam gate)
  const powResult = authFlow.verifyPOW(powChallengeId, powNonce);
  if (!powResult.data.sessionToken) {
    throw new Error('PoW verification failed');
  }
  const sessionToken = powResult.data.sessionToken;

  // Step 2: Create auth account (Layer 1)
  // NOTE: This uses your existing authFlow, but you should replace
  // PBKDF2 with Argon2id in user.js before production
  const authResult = await authFlow.createAccount(sessionToken, username, password);
  if (authResult.step !== 'account_created') {
    throw new Error(`Account creation failed: ${authResult.data.message}`);
  }

  // Step 3: Initialize crypto layer
  await KeysetManager.init();

  // Step 4: Generate keypair (Layer 2)
  const keypairResult = await KeysetManager.createUser(username);

  // Step 5: Prompt user to save keypair — THIS IS CRITICAL
  // The private keys are only available here. If not saved, account
  // is unusable for crypto operations and cannot be recovered.
  const keypairFile = {
    version: 'medledger-keypair-v1',
    username: keypairResult.username,
    userIdHex: keypairResult.userIdHex,
    signingPublicKey: keypairResult.signingPublicKey,
    exchangePublicKey: keypairResult.exchangePublicKey,
    signingPrivateKey: sodium.to_base64(
      keypairResult.signingPrivateKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    exchangePrivateKey: sodium.to_base64(
      keypairResult.exchangePrivateKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    createdAt: new Date().toISOString(),
  };

  // Trigger browser download
  const blob = new Blob([JSON.stringify(keypairFile, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${username}.medledger-key.json`;
  a.click();
  URL.revokeObjectURL(url);

  // Step 6: Send public keys to server
  // Server stores these alongside the auth user record
  await api.registerPublicKeys({
    username: keypairResult.username,
    userIdHex: keypairResult.userIdHex,
    signingPublicKey: keypairResult.signingPublicKey,
    exchangePublicKey: keypairResult.exchangePublicKey,
  });

  // Step 7: Wipe private keys from memory (user has file copy)
  // KeysetManager already holds them in session, but we clear
  // the temporary keypairFile object
  keypairFile.signingPrivateKey = null;
  keypairFile.exchangePrivateKey = null;

  return {
    authResult: authResult.data,      // { userId, username }
    keypairResult: {                   // Public keys only
      username: keypairResult.username,
      userIdHex: keypairResult.userIdHex,
      signingPublicKey: keypairResult.signingPublicKey,
      exchangePublicKey: keypairResult.exchangePublicKey,
    },
    keypairSaved: true,  // User was prompted to download
  };
}
```

### 2.3 Login Flow (New)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LOGIN FLOW (INTEGRATED)                             │
│                                                                             │
│  POST /api/login                                                            │
│  Body: { username, password }                                               │
│                                                                             │
│  Server:                                                                    │
│    1. Find user by username (case-insensitive)                              │
│    2. Argon2id.verify(password, stored_hash)                                │
│    3. If valid: issue JWT (HttpOnly, SameSite=Lax, 15 min)                 │
│    4. Issue refresh_token (HttpOnly, SameSite=Strict, 7 days)             │
│                                                                             │
│  Response: 200 OK + Set-Cookie headers                                      │
│  Body: { userIdHex, username, publicKeys: { signing, exchange } }           │
│                                                                             │
│  ──► Browser: Dashboard shows "Vault Locked"                               │
│                                                                             │
│  User clicks "Unlock Vault"                                                │
│  ──► Prompt: Upload your .medledger-key.json file                         │
│                                                                             │
│  Browser reads file → extracts keypair → calls KeysetManager.loginUser()   │
│                                                                             │
│  KeysetManager.loginUser(username, keypair):                                │
│    1. Validates keypair format (both keys present, correct lengths)         │
│    2. Derives userIdHex from signingPublicKey                              │
│    3. Verifies userIdHex matches server response                           │
│    4. Stores private keys in memory (session unlocked)                    │
│                                                                             │
│  ──► Dashboard shows "Vault Unlocked"                                      │
│      Share / decrypt operations now available                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.4 Code: Login Bridge

Create `shared/loginBridge.js`:

```javascript
// shared/loginBridge.js
import { KeysetManager, KeysetError, ERRORS } from '../key_manager/key_manager.js';

/**
 * Unlock crypto session after auth login
 * @param {string} username - From auth login
 * @param {File} keypairFile - User's .medledger-key.json file
 * @param {object} serverPublicKeys - From /api/me response
 * @returns {Promise<{unlocked, publicKeys}>}
 */
export async function unlockVault(username, keypairFile, serverPublicKeys) {
  // Step 1: Read and parse keypair file
  const text = await keypairFile.text();
  const keypairData = JSON.parse(text);

  // Step 2: Validate file structure
  if (keypairData.version !== 'medledger-keypair-v1') {
    throw new Error('Unsupported keypair file version');
  }
  if (keypairData.username.toLowerCase() !== username.toLowerCase()) {
    throw new Error('Keypair file does not match logged-in user');
  }

  // Step 3: Reconstruct keypair for KeysetManager
  const keypair = {
    signing: {
      publicKey: sodium.from_base64(
        keypairData.signingPublicKey,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
      privateKey: sodium.from_base64(
        keypairData.signingPrivateKey,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
    },
    exchange: {
      publicKey: sodium.from_base64(
        keypairData.exchangePublicKey,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
      privateKey: sodium.from_base64(
        keypairData.exchangePrivateKey,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
    },
  };

  // Step 4: Initialize and unlock
  await KeysetManager.init();
  const sessionKeys = await KeysetManager.loginUser(username, keypair);

  // Step 5: Verify server-side public keys match
  if (sessionKeys.signingPublicKey !== serverPublicKeys.signingPublicKey) {
    KeysetManager.logoutUser();
    throw new Error('Keypair mismatch: possible tampering or wrong file');
  }

  return {
    unlocked: true,
    publicKeys: sessionKeys,
  };
}

/**
 * Lock vault (clear private keys from memory)
 * Keep JWT cookie active (Layer 1 still valid)
 */
export function lockVault() {
  KeysetManager.logoutUser();
  return { locked: true };
}

/**
 * Full logout (clear both layers)
 */
export async function fullLogout() {
  lockVault();
  await api.logout();  // Clears JWT cookies server-side
  return { loggedOut: true };
}
```

---

## 3. Server-Side Changes Required

### 3.1 User Record Schema (Updated)

Your current `data/users.json` stores:
```json
{
  "userId": "<32-char hex>",
  "username": "alice",
  "email": "alice@example.com",
  "passwordHash": "<128-char hex>",
  "salt": "<32-char hex>",
  "totpEnabled": true,
  "verified": true
}
```

Target schema (add public keys, remove TOTP):
```json
{
  "userId": "<32-char hex>",
  "username": "alice",
  "email": "alice@example.com",
  "emailHash": "<64-char hex>",
  "passwordHash": "<Argon2id MCF string>",
  "signingPublicKey": "<base64url>",
  "exchangePublicKey": "<base64url>",
  "userIdHex": "<32-char hex>",
  "createdAt": 1700000000000,
  "lastLogin": 1700000000000
}
```

### 3.2 New API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register/keys` | Bearer (fresh JWT) | Store public keys after registration |
| GET | `/api/me` | Bearer | Return user profile + public keys |
| POST | `/api/keys/verify` | Bearer + Keyset | Verify keypair matches stored public keys |

### 3.3 Storage Module Update

Add to `auth/modules/storage.js`:

```javascript
// Add to storage.js
savePublicKeys(username, { signingPublicKey, exchangePublicKey, userIdHex }) {
  const user = this.getUserByUsername(username);
  if (!user) return false;
  user.signingPublicKey = signingPublicKey;
  user.exchangePublicKey = exchangePublicKey;
  user.userIdHex = userIdHex;
  this._save();
  return true;
}

getPublicKeys(username) {
  const user = this.getUserByUsername(username);
  if (!user) return null;
  return {
    signingPublicKey: user.signingPublicKey,
    exchangePublicKey: user.exchangePublicKey,
    userIdHex: user.userIdHex,
  };
}
```

---

## 4. React Integration Example

```jsx
// App.jsx — Root component
import { useState, useEffect } from 'react';
import { useAuth } from './hooks/useAuth';
import { useKeyset } from './hooks/useKeyset';
import { LoginForm } from './components/LoginForm';
import { VaultUnlock } from './components/VaultUnlock';
import { Dashboard } from './components/Dashboard';

export function App() {
  const { user, login: authLogin, logout: authLogout } = useAuth();
  const { locked, publicKeys, login: keyLogin, logout: keyLogout } = useKeyset();

  const handleLogin = async (username, password) => {
    // Layer 1: Auth
    const authResult = await authLogin(username, password);
    // Fetch public keys from server
    const serverKeys = await api.getPublicKeys(username);
    // Layer 2: Prompt for keypair (handled by VaultUnlock component)
    return { authResult, serverKeys };
  };

  const handleUnlock = async (keypairFile) => {
    const result = await keyLogin(user.username, keypairFile, user.publicKeys);
    return result;
  };

  const handleLogout = () => {
    keyLogout();  // Clear crypto keys
    authLogout(); // Clear JWT
  };

  if (!user) return <LoginForm onLogin={handleLogin} />;
  if (locked) return <VaultUnlock onUnlock={handleUnlock} username={user.username} />;
  return <Dashboard user={user} publicKeys={publicKeys} onLogout={handleLogout} />;
}
```

---

## 5. Critical Security Notes

### 5.1 The Keypair File Is Everything

Without the `.medledger-key.json` file, the user cannot:
- Decrypt received shares
- Create new shares (no signing key)
- Prove their identity cryptographically

**UI messaging must be explicit:**
> "This file is your only key to encrypted data. We cannot recover it. Save it like a password manager or hardware wallet backup."

### 5.2 Never Store Private Keys Server-Side

Your server must store **only**:
- `signingPublicKey` (32 bytes, base64url)
- `exchangePublicKey` (32 bytes, base64url)
- `userIdHex` (16 bytes, hex)

Never store or log:
- `signingPrivateKey` (64 bytes)
- `exchangePrivateKey` (32 bytes)
- The full keypair file contents

### 5.3 Password vs. Keypair Separation

| Layer | Credential | Purpose | Compromise Impact |
|-------|-----------|---------|-----------------|
| 1 (Auth) | Password | Login, account management | Attacker can see metadata, delete shares, but **cannot decrypt** |
| 2 (Crypto) | Keypair file | Encrypt, decrypt, sign | Attacker can decrypt all shares, forge new ones |

If keypair is compromised: **User must delete account and re-register with new keypair.**

---

## 6. Testing the Integration

```javascript
// tests/integrationTest.js
import { registerUser } from '../shared/registerBridge.js';
import { unlockVault } from '../shared/loginBridge.js';
import { KeysetManager } from '../key_manager/key_manager.js';

describe('Auth + Key Manager Integration', () => {
  test('full registration creates both auth user and keypair', async () => {
    const result = await registerUser(
      'test@example.com',
      'testuser',
      'SecureP@ss123',
      challengeId,
      nonce
    );

    expect(result.authResult.username).toBe('testuser');
    expect(result.keypairResult.userIdHex).toHaveLength(32);
    expect(result.keypairResult.signingPublicKey).toBeTruthy();
    expect(result.keypairSaved).toBe(true);
  });

  test('unlock vault with saved keypair file', async () => {
    // Simulate user uploading their saved file
    const keypairFile = new File(
      [JSON.stringify(savedKeypair)],
      'testuser.medledger-key.json',
      { type: 'application/json' }
    );

    const serverKeys = await api.getPublicKeys('testuser');
    const result = await unlockVault('testuser', keypairFile, serverKeys);

    expect(result.unlocked).toBe(true);
    expect(KeysetManager.isLocked()).toBe(false);
  });

  test('wrong keypair file fails verification', async () => {
    const wrongFile = new File(
      [JSON.stringify(attackerKeypair)],
      'attacker.medledger-key.json',
      { type: 'application/json' }
    );

    await expect(
      unlockVault('testuser', wrongFile, serverKeys)
    ).rejects.toThrow('Keypair mismatch');
  });
});
```

---

*Integration Guide v1.0 | MedLedger UI | June 2026*
