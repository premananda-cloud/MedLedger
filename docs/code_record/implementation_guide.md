# MedLedger UI — Missing Files Implementation Guide

**Date:** 2026-06-13  
**Covers:** `shared/loginBridge.js` · `shared/apiClient.js` · `components/VaultUnlock.jsx` · `components/KeypairDownload.jsx` · `components/VaultStatus.jsx`

---

## Table of Contents

1. [Project Context](#project-context)
2. [shared/loginBridge.js](#sharedloginbridgejs)
3. [shared/apiClient.js](#sharedapiclientjs)
4. [components/VaultUnlock.jsx](#componentsvaultunlockjsx)
5. [components/KeypairDownload.jsx](#componentskeypairdownloadjsx)
6. [components/VaultStatus.jsx](#componentsvaultstatusjsx)
7. [Integration Map](#integration-map)
8. [Security Checklist](#security-checklist)

---

## Project Context

The MedLedger frontend is a 46KB single-file vanilla JS application (`index.html`) with inline state management, API client, and rendering. The React components and hooks in this repo are scaffolding for a future migration. The files below bridge the gap between the existing crypto layer (`key_manager/`) and the auth layer (`auth/`), and provide the React UI components that will replace the inline HTML UI once the migration happens.

**What's already working:**
- `key_manager/` — 79 tests passing, full libsodium integration
- `auth/` — 6 bugs fixed, end-to-end test passes
- `index.html` — complete vanilla JS frontend with PoW → email → TOTP → account creation flow

**What was missing (now implemented):**
- `shared/loginBridge.js` — empty; needed for vault unlock
- `shared/apiClent.js` — empty and misspelled; duplicated inline in `index.html`
- `components/VaultUnlock.jsx` — had a `props` bug in functional component
- `components/KeypairDownload.jsx` — empty
- `components/VaultStatus.jsx` — empty

---

## shared/loginBridge.js

**Purpose:** Bridge between the user's saved `.medledger-key.json` file and the `KeysetManager` crypto layer. This is the only code path that ever loads private keys into memory after registration.

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| Validate everything | Version string, required fields, base64 decodability, key lengths |
| Never trust the server blindly | Optional `serverPublicKeys` parameter verifies server-recorded keys match the file |
| Wipe temporary copies | `sodium.memzero()` on decoded Uint8Arrays after `KeysetManager.loginUser()` copies them |
| Fail closed | Any validation error calls `KeysetManager.logoutUser()` before throwing |

### API Reference

#### `unlockVault(username, keypairFile, serverPublicKeys?)`

```js
import { unlockVault } from "./shared/loginBridge.js";

const result = await unlockVault("alice", keypairFile, {
  signingPublicKey:  "...",
  exchangePublicKey: "...",
});
// Returns: { publicKeys: { signing, exchange }, username, userIdHex }
```

**Validation steps (in order):**

1. **Structure check** — `keypairFile` must be an object with all 7 required fields
2. **Version check** — must be exactly `"medledger-keypair-v1"`
3. **Base64 decode** — both private and public keys decoded with `URLSAFE_NO_PADDING`
4. **Length check** — Ed25519: private 64 bytes, public 32 bytes; X25519: both 32 bytes
5. **KeysetManager login** — loads keys into module memory, session now unlocked
6. **Server verification** (optional) — if `serverPublicKeys` provided, compares both signing and exchange public keys; mismatch triggers immediate `logoutUser()` and throws `BAD_KEY_FORMAT`
7. **Memory wipe** — `sodium.memzero()` on the local decoded copies

**Error codes thrown:**

| Error | Code | When |
|-------|------|------|
| `KeysetError` | `ERRORS.BAD_KEY_FORMAT` | Missing field, bad version, bad base64, wrong length, server mismatch |
| `KeysetError` | `ERRORS.NOT_INITIALIZED` | `KeysetManager.init()` not called (caught internally) |

---

#### `lockVault()`

```js
import { lockVault } from "./shared/loginBridge.js";

lockVault(); // Synchronous. Wipes all private keys.
```

Calls `KeysetManager.logoutUser()`. Safe to call even if already locked. Use for:
- User clicks "Lock" or "Logout"
- `beforeunload` event handler
- Inactivity timeout (30 minutes recommended)

---

#### `isVaultUnlocked()`

```js
import { isVaultUnlocked } from "./shared/loginBridge.js";

const open = isVaultUnlocked(); // boolean
```

Convenience wrapper around `!KeysetManager.isLocked()`. No side effects.

---

#### `autoLockVault()`

```js
import { autoLockVault } from "./shared/loginBridge.js";

// Wire to a 30-minute inactivity timer
setTimeout(autoLockVault, 30 * 60 * 1000);
```

Idempotent lock. Checks `isLocked()` first to avoid redundant `memzero` calls.

---

#### `previewKeypair(keypairFile)`

```js
import { previewKeypair } from "./shared/loginBridge.js";

const preview = await previewKeypair(parsedJson);
// Returns: { valid: boolean, username?, userIdHex?, error? }
```

Lightweight validation without touching `KeysetManager`. Useful for:
- Pre-filling username in unlock modal
- Showing file metadata before user clicks "Unlock"
- Detecting corrupted files early

---

### Full Source

```js
// shared/loginBridge.js
import { KeysetManager, KeysetError, ERRORS } from "../key_manager/key_manager.js";
import { apiClient } from "./apiClient.js";

export async function unlockVault(username, keypairFile, serverPublicKeys = null) {
  if (!keypairFile || typeof keypairFile !== "object") {
    throw new KeysetError("Invalid keypair file: expected object", ERRORS.BAD_KEY_FORMAT);
  }

  const required = [
    "version", "username", "userIdHex",
    "signingPublicKey", "exchangePublicKey",
    "signingPrivateKey", "exchangePrivateKey"
  ];
  for (const field of required) {
    if (!(field in keypairFile)) {
      throw new KeysetError(`Missing field: ${field}`, ERRORS.BAD_KEY_FORMAT);
    }
  }

  if (keypairFile.version !== "medledger-keypair-v1") {
    throw new KeysetError(`Unsupported version: ${keypairFile.version}`, ERRORS.BAD_KEY_FORMAT);
  }

  const sodium = await import("libsodium-wrappers-sumo").then((m) => m.default);
  await sodium.ready;

  let signingPrivateKey, exchangePrivateKey, signingPublicKey, exchangePublicKey;
  try {
    signingPrivateKey = sodium.from_base64(keypairFile.signingPrivateKey, sodium.base64_variants.URLSAFE_NO_PADDING);
    exchangePrivateKey = sodium.from_base64(keypairFile.exchangePrivateKey, sodium.base64_variants.URLSAFE_NO_PADDING);
    signingPublicKey = sodium.from_base64(keypairFile.signingPublicKey, sodium.base64_variants.URLSAFE_NO_PADDING);
    exchangePublicKey = sodium.from_base64(keypairFile.exchangePublicKey, sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch (e) {
    throw new KeysetError("Failed to decode keys from base64", ERRORS.BAD_KEY_FORMAT);
  }

  if (signingPrivateKey.length !== 64 || signingPublicKey.length !== 32) {
    throw new KeysetError(`Invalid Ed25519 lengths`, ERRORS.BAD_KEY_FORMAT);
  }
  if (exchangePrivateKey.length !== 32 || exchangePublicKey.length !== 32) {
    throw new KeysetError(`Invalid X25519 lengths`, ERRORS.BAD_KEY_FORMAT);
  }

  const keypair = {
    signing:  { publicKey: signingPublicKey,  privateKey: signingPrivateKey },
    exchange: { publicKey: exchangePublicKey, privateKey: exchangePrivateKey },
  };

  await KeysetManager.init();
  const session = await KeysetManager.loginUser(username, keypair);

  if (serverPublicKeys) {
    if (serverPublicKeys.signingPublicKey !== session.signingPublicKey ||
        serverPublicKeys.exchangePublicKey !== session.exchangePublicKey) {
      KeysetManager.logoutUser();
      throw new KeysetError("Server keys mismatch — possible tampering", ERRORS.BAD_KEY_FORMAT);
    }
  }

  sodium.memzero(signingPrivateKey);
  sodium.memzero(exchangePrivateKey);

  return {
    publicKeys: { signing: session.signingPublicKey, exchange: session.exchangePublicKey },
    username: session.username,
    userIdHex: session.userIdHex,
  };
}

export function lockVault() {
  KeysetManager.logoutUser();
}

export function isVaultUnlocked() {
  return !KeysetManager.isLocked();
}

export function autoLockVault() {
  if (!KeysetManager.isLocked()) KeysetManager.logoutUser();
}

export async function previewKeypair(keypairFile) {
  try {
    if (!keypairFile || keypairFile.version !== "medledger-keypair-v1") {
      return { valid: false, error: "Invalid version" };
    }
    const required = ["username", "userIdHex", "signingPublicKey", "exchangePublicKey"];
    for (const f of required) {
      if (!(f in keypairFile)) return { valid: false, error: `Missing ${f}` };
    }
    return { valid: true, username: keypairFile.username, userIdHex: keypairFile.userIdHex };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}
```

---

## shared/apiClient.js

**Purpose:** Reusable HTTP client that replaces the inline `api` object scattered through `index.html`. Fixes the typo `apiClent.js` → `apiClient.js`.

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| One interface for all HTTP | `get`, `post`, `put`, `delete`, `upload` |
| CSRF protection | Auto-injects `X-CSRF-Token` from meta tag or cookie |
| Consistent error shape | All errors are `Error` objects with `.status`, `.data`, `.path` |
| Upload support | `upload()` uses native `FormData`, skips `Content-Type: application/json` |

### API Reference

#### `apiClient.get(path, params?)`

```js
const me = await apiClient.get("/api/me");
const shares = await apiClient.get("/api/shares", { limit: 10, offset: 0 });
```

Appends query string from `params` object automatically.

---

#### `apiClient.post(path, body)`

```js
const result = await apiClient.post("/api/login", { username, password });
```

Body is JSON-serialized. `Content-Type: application/json` is set automatically.

---

#### `apiClient.put(path, body)`

```js
await apiClient.put("/api/me/preferences", { theme: "dark" });
```

---

#### `apiClient.delete(path)`

```js
await apiClient.delete("/api/shares/abc123");
```

---

#### `apiClient.upload(path, formData)`

```js
const form = new FormData();
form.append("file", fileBlob);
form.append("metadata", JSON.stringify({ name: "scan.pdf" }));

const result = await apiClient.upload("/api/upload", form);
```

**Critical:** Does **not** set `Content-Type: application/json`. Lets the browser set the multipart boundary. CSRF token is still injected.

---

### Error Handling

All methods throw a standard `Error` on non-2xx responses:

```js
try {
  await apiClient.post("/api/login", { username, password });
} catch (err) {
  console.log(err.status);   // HTTP status code (e.g. 401)
  console.log(err.data);     // Parsed JSON error body
  console.log(err.path);     // "/api/login"
  console.log(err.message);  // Human-readable message
}
```

---

### Full Source

```js
// shared/apiClient.js
const BASE_URL = ""; // Set to API origin if different from frontend

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) return meta.content;
  const match = document.cookie.match(/csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function request(method, path, body = null, extraHeaders = {}) {
  const url = `${BASE_URL}${path}`;
  const headers = { "Accept": "application/json", "Content-Type": "application/json", ...extraHeaders };
  const csrf = getCsrfToken();
  if (csrf) headers["X-CSRF-Token"] = csrf;

  const opts = { method, headers, credentials: "same-origin" };
  if (body !== null) opts.body = JSON.stringify(body);

  const response = await fetch(url, opts);
  let data;
  const ct = response.headers.get("content-type") || "";
  if (ct.includes("application/json")) data = await response.json();
  else data = await response.text();

  if (!response.ok) {
    const error = new Error(data?.message || data || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    error.path = path;
    throw error;
  }
  return data;
}

export const apiClient = {
  get(path, params = null) {
    let url = path;
    if (params) url += `?${new URLSearchParams(params).toString()}`;
    return request("GET", url, null);
  },
  post(path, body) { return request("POST", path, body); },
  put(path, body) { return request("PUT", path, body); },
  delete(path) { return request("DELETE", path, null); },
  upload(path, formData) {
    const url = `${BASE_URL}${path}`;
    const headers = {};
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
    return fetch(url, { method: "POST", headers, body: formData, credentials: "same-origin" })
      .then(async (res) => {
        let data;
        const ct = res.headers.get("content-type") || "";
        if (ct.includes("application/json")) data = await res.json();
        else data = await res.text();
        if (!res.ok) {
          const err = new Error(data?.message || data || `HTTP ${res.status}`);
          err.status = res.status; err.data = data; throw err;
        }
        return data;
      });
  },
};

export default apiClient;
```

---

## components/VaultUnlock.jsx

**Purpose:** Modal for unlocking the crypto vault. Fixed the original `props` bug where a functional component referenced `props` without receiving it.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `onUnlock` | `function(result)` | Yes | Called with `{ publicKeys, username, userIdHex }` on success |
| `onCancel` | `function()` | Yes | Called when user clicks Cancel or dismisses |
| `serverPublicKeys` | `{ signingPublicKey, exchangePublicKey }` | No | Optional server-side keys for anti-tamper verification |

### State & UX

| State | Behavior |
|-------|----------|
| Username input | Auto-filled from keypair file if empty and file contains username |
| File drop zone | Supports drag-and-drop and click-to-browse; accepts `.json` and `application/json` |
| Validation | `previewKeypair()` runs on file select; immediate feedback for corrupted files |
| Error display | `KeysetError` codes mapped to human-friendly messages |
| Loading | Buttons disabled during unlock; primary button shows "Unlocking…" |

### Full Source

```jsx
// components/VaultUnlock.jsx
import { useState, useRef } from "react";
import { unlockVault, previewKeypair } from "../shared/loginBridge.js";
import { KeysetError, ERRORS } from "../key_manager/key_manager.js";

export default function VaultUnlock({ onUnlock, onCancel, serverPublicKeys }) {
  const [username, setUsername] = useState("");
  const [keypairFile, setKeypairFile] = useState(null);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileSelect = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setError(""); setFileName(file.name);
    try {
      const parsed = JSON.parse(await file.text());
      const preview = await previewKeypair(parsed);
      if (!preview.valid) { setError(`Invalid keypair: ${preview.error}`); setKeypairFile(null); return; }
      if (preview.username && !username) setUsername(preview.username);
      setKeypairFile(parsed);
    } catch { setError("Failed to read keypair file."); setKeypairFile(null); }
  };

  const handleUnlock = async () => {
    if (!username.trim()) { setError("Enter your username."); return; }
    if (!keypairFile) { setError("Select your .medledger-key.json file."); return; }
    setError(""); setLoading(true);
    try {
      const result = await unlockVault(username.trim(), keypairFile, serverPublicKeys);
      onUnlock(result);
    } catch (err) {
      if (err instanceof KeysetError) {
        switch (err.code) {
          case ERRORS.BAD_KEY_FORMAT: setError("Keypair corrupted or does not match account."); break;
          case ERRORS.SESSION_LOCKED: setError("Vault already locked."); break;
          default: setError(err.message || "Unlock failed.");
        }
      } else { setError(err.message || "Network error."); }
    } finally { setLoading(false); }
  };

  return (
    <div className="vault-unlock-overlay">
      <div className="vault-unlock-modal">
        <h2>🔐 Unlock Vault</h2>
        <p className="subtitle">Load your keypair file to access encrypted shares.</p>

        <div className="form-group">
          <label htmlFor="vault-username">Username</label>
          <input id="vault-username" type="text" value={username}
            onChange={(e) => setUsername(e.target.value)} placeholder="your_username"
            autoComplete="username" disabled={loading} />
        </div>

        <div className="drop-zone" onClick={() => fileInputRef.current?.click()}>
          <input ref={fileInputRef} type="file" accept=".json,application/json"
            onChange={handleFileSelect} style={{ display: "none" }} />
          {fileName ? <span className="file-name">📄 {fileName}</span>
            : <><span className="drop-icon">📂</span><span>Drop .medledger-key.json or click to browse</span></>}
        </div>

        {error && <div className="error-banner" role="alert">{error}</div>}

        <div className="button-row">
          <button className="btn-primary" onClick={handleUnlock}
            disabled={loading || !username || !keypairFile}>
            {loading ? "Unlocking…" : "Unlock Vault"}
          </button>
          <button className="btn-secondary" onClick={onCancel} disabled={loading}>Cancel</button>
        </div>

        <p className="hint">Lost your keypair? Register a new account — past shares are unrecoverable.</p>
      </div>
    </div>
  );
}
```

---

## components/KeypairDownload.jsx

**Purpose:** Post-registration screen that forces the user to save their `.medledger-key.json` file before proceeding. Implements a two-click skip guard to prevent accidental data loss.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `keypairResult` | `object` | Yes | Output from `KeysetManager.createUser()` — must include all public and private key fields |
| `onDownloaded` | `function()` | Yes | Called when user confirms they saved the file |
| `onSkip` | `function()` | Yes | Called after two-click skip confirmation |

### UX Flow

```
┌─────────────────────────────┐
│  🔑 Save Your Keypair        │
│  ⚠️ This is your ONLY chance │
├─────────────────────────────┤
│  [📥 Download file]          │  ← Primary action
│                              │
│  [Skip for now]              │  ← First click
├─────────────────────────────┤
│  ⚠️ DANGER BANNER appears   │  ← After first skip click
│  [⚠️ Skip anyway (DATA LOSS)]│  ← Second click required
└─────────────────────────────┘
```

### Full Source

```jsx
// components/KeypairDownload.jsx
import { useState } from "react";

export default function KeypairDownload({ keypairResult, onDownloaded, onSkip }) {
  const [downloaded, setDownloaded] = useState(false);
  const [warningAck, setWarningAck] = useState(false);

  const handleDownload = () => {
    if (!keypairResult) return;
    const keypairFile = {
      version: "medledger-keypair-v1",
      username: keypairResult.username,
      userIdHex: keypairResult.userIdHex,
      signingPublicKey: keypairResult.signingPublicKey,
      exchangePublicKey: keypairResult.exchangePublicKey,
      signingPrivateKey: keypairResult.signingPrivateKey,
      exchangePrivateKey: keypairResult.exchangePrivateKey,
      createdAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(keypairFile, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${keypairResult.username}.medledger-key.json`; a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  };

  const handleSkip = () => {
    if (!warningAck) { setWarningAck(true); return; }
    onSkip();
  };

  return (
    <div className="keypair-download-overlay">
      <div className="keypair-download-modal">
        <h2>🔑 Save Your Keypair</h2>
        <div className="warning-box">
          <strong>⚠️ This is your only chance to save these keys.</strong>
          <p>MedLedger does <strong>not</strong> store private keys server-side.
             Lost file = <strong>permanent data loss</strong>, no recovery.</p>
        </div>

        <div className="keypair-details">
          <div className="detail-row"><span className="label">Username:</span><span>{keypairResult?.username}</span></div>
          <div className="detail-row"><span className="label">User ID:</span><span className="mono">{keypairResult?.userIdHex}</span></div>
          <div className="detail-row"><span className="label">Signing:</span><span className="mono truncate">{keypairResult?.signingPublicKey}</span></div>
          <div className="detail-row"><span className="label">Exchange:</span><span className="mono truncate">{keypairResult?.exchangePublicKey}</span></div>
        </div>

        <div className="button-row">
          {!downloaded ? (
            <button className="btn-primary btn-download" onClick={handleDownload}>
              📥 Download {keypairResult?.username}.medledger-key.json
            </button>
          ) : (
            <button className="btn-primary btn-confirm" onClick={onDownloaded}>
              ✅ I have saved the file — Continue
            </button>
          )}
          <button className={`btn-secondary ${warningAck ? "btn-danger" : ""}`} onClick={handleSkip}>
            {warningAck ? "⚠️ Skip anyway (DATA LOSS RISK)" : "Skip for now"}
          </button>
        </div>

        {warningAck && (
          <div className="danger-banner" role="alert">
            Skipping discards your private keys. You will need to re-register. Past shares are unrecoverable.
          </div>
        )}

        <p className="hint">Store in a password manager or encrypted USB. Never email or use plain cloud storage.</p>
      </div>
    </div>
  );
}
```

---

## components/VaultStatus.jsx

**Purpose:** Live indicator of whether the crypto vault is locked or unlocked. Polls `KeysetManager` every 2 seconds. Supports compact badge mode and full card mode.

### Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onUnlockRequest` | `function()` | Yes | Called when locked user clicks to unlock |
| `onLockRequest` | `function()` | Yes | Called when unlocked user clicks to lock |
| `compact` | `boolean` | `false` | If true, renders as a small inline button |

### Modes

**Compact mode (`compact={true}`):**
```
┌─────────────┐
│ 🔒 Locked   │ ← click → shows VaultUnlock modal
│ 🔓 Unlocked │ ← click → locks vault
└─────────────┘
```

**Full card mode (`compact={false}`, default):**
```
┌────────────────────────────┐
│ 🔓 Vault Unlocked          │
│ User: alice                │
│ ID:   a1b2c3...            │
│ Signing:  AbCdEf...        │
│ Exchange: XyZaBc...        │
│ [Lock Vault]               │
└────────────────────────────┘
```

### Full Source

```jsx
// components/VaultStatus.jsx
import { useState, useEffect } from "react";
import { KeysetManager } from "../key_manager/key_manager.js";

export default function VaultStatus({ onUnlockRequest, onLockRequest, compact = false }) {
  const [locked, setLocked] = useState(true);
  const [keys, setKeys] = useState(null);

  useEffect(() => {
    const check = () => {
      const isLocked = KeysetManager.isLocked();
      setLocked(isLocked);
      if (!isLocked) {
        try { setKeys(KeysetManager.getPublicKeys()); } catch { setKeys(null); }
      } else { setKeys(null); }
    };
    check();
    const id = setInterval(check, 2000);
    return () => clearInterval(id);
  }, []);

  if (compact) {
    return (
      <button className={`vault-badge ${locked ? "locked" : "unlocked"}`}
        onClick={locked ? onUnlockRequest : onLockRequest}
        title={locked ? "Vault locked — click to unlock" : "Vault unlocked — click to lock"}>
        {locked ? "🔒 Locked" : "🔓 Unlocked"}
      </button>
    );
  }

  return (
    <div className={`vault-status-card ${locked ? "locked" : "unlocked"}`}>
      <div className="status-header">
        <span className="status-icon">{locked ? "🔒" : "🔓"}</span>
        <span className="status-text">{locked ? "Vault Locked" : "Vault Unlocked"}</span>
      </div>

      {!locked && keys && (
        <div className="key-summary">
          <div className="key-row"><span className="key-label">User:</span><span>{keys.username}</span></div>
          <div className="key-row"><span className="key-label">ID:</span><span className="mono">{keys.userIdHex}</span></div>
          <div className="key-row"><span className="key-label">Signing:</span><span className="mono truncate">{keys.signingPublicKey}</span></div>
          <div className="key-row"><span className="key-label">Exchange:</span><span className="mono truncate">{keys.exchangePublicKey}</span></div>
        </div>
      )}

      <div className="status-actions">
        {locked
          ? <button className="btn-primary" onClick={onUnlockRequest}>Unlock Vault</button>
          : <button className="btn-secondary" onClick={onLockRequest}>Lock Vault</button>}
      </div>

      {locked && <p className="status-hint">Unlock to decrypt shares and sign grants.</p>}
    </div>
  );
}
```

---

## Integration Map

### Registration Flow (end-to-end)

```
User fills form in index.html
    ↓
authFlow.js (server-side): PoW → email → TOTP → account creation
    ↓
registerBridge.registerUser()
    ├── Step 1-3: authFlow (server)
    ├── Step 4-5: KeysetManager.init() + createUser() → keypairResult
    ├── Step 6-8: Build .medledger-key.json + trigger browser download
    ├── Step 9:  apiClient.post("/api/register/keys", publicKeys)
    └── Step 10: Wipe private keys from memory
    ↓
<KeypairDownload keypairResult={...} />
    ├── User downloads file (or skips with 2-click guard)
    └── onDownloaded() → app dashboard
```

### Login / Unlock Flow (end-to-end)

```
User opens app, vault is locked
    ↓
<VaultStatus compact={true} /> shows 🔒 Locked
    ↓
User clicks → onUnlockRequest() → show <VaultUnlock />
    ↓
User enters username + drops .medledger-key.json
    ↓
loginBridge.unlockVault()
    ├── Validate file structure & version
    ├── Decode base64 → Uint8Array
    ├── Check Ed25519/X25519 key lengths
    ├── KeysetManager.loginUser() → session unlocked
    ├── Verify server keys match (optional)
    └── sodium.memzero() temporary copies
    ↓
<VaultStatus /> shows 🔓 Unlocked with key details
    ↓
User can now: encryptRecord(), decryptShare(), signPayload()
```

### Auto-Lock Wiring (recommended)

```js
// In your root layout or App component
useEffect(() => {
  let timer;
  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (!KeysetManager.isLocked()) {
        KeysetManager.logoutUser();
        navigate('/lock');
      }
    }, 30 * 60 * 1000); // 30 minutes
  };
  ['mousemove', 'keydown', 'click', 'touchstart']
    .forEach(e => window.addEventListener(e, reset));
  reset();
  return () => {
    clearTimeout(timer);
    ['mousemove', 'keydown', 'click', 'touchstart']
      .forEach(e => window.removeEventListener(e, reset));
  };
}, []);
```

---

## Security Checklist

| # | Check | File | Status |
|---|-------|------|--------|
| 1 | Keypair file version validated | `loginBridge.js` | ✅ `medledger-keypair-v1` exact match |
| 2 | All 7 required fields present | `loginBridge.js` | ✅ Explicit loop check |
| 3 | Base64 decoded with correct variant | `loginBridge.js` | ✅ `URLSAFE_NO_PADDING` |
| 4 | Key lengths validated before use | `loginBridge.js` | ✅ Ed25519 64/32, X25519 32/32 |
| 5 | Server public key verification | `loginBridge.js` | ✅ Optional but recommended |
| 6 | Mismatch triggers immediate lock | `loginBridge.js` | ✅ `logoutUser()` before throw |
| 7 | Temporary Uint8Arrays wiped | `loginBridge.js` | ✅ `sodium.memzero()` after login |
| 8 | CSRF token auto-injected | `apiClient.js` | ✅ Meta tag + cookie fallback |
| 9 | Non-2xx responses throw with context | `apiClient.js` | ✅ `.status`, `.data`, `.path` |
| 10 | Upload uses native FormData (no JSON CT) | `apiClient.js` | ✅ No `Content-Type` override |
| 11 | File drop zone validates before unlock | `VaultUnlock.jsx` | ✅ `previewKeypair()` on select |
| 12 | Username auto-filled from file | `VaultUnlock.jsx` | ✅ Reduces user error |
| 13 | Loading state prevents double-submit | `VaultUnlock.jsx` | ✅ Buttons disabled |
| 14 | Two-click skip guard | `KeypairDownload.jsx` | ✅ Warning banner + danger button |
| 15 | Download only triggers once | `KeypairDownload.jsx` | ✅ `downloaded` state gate |
| 16 | Vault status polled (no stale state) | `VaultStatus.jsx` | ✅ 2-second interval |
| 17 | Compact mode toggles lock/unlock | `VaultStatus.jsx` | ✅ Single button dual action |
| 18 | `beforeunload` handler in hooks | `useKeyset.js` | ✅ Already present in uploaded file |

---

*Implementation Guide v1.0 | MedLedger Team Praxis | 2026-06-13*
