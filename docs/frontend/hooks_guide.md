# Hooks Guide

Reference for `useRegister`, `useAuth`, and `useKeyset` — the three hooks that sit between the services layer and the React component layer.

---

## Architecture Overview

```
Components
    │
    ├── useRegister ──► RegisterBridge ──► apiClient + KeysetManager
    ├── useAuth     ──► loginBridge    ──► apiClient + KeysetManager
    └── useKeyset   ──► authKeyBridge  ──► authFlow + KeysetManager
```

No component imports from `services/` directly. All state management, error formatting, and loading flags live in the hooks.

---

## `useAuth`

Manages the login session. Wraps `loginBridge.js` — keypair-based Ed25519 signature login.

### Returns

| Name | Type | Description |
|------|------|-------------|
| `isAuthenticated` | `boolean` | True when a JWT is held in `apiClient` and a keypair is loaded in `KeysetManager` |
| `publicKeys` | `object \| null` | `{ signingPublicKey, exchangePublicKey, userIdHex, username }` — available after login |
| `loading` | `boolean` | True during `login()` or `logout()` |
| `error` | `string \| null` | User-facing error message, or `null` |
| `login(username, keypair)` | `async (string, Keypair) => boolean` | Authenticate; returns `true` on success |
| `logout()` | `async () => void` | Clears JWT first, then wipes private keys |
| `clearError()` | `() => void` | Resets `error` to `null` |

### Keypair shape

```js
{
  signing:  { publicKey: Uint8Array, privateKey: Uint8Array },
  exchange: { publicKey: Uint8Array, privateKey: Uint8Array },
}
```

### Usage — `LoginFlow.jsx`

```jsx
import { useAuth } from "../hooks/useAuth";

function LoginFlow() {
  const { isAuthenticated, publicKeys, loading, error, login, logout } = useAuth();
  const [username, setUsername] = useState("");
  const [keypair, setKeypair] = useState(null); // loaded from file upload

  async function handleLogin() {
    const success = await login(username, keypair);
    if (success) {
      // navigate to dashboard — isAuthenticated is now true
    }
  }

  if (isAuthenticated) {
    return (
      <div>
        <p>Logged in as {publicKeys.username}</p>
        <button onClick={logout}>Log out</button>
      </div>
    );
  }

  return (
    <div>
      {error && <p className="error">{error}</p>}
      <input value={username} onChange={e => setUsername(e.target.value)} />
      {/* your keypair file upload → setKeypair */}
      <button onClick={handleLogin} disabled={loading || !keypair}>
        {loading ? "Logging in…" : "Log in"}
      </button>
    </div>
  );
}
```

### Error codes surfaced

| Scenario | Message |
|----------|---------|
| Network offline | `"Network error — check your connection."` |
| Keypair doesn't match account | `"Login failed — keypair does not match this account."` |
| Account not found | `"Account not found."` |
| Invalid keypair file | `"Invalid keypair file — check the file and try again."` |
| Session expired | `"Session expired — please log in again."` |

### Notes

- `isAuthenticated` is seeded from `isSessionActive()` on mount — stays consistent across in-page navigations without remounting.
- The JWT is never written to `localStorage`. After a full page reload, the user must log in again.
- `logout()` is resilient: it clears the JWT before touching `KeysetManager`, so even if the crypto layer throws, the session is destroyed.

---

## `useRegister`

Drives the six-step `RegisterBridge` flow. Exposes a step state machine so components only need to render the current step.

### Step machine

```
"idle" → "pow" → "emailVerify" → "totp" → "createAccount" → "keypairReady"
```

Each action advances the step. On error, the step stays where it is and `error` is set — the user can retry the same step.

### Returns

| Name | Type | Description |
|------|------|-------------|
| `step` | `string` | Current step name (compare with `STEPS` constants) |
| `STEPS` | `object` | Constants: `IDLE, POW, EMAIL_VERIFY, TOTP, CREATE_ACCOUNT, KEYPAIR_READY` |
| `loading` | `boolean` | True during any async step |
| `error` | `string \| null` | User-facing error for the current step |
| `startPoW()` | `async () => object \| null` | Fetch + solve + verify PoW challenge |
| `cancelPoW()` | `() => void` | Abort in-flight PoW; resets to `"idle"` |
| `submitEmail(email)` | `async (string) => object \| null` | Submit email for verification |
| `verifyEmailCode(code)` | `async (string) => object \| null` | Submit 6-digit email code |
| `totpInfo` | `object \| null` | `{ qrCodeUri, manualKey }` — available after `verifyEmailCode` |
| `verifyTOTP(totpToken)` | `async (string) => object \| null` | Submit TOTP token |
| `createAccount(username, password)` | `async (string, string) => object \| null` | Final step; generates keypair |
| `keypair` | `object \| null` | Raw keypair including private keys — render download prompt immediately |
| `publicKeys` | `object \| null` | `{ signingPublicKey, exchangePublicKey, userIdHex, username }` |
| `clearKeypair()` | `() => void` | Drop private key references after user confirms save |
| `reset()` | `() => void` | Reset to `"idle"`, fresh bridge instance |

### Usage — `RegistrationFlow.jsx`

```jsx
import { useRegister } from "../hooks/useRegister";

function RegistrationFlow() {
  const {
    step, STEPS, loading, error,
    startPoW, cancelPoW, submitEmail,
    verifyEmailCode, totpInfo,
    verifyTOTP, createAccount,
    keypair, publicKeys, clearKeypair,
    reset,
  } = useRegister();

  const [email, setEmail] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [totpToken, setTotpToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  // Start PoW automatically when the component mounts
  useEffect(() => {
    startPoW();
  }, []);

  if (step === STEPS.IDLE || step === STEPS.POW) {
    return <p>{loading ? "Preparing registration…" : "Starting…"}</p>;
  }

  if (step === STEPS.EMAIL_VERIFY) {
    return (
      <div>
        {error && <p className="error">{error}</p>}
        <input
          placeholder="you@example.com"
          value={email}
          onChange={e => setEmail(e.target.value)}
        />
        <button onClick={() => submitEmail(email)} disabled={loading}>
          {loading ? "Sending…" : "Send verification code"}
        </button>

        {/* After email is submitted, show the 6-digit code input */}
        {loading === false && error === null && email && (
          <div>
            <input
              placeholder="6-digit email code"
              value={emailCode}
              onChange={e => setEmailCode(e.target.value)}
              maxLength={6}
            />
            <button onClick={() => verifyEmailCode(emailCode)} disabled={loading || !emailCode}>
              {loading ? "Verifying…" : "Verify code"}
            </button>
          </div>
        )}
      </div>
    );
  }

  // step === STEPS.TOTP — email verified, show TOTP QR + input
  if (step === STEPS.TOTP) {
    return (
      <div>
        {error && <p className="error">{error}</p>}

        {totpInfo && (
          <div>
            <img src={totpInfo.qrCodeUri} alt="Scan with your authenticator app" />
            <p>Manual key: <code>{totpInfo.manualKey}</code></p>
            <input
              placeholder="6-digit TOTP"
              value={totpToken}
              onChange={e => setTotpToken(e.target.value)}
              maxLength={6}
            />
            <button onClick={() => verifyTOTP(totpToken)} disabled={loading || !totpToken}>
              {loading ? "Verifying…" : "Verify TOTP"}
            </button>
          </div>
        )}
      </div>
    );
  }

  if (step === STEPS.CREATE_ACCOUNT) {
    return (
      <div>
        {error && <p className="error">{error}</p>}
        <input placeholder="Username (min 2 chars)" value={username} onChange={e => setUsername(e.target.value)} />
        <input placeholder="Password (min 8 chars)" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button onClick={() => createAccount(username, password)} disabled={loading}>
          {loading ? "Creating account…" : "Create account"}
        </button>
      </div>
    );
  }

  if (step === STEPS.KEYPAIR_READY) {
    // ⚠️ keypair contains raw private keys — show download prompt, do not navigate away
    return (
      <KeypairDownload
        keypair={keypair}
        publicKeys={publicKeys}
        onConfirmed={() => {
          clearKeypair();
          // navigate to login or dashboard
        }}
      />
    );
  }
}
```

### Notes

- `startPoW()` is safe to call on mount — it aborts any in-flight PoW before starting a new one.
- `totpInfo` is set automatically inside `verifyEmailCode()`. Render the QR code as soon as it's non-null.
- `keypair` holds raw `Uint8Array` private keys. Render `<KeypairDownload>` immediately when `step === STEPS.KEYPAIR_READY`. Call `clearKeypair()` only after the user confirms they have saved the file.
- `reset()` creates a fresh `RegisterBridge` instance — safe to call if the user cancels mid-flow.
- `cancelPoW()` aborts an in-flight PoW request and resets the step back to `"idle"`.

### Error codes surfaced

| Scenario | Message |
|----------|---------|
| Network offline | `"Network error — check your connection."` |
| Invalid email format | `"registerBridge: email format…"` (bridge validation) |
| Code not 6 digits | `"registerBridge: … must be exactly 6 digits"` |
| Server rejects PoW | Server error message |
| Username too short | Bridge validation message |
| Password too short | Bridge validation message |

---

## `useKeyset`

Manages the crypto vault session. Wraps the `authKeyBridge` singleton. Mirrors the `KeysetManager` state machine: `uninitialized → locked → unlocked`.

### Vault status

```
"uninitialized"  →  bridge.init() hasn't resolved yet
"locked"         →  init done, no keypair loaded
"unlocked"       →  keypair loaded, crypto ops available
```

### Returns

| Name | Type | Description |
|------|------|-------------|
| `vaultStatus` | `string` | `"uninitialized" \| "locked" \| "unlocked"` |
| `VAULT_STATUS` | `object` | Constants: `UNINITIALIZED, LOCKED, UNLOCKED` |
| `isLocked` | `boolean` | True when not unlocked (covers uninitialized + locked) |
| `isUnlocked` | `boolean` | True when crypto ops are available |
| `initialized` | `boolean` | True once `bridge.init()` resolves |
| `publicKeys` | `object \| null` | `{ signingPublicKey, exchangePublicKey, userIdHex }` — available when unlocked |
| `loading` | `boolean` | True during `unlockSession()` |
| `error` | `string \| null` | User-facing error |
| `unlockSession(username, savedKeypair)` | `async (string, Keypair) => boolean` | Load keypair; returns `true` on success |
| `lockSession()` | `() => void` | Wipe private keys, set status to `"locked"` |
| `encryptRecord(fileBytes, recipientPublicKey)` | `async (Uint8Array, string) => object \| null` | Encrypt for recipient |
| `decryptShare(encryptedRecord, nonce, dekBundle)` | `async (Uint8Array, Uint8Array, object) => Uint8Array \| null` | Decrypt received share |
| `signPayload(payload)` | `async (object) => { payloadCanon, signature } \| null` | Sign with Ed25519 private key |
| `verifySignature(payload, signature, signerPublicKey)` | `(object, string, string) => boolean` | Verify a signature — no unlock required |
| `clearError()` | `() => void` | Resets `error` to `null` |

### Usage — `VaultStatus.jsx`

```jsx
import { useKeyset } from "../hooks/useKeyset";

function VaultStatus() {
  const { vaultStatus, VAULT_STATUS, isUnlocked, publicKeys, lockSession } = useKeyset();

  if (vaultStatus === VAULT_STATUS.UNINITIALIZED) {
    return <p>Initializing crypto…</p>;
  }

  if (vaultStatus === VAULT_STATUS.LOCKED) {
    return <p>Vault locked — <a href="/unlock">unlock</a></p>;
  }

  return (
    <div>
      <p>Vault unlocked</p>
      <p>User: {publicKeys?.username ?? publicKeys?.userIdHex}</p>
      <button onClick={lockSession}>Lock vault</button>
    </div>
  );
}
```

### Usage — `VaultUnlock.jsx`

```jsx
import { useKeyset } from "../hooks/useKeyset";

function VaultUnlock() {
  const { isUnlocked, loading, error, unlockSession, clearError } = useKeyset();
  const [username, setUsername] = useState("");
  const [keypair, setKeypair] = useState(null); // loaded from file upload

  async function handleUnlock() {
    const success = await unlockSession(username, keypair);
    if (success) {
      // navigate to vault or close modal
    }
  }

  if (isUnlocked) return null; // already unlocked

  return (
    <div>
      {error && <p className="error" onClick={clearError}>{error}</p>}
      <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
      {/* keypair file upload → setKeypair */}
      <button onClick={handleUnlock} disabled={loading || !keypair}>
        {loading ? "Unlocking…" : "Unlock vault"}
      </button>
    </div>
  );
}
```

### Usage — crypto operations

```jsx
import { useKeyset } from "../hooks/useKeyset";

function RecordUpload({ recipientPublicKey }) {
  const { isLocked, encryptRecord, error } = useKeyset();

  async function handleUpload(file) {
    if (isLocked) return; // guard — vault must be unlocked

    const bytes = new Uint8Array(await file.arrayBuffer());
    const encrypted = await encryptRecord(bytes, recipientPublicKey);

    if (encrypted) {
      // send encrypted to your API
    }
  }

  return (
    <div>
      {error && <p className="error">{error}</p>}
      <input type="file" onChange={e => handleUpload(e.target.files[0])} disabled={isLocked} />
    </div>
  );
}
```

### Error codes surfaced

| Scenario | Message |
|----------|---------|
| Network offline | `"Network error — check your connection."` |
| Invalid keypair file | `"Invalid keypair — check your saved keys and try again."` |
| Crypto ops on locked vault | `"The vault is locked. Upload your keypair to unlock."` |
| Crypto not yet initialized | `"Crypto layer not ready. Refresh the page."` |
| Init failure | `"Failed to initialize crypto layer."` |

### Notes

- `bridge.init()` (libsodium WASM) is called once on mount. Components can gate on `initialized` before rendering crypto-dependent UI.
- `verifySignature()` is synchronous and does not require an unlocked session — it operates on public keys only.
- Crypto op methods (`encryptRecord`, `decryptShare`, `signPayload`) return `null` and set `error` on failure rather than throwing, so components don't need try/catch.
- `lockSession()` is synchronous and always succeeds — it calls `bridge.logout()` best-effort and unconditionally updates state.

---

## Shared patterns

### Loading state

All hooks expose a single `loading` boolean. Disable form buttons while loading:

```jsx
<button disabled={loading || !someRequiredField}>
  {loading ? "Working…" : "Submit"}
</button>
```

### Error display

All hooks format errors as plain strings. No error typing or code-switching in components:

```jsx
{error && <p role="alert" className="error">{error}</p>}
```

Call `clearError()` when the user edits an input to reset stale errors:

```jsx
<input onChange={e => { clearError(); setValue(e.target.value); }} />
```

### Combining hooks

`useAuth` and `useKeyset` are independent — use both when you need the full session picture:

```jsx
function Dashboard() {
  const { isAuthenticated, publicKeys: authKeys, logout } = useAuth();
  const { isUnlocked, publicKeys: cryptoKeys, lockSession } = useKeyset();

  // isAuthenticated → JWT is held, user is logged in (auth layer)
  // isUnlocked      → keypair is loaded, crypto is available (crypto layer)
}
```

`useRegister` is self-contained — instantiate it once per registration attempt, call `reset()` on cancel.

---

## Component → hook map

| Component | Hook(s) | Key values consumed |
|-----------|---------|---------------------|
| `LoginFlow.jsx` | `useAuth` | `login`, `logout`, `isAuthenticated`, `loading`, `error` |
| `RegistrationFlow.jsx` | `useRegister` | `step`, `STEPS`, all step actions, `keypair`, `totpInfo` |
| `KeypairDownload.jsx` | props only | Receives `keypair` and `onConfirmed` from `RegistrationFlow` |
| `VaultStatus.jsx` | `useKeyset` | `vaultStatus`, `publicKeys`, `lockSession` |
| `VaultUnlock.jsx` | `useKeyset` | `unlockSession`, `isUnlocked`, `loading`, `error` |
