# Components — Usage Reference

All components live in `src/components/`. They consume state exclusively through the three hooks (`useAuth`, `useRegister`, `useKeyset`) — no component imports from `src/services/` directly.

---

## Table of contents

- [App-level wiring](#app-level-wiring)
- [LoginFlow](#loginflow)
- [RegistrationFlow](#registrationflow)
- [KeypairSaveDialog](#keypairsavedialog)
- [KeypairDownload](#keypairdownload)
- [VaultUnlock](#vaultunlock)
- [VaultStatus](#vaultstatus)
- [Dashboard](#dashboard)

---

## App-level wiring

The four screens map to four exclusive states. A minimal `App.jsx`:

```jsx
import { useAuth }   from "./hooks/useAuth";
import { useKeyset } from "./hooks/useKeyset";

import { LoginFlow }        from "./components/LoginFlow";
import { RegistrationFlow } from "./components/RegistrationFlow";
import { VaultUnlock }      from "./components/VaultUnlock";
import Dashboard            from "./components/Dashboard";

export default function App() {
  const { isAuthenticated }           = useAuth();
  const { isUnlocked, initialized }   = useKeyset();

  if (!isAuthenticated)          return <LoginFlow onLogin={() => {}} />;
  if (!initialized)              return <p>Initialising…</p>;
  if (!isUnlocked)               return <VaultUnlock onUnlocked={() => {}} />;
  return <Dashboard />;
}
```

Registration sits outside this flow — render it on a separate route or behind a "Create account" toggle before the login screen.

### Screen decision tree

```
isAuthenticated?
  No  → <LoginFlow>        (or <RegistrationFlow> for new users)
  Yes →
    initialized?
      No  → loading spinner
      Yes →
        isUnlocked?
          No  → <VaultUnlock>
          Yes → <Dashboard>
```

---

## LoginFlow

**File:** `LoginFlow.jsx`  
**Hook:** `useAuth`  
**Export:** named — `import { LoginFlow } from "./components/LoginFlow"`

### What it does

Collects a username and a keypair file, calls `useAuth.login(username, keypair)`, and notifies the parent on success.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `onLogin` | `() => void` | yes | Called after `login()` returns `true`. Parent should re-evaluate `isAuthenticated` and re-render. |

### Internally managed state

| State | Purpose |
|-------|---------|
| `username` | Controlled input |
| `keypair` | Parsed `Uint8Array` keypair from file upload |
| `fileError` | Parse-stage error (distinct from hook `error`) |
| `fileName` | Display name of the uploaded file |

### Keypair file formats supported

Both formats written by this app are accepted:

| Format | Field | Encoding |
|--------|-------|----------|
| `KeypairDownload` (`_medledger: "keypair-v1"`) | `signing`, `exchange` | base64url |
| `KeypairSaveDialog` (`version: 1`) | `signing`, `exchange` | hex |

If `username` is present in the file and the username field is still empty, it is pre-filled automatically.

### Error display

Errors from two sources are merged and shown in a single `role="alert"` paragraph:
- `fileError` — JSON parse failures, wrong file type, missing fields
- `useAuth.error` — network errors, keypair mismatch, account not found

### Usage

```jsx
import { LoginFlow } from "./components/LoginFlow";

function AuthGate() {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) return <Dashboard />;

  return <LoginFlow onLogin={() => { /* state update triggers re-render */ }} />;
}
```

### Notes

- The submit button is disabled until both `username` and `keypair` are present.
- `clearError()` is called on every username change and every file selection to avoid stale error messages.
- Do not render `LoginFlow` when `isAuthenticated` is already true.

---

## RegistrationFlow

**File:** `RegistrationFlow.jsx`  
**Hook:** `useRegister`  
**Export:** named — `import { RegistrationFlow } from "./components/RegistrationFlow"`  
**Peer dependency:** `qrcode.react` (for `QRCodeSVG`)

### What it does

Drives the full six-step registration state machine. Each step is a separate rendered screen. The component calls `useRegister` actions and renders the appropriate UI for the current `step`.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `onComplete` | `({ username, email }) => void` | yes | Called after the user confirms their keypair is saved. Parent should navigate to login or dashboard. |

### Step flow

```
IDLE / POW       → loading screen (PoW runs automatically on mount)
EMAIL_VERIFY     → email input → verification code input
TOTP             → QR code display + 6-digit TOTP input
CREATE_ACCOUNT   → username + password inputs
KEYPAIR_READY    → <KeypairSaveDialog> (download gate)
```

### Internally managed state

| State | Purpose |
|-------|---------|
| `email`, `emailCode` | Email step inputs |
| `totpToken` | TOTP step input |
| `username`, `password` | Account creation inputs |
| `emailSent` | Sub-state: whether `submitEmail()` has been called; controls whether the code input is shown |

All async state (`step`, `loading`, `error`, `totpInfo`, `keypair`, `publicKeys`) lives in `useRegister`.

### PoW

`startPoW()` is called on mount inside a `useEffect`. It is safe to call more than once — `useRegister` aborts any in-flight request before starting a new one.

### Keypair handoff

When `step === STEPS.KEYPAIR_READY`, `RegistrationFlow` renders `<KeypairSaveDialog>`. Inside `onConfirmed`:
1. `clearKeypair()` is called to wipe private key references from React state.
2. `onComplete({ username, email })` is called to notify the parent.

### Usage

```jsx
import { RegistrationFlow } from "./components/RegistrationFlow";

function RegisterPage() {
  function handleComplete({ username, email }) {
    // e.g. navigate to login, show a welcome message
    console.log("Registered:", username);
  }

  return <RegistrationFlow onComplete={handleComplete} />;
}
```

### Notes

- `reset()` from `useRegister` is available but not wired to any button in the component — call it from a parent "Cancel" affordance if needed.
- The TOTP QR code is rendered as soon as `totpInfo` is non-null (set automatically by `verifyEmailCode`).
- Numeric inputs (`emailCode`, `totpToken`) strip non-digit characters on `onChange`.

---

## KeypairSaveDialog

**File:** `KeypairSaveDialog.jsx`  
**Hook:** none — purely presentational  
**Export:** named — `import { KeypairSaveDialog } from "./components/KeypairSaveDialog"`

### What it does

Forces the user to download their keypair JSON file and check a confirmation checkbox before proceeding. Used as the final step in `RegistrationFlow`.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `keypair` | `{ signing: { publicKey: Uint8Array, privateKey: Uint8Array }, exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }` | yes | Raw keypair from `useRegister.keypair` |
| `publicKeys` | `{ username?: string, userIdHex?: string, signingPublicKey?: string, exchangePublicKey?: string }` | yes | Public identity info shown in the account summary block |
| `onConfirmed` | `() => void` | yes | Called after the user checks the confirmation checkbox. Caller must call `clearKeypair()` here. |

### Render behaviour

- Renders `null` after `onConfirmed` fires (self-dismisses).
- The checkbox only appears after the file has been downloaded at least once.
- The "Download again" button re-triggers the download for users who misplace the file immediately.

### Download format

The file is written as `envoi-keypair-{username}.json` with this shape:

```json
{
  "version": 1,
  "createdAt": "ISO-8601",
  "username": "alice",
  "userIdHex": "abcdef…",
  "signing":  { "publicKey": "hex…", "privateKey": "hex…" },
  "exchange": { "publicKey": "hex…", "privateKey": "hex…" }
}
```

Keys are hex-encoded. `VaultUnlock` and `LoginFlow` both parse this format.

### Usage

```jsx
// Inside RegistrationFlow, when step === STEPS.KEYPAIR_READY:
<KeypairSaveDialog
  keypair={keypair}
  publicKeys={publicKeys}
  onConfirmed={() => {
    clearKeypair();   // wipe private keys from useRegister state
    onComplete({ username, email });
  }}
/>
```

### Notes

- There is no skip or dismiss path — the component cannot be bypassed.
- `onConfirmed` must call `clearKeypair()`. If you forget, private key `Uint8Array`s remain in `useRegister` state after registration.

---

## KeypairDownload

**File:** `KeypairDownload.jsx`  
**Hook:** none — purely presentational  
**Export:** named — `import { KeypairDownload } from "./components/KeypairDownload"`

### What it does

An alternative keypair save screen with a more prominent design — full-page card, key fingerprint display, numbered checklist. Functionally equivalent to `KeypairSaveDialog` but suited for a dedicated page rather than an inline dialog. Both components write compatible file formats.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `keypair` | `{ signing: { publicKey: Uint8Array, privateKey: Uint8Array }, exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }` | yes | Raw keypair from `useRegister.keypair` |
| `publicKeys` | `{ username?: string, userIdHex?: string }` | yes | Used for the download filename and key fingerprint display |
| `onConfirmed` | `() => void` | yes | Called when the user clicks "I've saved my keys — continue". Caller must call `clearKeypair()` here. |

### Download format

The file is written as `envoi-keypair-{username}.json` with this shape:

```json
{
  "_medledger": "keypair-v1",
  "username": "alice",
  "userIdHex": "abcdef…",
  "createdAt": "ISO-8601",
  "warning": "…",
  "signing":  { "publicKey": "base64url…", "privateKey": "base64url…" },
  "exchange": { "publicKey": "base64url…", "privateKey": "base64url…" }
}
```

Keys are base64url-encoded. `VaultUnlock` and `LoginFlow` both parse this format.

### Choosing between KeypairDownload and KeypairSaveDialog

| | `KeypairSaveDialog` | `KeypairDownload` |
|---|---|---|
| Layout | Inline card (fits within a flow) | Full-page centered card |
| Key display | Account summary (username + user ID) | Fingerprint preview of public keys |
| Confirmation | Checkbox | Separate "continue" button |
| File format | hex / `version: 1` | base64url / `_medledger: "keypair-v1"` |
| Best for | Inline in `RegistrationFlow` | Dedicated `/save-keys` route |

Both formats are supported by `VaultUnlock` and `LoginFlow`. Pick one per registration flow — do not show both.

### Usage

```jsx
// hooks_guide example — inside RegistrationFlow when step === STEPS.KEYPAIR_READY:
<KeypairDownload
  keypair={keypair}
  publicKeys={publicKeys}
  onConfirmed={() => {
    clearKeypair();
    // navigate to login or dashboard
  }}
/>
```

---

## VaultUnlock

**File:** `VaultUnlock.jsx`  
**Hook:** `useKeyset`  
**Export:** named — `import { VaultUnlock } from "./components/VaultUnlock"`

### What it does

Full-page screen for returning users. Accepts the keypair JSON file (from registration) via drag-and-drop, file picker, or JSON paste, then calls `useKeyset.unlockSession(username, keypair)`.

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `onUnlocked` | `() => void` | yes | Called after `unlockSession()` returns `true`. Parent re-evaluates `isUnlocked` and re-renders. |
| `className` | `string` | no | Additional class on the root `div` for layout integration. |

### Input modes

| Mode | How to activate |
|------|----------------|
| File drop / picker | Default; click the drop zone or drag a file onto it |
| JSON paste | Click "Paste JSON instead" to reveal a textarea |

### Keypair file formats supported

| Format | Indicator | Key encoding |
|--------|-----------|--------------|
| `KeypairDownload` | `_medledger: "keypair-v1"` | base64url |
| `KeypairSaveDialog` | `version: 1` | hex |

### Error display

Errors from two sources are merged and shown in a shake-animated error banner:
- `parseError` — JSON parse failures, wrong file format, missing fields, decode errors
- `useKeyset.error` — wrong keypair for account, network errors, crypto layer failures

### Usage

```jsx
import { VaultUnlock } from "./components/VaultUnlock";

function SessionGate() {
  const { isUnlocked } = useKeyset();

  if (isUnlocked) return null;

  return <VaultUnlock onUnlocked={() => { /* re-render triggers Dashboard */ }} />;
}
```

### Notes

- Calling `onUnlocked()` with no arguments is correct — `publicKeys` is available to the parent via its own `useKeyset()` call.
- The file drop zone is a `<button>` element for keyboard accessibility; pressing Enter/Space opens the file picker.
- The paste textarea clears its error state on every keystroke.
- Do not render `VaultUnlock` when `isUnlocked` is already true.

---

## VaultStatus

**File:** `VaultStatus.jsx`  
**Hook:** `useKeyset` (owned internally — no hook props needed)  
**Export:** default — `import VaultStatus from "./components/VaultStatus"`

### What it does

Compact status badge for nav bars and headers. Shows locked/unlocked state, the active user's fingerprint, and a lock confirmation popover. Calls `lockSession()` directly after user confirms.

### Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `compact` | `boolean` | `false` | When `true`, hides the text label and fingerprint; shows only the lock icon and pip. Use in tight headers. |
| `className` | `string` | `""` | Additional class on the root `div`. |

### Visual states

| Vault state | Appearance |
|-------------|-----------|
| `uninitialized` | Muted pill, button disabled |
| `locked` | Dark pill, grey pip |
| `unlocked` | Teal pill, animated teal pip, username + fingerprint |

### Lock confirmation

Clicking the badge when unlocked opens an inline popover with "Lock" and "Cancel" buttons. "Lock" calls `lockSession()` which wipes private keys from memory. The popover is dismissed on cancel.

### Usage

```jsx
// In a header — no props required beyond optional compact/className
import VaultStatus from "./components/VaultStatus";

function AppHeader() {
  return (
    <header>
      <span>envoi</span>
      <VaultStatus compact />
    </header>
  );
}

// Full label + fingerprint (e.g. in a sidebar)
<VaultStatus />

// With custom layout class
<VaultStatus className="ml-auto" />
```

### Notes

- `VaultStatus` calls `useKeyset()` itself — do not pass hook values as props.
- Routing to `VaultUnlock` after a lock is the parent's responsibility. `VaultStatus` only calls `lockSession()`; it does not navigate.
- When `compact={true}`, only the icon and pip are shown. The label and fingerprint are hidden. The lock confirmation popover still works normally.

---

## Dashboard

**File:** `Dashboard.jsx`  
**Hooks:** `useAuth`, `useKeyset`  
**Export:** default — `import Dashboard from "./components/Dashboard"`

### What it does

The main authenticated screen. Contains three functional areas:

| Area | Component | Purpose |
|------|-----------|---------|
| Header | `Header` (internal) | App wordmark, vault badge, username, lock + sign-out buttons |
| Send panel | `SendPanel` (internal) | Encrypt a file for a recipient's exchange public key; download ciphertext bundle |
| Receive panel | `ReceivePanel` (internal) | Decrypt a received `.envoi.json` bundle; download plaintext |
| Public key display | `YourPublicKey` (internal) | Show and copy the user's own exchange public key for sharing |

### Props

None. `Dashboard` reads everything it needs from `useAuth` and `useKeyset` internally.

### Hook usage split

| Hook | Values used | Where |
|------|-------------|-------|
| `useAuth` | `publicKeys.username`, `logout`, `loading` | `Header` |
| `useKeyset` | `isUnlocked`, `lockSession` | `Header` |
| `useKeyset` | `encryptRecord`, `isLocked`, `error`, `clearError` | `SendPanel` |
| `useKeyset` | `decryptShare`, `isLocked`, `error`, `clearError` | `ReceivePanel` |
| `useKeyset` | `publicKeys.exchangePublicKey` | `YourPublicKey` |

`VaultStatus` is rendered in the header with `compact` — it owns its own `useKeyset()` call.

### Encrypt flow (SendPanel)

1. User pastes a recipient's hex exchange public key.
2. User picks a file.
3. Click "Encrypt and download" → `encryptRecord(fileBytes, recipientPublicKey)`.
4. On success, a JSON bundle (`{ filename, ...encryptedPayload }`) is downloaded as `{filename}.envoi.json`.

### Decrypt flow (ReceivePanel)

1. User picks a `.envoi.json` bundle received from a sender.
2. Click "Decrypt and download" → `decryptShare(encryptedRecord, nonce, dekBundle)`.
3. On success, the plaintext file is downloaded under its original filename.

### Usage

```jsx
import Dashboard from "./components/Dashboard";

// Render only when both layers are ready:
const { isAuthenticated } = useAuth();
const { isUnlocked }      = useKeyset();

if (isAuthenticated && isUnlocked) return <Dashboard />;
```

### Notes

- Both panels disable their inputs and buttons when `isLocked` is true, and show a "Unlock your vault" message.
- `cryptoError` from `useKeyset` and `localError` (caught exceptions) are merged with `||` and shown in a single `role="alert"` paragraph. `clearError()` is called on every input change.
- The `YourPublicKey` section renders nothing if `publicKeys.exchangePublicKey` is absent (e.g. vault is locked).

---

## Shared CSS conventions

All components reference the global CSS custom properties from `index.css`. The variable names used:

| Variable | Role |
|----------|------|
| `--c-bg` | Page / input background |
| `--c-border` | Default border colour |
| `--c-accent` | Primary accent (teal) |
| `--c-text-muted` | Secondary text |
| `--c-text-faint` | Tertiary / hint text |
| `--r-sm` | Small border radius |

`LoginFlow`, `RegistrationFlow`, and the auth-card wrappers in `KeypairSaveDialog` use the shared classes `auth-root`, `auth-card`, `stack`, `stack-{n}`, `field`, `btn`, `btn--primary`, `btn--ghost`, `btn--full`, `error-msg`, `success-msg`, `text-mono`, `text-muted`, `text-faint`.

`VaultStatus`, `VaultUnlock`, `KeypairDownload`, and `Dashboard` ship their own `<style>` blocks with scoped class names (`vs-*`, `vu-*`, `kd-*`, `dash-*`) to avoid conflicts.
