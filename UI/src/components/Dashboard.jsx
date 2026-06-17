import { useState } from "react";
import { useAuth } from "../hooks/useAuth";
import { useKeyset } from "../hooks/useKeyset";
import VaultStatus from "./VaultStatus";

/*
  Dashboard — shown when isAuthenticated && isUnlocked.

  Hook split per hooks_guide:
    useAuth   → isAuthenticated, logout, loading, publicKeys (auth-layer username)
    useKeyset → isUnlocked, isLocked, lockSession, encryptRecord, decryptShare,
                publicKeys (crypto-layer exchange key), error, clearError

  VaultStatus now owns its own useKeyset() call — no props needed.
*/

export default function Dashboard() {
  return (
    <div style={{ minHeight: "100dvh", display: "flex", flexDirection: "column" }}>
      <Header />
      <main
        style={{
          flex: 1,
          maxWidth: 840,
          width: "100%",
          margin: "0 auto",
          padding: "28px 20px 48px",
        }}
      >
        <div className="dash-grid">
          <SendPanel />
          <ReceivePanel />
        </div>
      </main>
    </div>
  );
}

// ─── Header ───────────────────────────────────────────────────────────────────

function Header() {
  // useAuth.publicKeys carries the auth-layer username (available after login)
  const { publicKeys: authKeys, logout, loading } = useAuth();
  // useKeyset.isUnlocked / lockSession for vault controls
  const { isUnlocked, lockSession } = useKeyset();

  return (
    <header
      style={{
        borderBottom: "1px solid var(--c-border)",
        padding: "14px 20px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
      }}
    >
      <div className="wordmark" style={{ marginBottom: 0 }}>envoi</div>

      <div className="row gap-12" style={{ flexWrap: "wrap" }}>
        {/* VaultStatus owns its own hook — no props needed */}
        <VaultStatus compact />

        {/* Username from auth layer */}
        {authKeys?.username && (
          <span className="text-mono text-muted" style={{ fontSize: "0.8125rem" }}>
            {authKeys.username}
          </span>
        )}

        {/* Lock vault */}
        {isUnlocked && (
          <button
            className="btn btn--ghost"
            style={{ fontSize: "0.8125rem", padding: "5px 12px" }}
            onClick={lockSession}
          >
            Lock vault
          </button>
        )}

        {/* Sign out */}
        <button
          className="btn btn--ghost"
          style={{ fontSize: "0.8125rem", padding: "5px 12px" }}
          onClick={logout}
          disabled={loading}
        >
          {loading ? "Signing out…" : "Sign out"}
        </button>
      </div>
    </header>
  );
}

// ─── Send panel ───────────────────────────────────────────────────────────────

function SendPanel() {
  const { encryptRecord, isLocked, error: cryptoError, clearError } = useKeyset();

  const [recipientKey, setRecipientKey] = useState("");
  const [file,         setFile]         = useState(null);
  const [busy,         setBusy]         = useState(false);
  const [localError,   setLocalError]   = useState(null);
  const [done,         setDone]         = useState(false);

  const error = localError || cryptoError;

  async function handleEncrypt() {
    if (!file || !recipientKey.trim()) return;
    setLocalError(null);
    clearError();
    setDone(false);
    setBusy(true);
    try {
      const bytes     = new Uint8Array(await file.arrayBuffer());
      const encrypted = await encryptRecord(bytes, recipientKey.trim());
      if (!encrypted) {
        // encryptRecord returns null and sets cryptoError on failure
        setBusy(false);
        return;
      }
      const bundle = JSON.stringify({ filename: file.name, ...encrypted });
      downloadText(bundle, `${file.name}.envoi.json`);
      setDone(true);
      setFile(null);
      setRecipientKey("");
    } catch (e) {
      setLocalError("Encryption failed — " + (e?.message ?? "unknown error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel stack stack-16">
      <p className="panel__title">Send a document</p>

      {error && <p className="error-msg" role="alert">{error}</p>}
      {done  && (
        <p className="success-msg">
          Encrypted file downloaded. Send it to your recipient.
        </p>
      )}

      <div className="field">
        <label htmlFor="recipient-key">Recipient's public key</label>
        <input
          id="recipient-key"
          value={recipientKey}
          onChange={(e) => { clearError(); setLocalError(null); setRecipientKey(e.target.value); }}
          placeholder="hex exchange key…"
          autoComplete="off"
          spellCheck={false}
          disabled={isLocked || busy}
          className="text-mono"
        />
      </div>

      <div className="field">
        <label htmlFor="send-file">File to encrypt</label>
        <input
          id="send-file"
          type="file"
          disabled={isLocked || busy}
          onChange={(e) => { setDone(false); setFile(e.target.files[0] || null); }}
        />
        {file && (
          <span className="text-faint">
            {file.name} — {formatBytes(file.size)}
          </span>
        )}
      </div>

      <button
        className="btn btn--primary btn--full"
        disabled={isLocked || busy || !file || !recipientKey.trim()}
        onClick={handleEncrypt}
      >
        {busy ? "Encrypting…" : "Encrypt and download"}
      </button>

      {isLocked && (
        <p className="text-faint" style={{ textAlign: "center" }}>
          Unlock your vault to send documents.
        </p>
      )}
    </div>
  );
}

// ─── Receive panel ────────────────────────────────────────────────────────────

function ReceivePanel() {
  const { decryptShare, isLocked, error: cryptoError, clearError } = useKeyset();

  const [bundleFile, setBundleFile] = useState(null);
  const [busy,       setBusy]       = useState(false);
  const [localError, setLocalError] = useState(null);
  const [done,       setDone]       = useState(false);

  const error = localError || cryptoError;

  async function handleDecrypt() {
    if (!bundleFile) return;
    setLocalError(null);
    clearError();
    setDone(false);
    setBusy(true);
    try {
      const text   = await bundleFile.text();
      const bundle = JSON.parse(text);

      const { filename, encryptedRecord, nonce, dekBundle } = bundle;

      if (!encryptedRecord || !nonce || !dekBundle) {
        setLocalError("Invalid bundle — this file doesn't look like an Envoi package.");
        setBusy(false);
        return;
      }

      const plainBytes = await decryptShare(
        base64ToBytes(encryptedRecord),
        base64ToBytes(nonce),
        dekBundle
      );

      if (!plainBytes) {
        setBusy(false);
        return;
      }

      downloadBytes(plainBytes, filename ?? "decrypted-file");
      setDone(true);
      setBundleFile(null);
    } catch (e) {
      setLocalError("Could not read bundle — " + (e?.message ?? "unknown error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel stack stack-16">
      <p className="panel__title">Receive a document</p>

      {error && <p className="error-msg" role="alert">{error}</p>}
      {done  && <p className="success-msg">File decrypted and downloaded.</p>}

      <div className="field">
        <label htmlFor="bundle-file">Envoi bundle (.envoi.json)</label>
        <input
          id="bundle-file"
          type="file"
          accept=".json,.envoi.json"
          disabled={isLocked || busy}
          onChange={(e) => {
            setDone(false);
            clearError();
            setLocalError(null);
            setBundleFile(e.target.files[0] || null);
          }}
        />
        {bundleFile && (
          <span className="text-faint">{bundleFile.name}</span>
        )}
      </div>

      <button
        className="btn btn--primary btn--full"
        disabled={isLocked || busy || !bundleFile}
        onClick={handleDecrypt}
      >
        {busy ? "Decrypting…" : "Decrypt and download"}
      </button>

      {isLocked && (
        <p className="text-faint" style={{ textAlign: "center" }}>
          Unlock your vault to receive documents.
        </p>
      )}

      <hr className="divider" />

      <YourPublicKey />
    </div>
  );
}

// ─── Your public key (share with senders) ────────────────────────────────────

function YourPublicKey() {
  // Crypto-layer publicKeys from useKeyset (has exchangePublicKey)
  const { publicKeys } = useKeyset();
  const [copied, setCopied] = useState(false);

  if (!publicKeys?.exchangePublicKey) return null;

  const hex =
    typeof publicKeys.exchangePublicKey === "string"
      ? publicKeys.exchangePublicKey
      : bytesToHex(publicKeys.exchangePublicKey);

  function copy() {
    navigator.clipboard.writeText(hex).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="stack stack-8">
      <p className="text-faint" style={{ fontSize: "0.8125rem" }}>
        Share your public key with anyone who wants to send you a document.
      </p>
      <div
        className="text-mono"
        style={{
          background: "var(--c-bg)",
          border: "1px solid var(--c-border)",
          borderRadius: "var(--r-sm)",
          padding: "8px 10px",
          fontSize: "0.75rem",
          wordBreak: "break-all",
          color: "var(--c-text-muted)",
        }}
      >
        {hex}
      </div>
      <button
        className="btn btn--ghost"
        style={{ alignSelf: "flex-start", fontSize: "0.8125rem", padding: "5px 12px" }}
        onClick={copy}
      >
        {copied ? "Copied!" : "Copy key"}
      </button>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function downloadText(content, filename) {
  triggerDownload(new Blob([content], { type: "application/json" }), filename);
}

function downloadBytes(bytes, filename) {
  triggerDownload(new Blob([bytes]), filename);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement("a");
  a.href    = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function formatBytes(n) {
  if (n < 1024)           return n + " B";
  if (n < 1024 * 1024)   return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(1) + " MB";
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
