import { useState } from "react";

/**
 * KeypairSaveDialog
 *
 * Shown after account creation when the keypair is freshly generated.
 * Forces the user to download the keypair file and confirm before proceeding.
 *
 * Props:
 *   keypair    — raw keypair object from useRegister (contains Uint8Array private keys)
 *   publicKeys — { signingPublicKey, exchangePublicKey, userIdHex, username }
 *   onConfirmed — callback fired after user confirms download
 */
export function KeypairSaveDialog({ keypair, publicKeys, onConfirmed }) {
  const [downloaded, setDownloaded] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  function handleDownload() {
    const bundle = buildKeypairBundle(keypair, publicKeys);
    const json = JSON.stringify(bundle, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `envoi-keypair-${publicKeys?.username ?? publicKeys?.userIdHex ?? "keys"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  }

  function handleConfirm() {
    if (!downloaded) return;
    setConfirmed(true);
    onConfirmed?.();
  }

  if (confirmed) return null;

  return (
    <div className="keypair-box stack stack-16">
      {/* Header */}
      <div className="stack stack-4">
        <h2>Save your keypair</h2>
        <p className="text-muted">
          This is the only time your private keys are available. There is no recovery —
          if you lose this file your account can no longer decrypt received documents.
          You can still re-register, but old ciphertext will be unreadable.
        </p>
      </div>

      {/* Public key preview */}
      {publicKeys && (
        <div className="stack stack-8">
          <p className="text-faint" style={{ fontSize: "0.75rem", letterSpacing: "0.05em", textTransform: "uppercase" }}>
            Your account
          </p>
          <div
            className="text-mono"
            style={{
              background: "var(--c-bg)",
              border: "1px solid var(--c-border)",
              borderRadius: "var(--r-sm)",
              padding: "10px 12px",
              fontSize: "0.8125rem",
              color: "var(--c-text-muted)",
            }}
          >
            <div style={{ marginBottom: 4 }}>
              <span style={{ color: "var(--c-text-faint)" }}>username  </span>
              {publicKeys.username}
            </div>
            <div style={{ wordBreak: "break-all" }}>
              <span style={{ color: "var(--c-text-faint)" }}>user id   </span>
              {publicKeys.userIdHex}
            </div>
          </div>
        </div>
      )}

      {/* Download button */}
      <button
        className="btn btn--primary btn--full"
        onClick={handleDownload}
      >
        {downloaded ? "Download again" : "Download keypair file"}
      </button>

      {/* Confirmation checkbox */}
      {downloaded && (
        <label
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 10,
            cursor: "pointer",
            fontSize: "0.875rem",
            color: "var(--c-text-muted)",
          }}
        >
          <input
            type="checkbox"
            style={{ marginTop: 3, accentColor: "var(--c-accent)", flexShrink: 0 }}
            onChange={e => {
              if (e.target.checked) handleConfirm();
            }}
          />
          I have saved the keypair file somewhere safe. I understand I cannot recover
          my private keys if I lose this file.
        </label>
      )}

      {!downloaded && (
        <p
          className="text-faint"
          style={{ textAlign: "center", fontSize: "0.8125rem" }}
        >
          Download the file above before continuing.
        </p>
      )}
    </div>
  );
}

/* ─── Helpers ────────────────────────────────────────── */

/**
 * Serialise the keypair to a JSON-safe object.
 * Uint8Arrays are encoded as hex strings so the file is human-readable
 * and unambiguous to re-import.
 */
function buildKeypairBundle(keypair, publicKeys) {
  return {
    version: 1,
    createdAt: new Date().toISOString(),
    username: publicKeys?.username ?? null,
    userIdHex: publicKeys?.userIdHex ?? null,
    signing: {
      publicKey: toHex(keypair?.signing?.publicKey),
      privateKey: toHex(keypair?.signing?.privateKey),
    },
    exchange: {
      publicKey: toHex(keypair?.exchange?.publicKey),
      privateKey: toHex(keypair?.exchange?.privateKey),
    },
  };
}

function toHex(bytes) {
  if (!bytes) return null;
  if (typeof bytes === "string") return bytes; // already hex
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
