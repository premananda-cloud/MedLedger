/**
 * KeypairDownload.jsx
 *
 * Shown exactly once — immediately after KeysetManager.createUser() returns
 * during registration. The user must download (and optionally copy) their
 * private keypair before the UI advances.
 *
 * Props:
 *   keypair  — the object returned by RegisterBridge.createAccount():
 *              { signing: { publicKey: Uint8Array, privateKey: Uint8Array },
 *                exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }
 *   username — string, shown in the filename and UI
 *   onConfirmed — () => void   called once the user clicks "I've saved my keys"
 *
 * This component does NOT call RegisterBridge or KeysetManager itself — it is
 * purely presentational with one side-effect: triggering a browser download.
 */

import { useState, useCallback } from "react";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Convert a Uint8Array to a hex string for human-readable display. */
function toHex(u8) {
  return Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert a Uint8Array to base64url (no padding). */
function toBase64url(u8) {
  const b64 = btoa(String.fromCharCode(...u8));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Build the JSON blob the user downloads.
 * Stores keys as base64url so the file is text-safe and copy-pasteable.
 */
function buildKeypairJson(username, keypair) {
  return JSON.stringify(
    {
      _medledger: "keypair-v1",
      username,
      createdAt: new Date().toISOString(),
      warning:
        "These are your private keys. Anyone with this file can access your MedLedger account. Store it offline or in a password manager. You cannot recover it.",
      signing: {
        publicKey: toBase64url(keypair.signing.publicKey),
        privateKey: toBase64url(keypair.signing.privateKey),
      },
      exchange: {
        publicKey: toBase64url(keypair.exchange.publicKey),
        privateKey: toBase64url(keypair.exchange.privateKey),
      },
    },
    null,
    2
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export function KeypairDownload({ keypair, username, onConfirmed }) {
  const [downloaded, setDownloaded] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const handleDownload = useCallback(() => {
    const json = buildKeypairJson(username, keypair);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `medledger-keypair-${username}.json`;
    document.body.appendChild(a);
    a.click();

    // Clean up immediately — the blob stays in memory until GC
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);

    setDownloaded(true);
  }, [keypair, username]);

  const handleConfirm = useCallback(() => {
    if (!downloaded) return;
    setConfirmed(true);
    onConfirmed?.();
  }, [downloaded, onConfirmed]);

  // Abbreviated key previews for reassurance (not full keys)
  const sigPubHex = keypair?.signing?.publicKey
    ? toHex(keypair.signing.publicKey)
    : "";
  const exPubHex = keypair?.exchange?.publicKey
    ? toHex(keypair.exchange.publicKey)
    : "";

  return (
    <div className="kd-root">
      <div className="kd-card">
        {/* Header */}
        <div className="kd-header">
          <svg className="kd-icon-key" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
          </svg>
          <div>
            <h2 className="kd-title">Save your private keys</h2>
            <p className="kd-subtitle">
              This is the only time they will be shown.
            </p>
          </div>
        </div>

        {/* Warning banner */}
        <div className="kd-warning" role="alert">
          <svg className="kd-icon-warn" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4m0 4h.01" />
          </svg>
          <p>
            MedLedger cannot recover lost keys. If you lose this file, you lose
            access to your encrypted records — permanently.
          </p>
        </div>

        {/* Key fingerprints */}
        <div className="kd-keys">
          <div className="kd-key-row">
            <span className="kd-key-label">Signing key</span>
            <code className="kd-key-value">
              {sigPubHex.slice(0, 16)}…{sigPubHex.slice(-8)}
            </code>
          </div>
          <div className="kd-key-row">
            <span className="kd-key-label">Exchange key</span>
            <code className="kd-key-value">
              {exPubHex.slice(0, 16)}…{exPubHex.slice(-8)}
            </code>
          </div>
        </div>

        {/* Instructions */}
        <ol className="kd-steps">
          <li className={downloaded ? "kd-step kd-step--done" : "kd-step"}>
            Download the file to a safe location — not your Downloads folder.
          </li>
          <li className="kd-step">
            Move it to a password manager, encrypted USB drive, or print it.
          </li>
          <li className="kd-step">
            Never share it. Never upload it to any service.
          </li>
        </ol>

        {/* Actions */}
        <div className="kd-actions">
          <button
            type="button"
            className="kd-btn kd-btn--primary"
            onClick={handleDownload}
          >
            {downloaded ? (
              <>
                <svg className="kd-icon-check" viewBox="0 0 24 24" aria-hidden="true">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                Downloaded
              </>
            ) : (
              <>
                <svg className="kd-icon-dl" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
                </svg>
                Download keypair
              </>
            )}
          </button>

          <button
            type="button"
            className={
              downloaded && !confirmed
                ? "kd-btn kd-btn--confirm"
                : "kd-btn kd-btn--confirm kd-btn--disabled"
            }
            onClick={handleConfirm}
            disabled={!downloaded || confirmed}
            aria-disabled={!downloaded || confirmed}
          >
            {confirmed ? "Saved ✓" : "I've saved my keys — continue"}
          </button>
        </div>

        {!downloaded && (
          <p className="kd-hint">Download the file first to continue.</p>
        )}
      </div>

      <style>{`
        /* ── Layout ── */
        .kd-root {
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          padding: 2rem 1rem;
          background: #0f1623;
          font-family: system-ui, -apple-system, sans-serif;
        }

        .kd-card {
          background: #1a2333;
          border: 1px solid #2a3a50;
          border-radius: 12px;
          padding: 2rem;
          max-width: 520px;
          width: 100%;
          box-shadow: 0 24px 64px rgba(0,0,0,0.5);
        }

        /* ── Header ── */
        .kd-header {
          display: flex;
          align-items: flex-start;
          gap: 1rem;
          margin-bottom: 1.5rem;
        }

        .kd-icon-key {
          flex-shrink: 0;
          width: 36px;
          height: 36px;
          stroke: #00bfa5;
          fill: none;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
          margin-top: 2px;
        }

        .kd-title {
          margin: 0 0 0.25rem;
          font-size: 1.25rem;
          font-weight: 600;
          color: #e8edf4;
          letter-spacing: -0.01em;
        }

        .kd-subtitle {
          margin: 0;
          font-size: 0.875rem;
          color: #6b7e96;
        }

        /* ── Warning ── */
        .kd-warning {
          display: flex;
          gap: 0.75rem;
          align-items: flex-start;
          background: rgba(232, 168, 56, 0.08);
          border: 1px solid rgba(232, 168, 56, 0.3);
          border-radius: 8px;
          padding: 0.875rem 1rem;
          margin-bottom: 1.5rem;
        }

        .kd-icon-warn {
          flex-shrink: 0;
          width: 18px;
          height: 18px;
          stroke: #e8a838;
          fill: none;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
          margin-top: 1px;
        }

        .kd-warning p {
          margin: 0;
          font-size: 0.85rem;
          color: #c8a050;
          line-height: 1.5;
        }

        /* ── Key fingerprints ── */
        .kd-keys {
          background: #111a28;
          border: 1px solid #1e2d42;
          border-radius: 8px;
          padding: 0.75rem 1rem;
          margin-bottom: 1.5rem;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .kd-key-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 1rem;
          flex-wrap: wrap;
        }

        .kd-key-label {
          font-size: 0.75rem;
          color: #4a6280;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          font-weight: 500;
          white-space: nowrap;
        }

        .kd-key-value {
          font-family: ui-monospace, "Cascadia Code", "Fira Code", monospace;
          font-size: 0.8rem;
          color: #00bfa5;
          letter-spacing: 0.04em;
          word-break: break-all;
        }

        /* ── Step list ── */
        .kd-steps {
          margin: 0 0 1.75rem;
          padding-left: 1.25rem;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .kd-step {
          font-size: 0.875rem;
          color: #8a9eb8;
          line-height: 1.5;
          padding-left: 0.25rem;
          transition: color 0.2s;
        }

        .kd-step--done {
          color: #00bfa5;
        }

        .kd-step--done::marker {
          color: #00bfa5;
        }

        /* ── Actions ── */
        .kd-actions {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        .kd-btn {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1.25rem;
          border-radius: 8px;
          font-size: 0.9rem;
          font-weight: 500;
          cursor: pointer;
          border: none;
          transition: background 0.15s, opacity 0.15s, transform 0.1s;
          outline-offset: 3px;
        }

        .kd-btn:active:not(:disabled) {
          transform: scale(0.98);
        }

        .kd-btn--primary {
          background: #00bfa5;
          color: #061018;
        }

        .kd-btn--primary:hover {
          background: #00d4b8;
        }

        .kd-btn--confirm {
          background: #1e3a28;
          color: #4dbb77;
          border: 1px solid #2a5038;
        }

        .kd-btn--confirm:not(.kd-btn--disabled):hover {
          background: #244530;
        }

        .kd-btn--disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        .kd-icon-check,
        .kd-icon-dl {
          width: 16px;
          height: 16px;
          stroke: currentColor;
          fill: none;
          stroke-width: 2.5;
          stroke-linecap: round;
          stroke-linejoin: round;
        }

        /* ── Hint ── */
        .kd-hint {
          margin: 0.75rem 0 0;
          font-size: 0.8rem;
          color: #3d5268;
          text-align: center;
        }

        /* ── Responsive ── */
        @media (max-width: 480px) {
          .kd-card {
            padding: 1.5rem 1rem;
          }
          .kd-key-row {
            flex-direction: column;
            align-items: flex-start;
            gap: 0.25rem;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .kd-btn { transition: none; }
        }
      `}</style>
    </div>
  );
}
