/**
 * VaultUnlock.jsx
 *
 * Full-page vault unlock screen for returning users.
 * Accepts the keypair JSON file (downloaded at registration) via:
 *   1. File drag-and-drop / file picker
 *   2. JSON paste into a textarea (for mobile / clipboard workflows)
 *
 * On success it calls onUnlocked(publicKeys) — the caller stores publicKeys
 * in React state and the rest of the app becomes accessible.
 *
 * This component handles:
 *  - File parsing + validation
 *  - Calling loginBridge.login()
 *  - Error display with actionable messages
 *
 * Props:
 *   onUnlocked — (publicKeys: object) => void   called on successful login
 *   className  — string (optional)
 */

import { useState, useCallback, useRef } from "react";
import { login } from "../shared/loginBridge.js";

// ─── Keypair file parser ──────────────────────────────────────────────────────

/**
 * Parse base64url → Uint8Array (strips padding, handles + and /)
 */
function fromBase64url(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Parse the medledger-keypair-v1 JSON into the keypair shape
 * expected by loginBridge / KeysetManager.loginUser().
 *
 * @param {string} jsonText
 * @returns {{ username: string, keypair: object }}
 * @throws {Error} with a user-readable message on any parse/validation failure
 */
function parseKeypairFile(jsonText) {
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new Error("This file is not valid JSON.");
  }

  if (parsed._medledger !== "keypair-v1") {
    throw new Error(
      "This doesn't look like a MedLedger keypair file. Make sure you're uploading the file downloaded at registration."
    );
  }

  const { username, signing, exchange } = parsed;

  if (!username || typeof username !== "string") {
    throw new Error("Keypair file is missing the username field.");
  }

  const requiredFields = [
    signing?.publicKey,
    signing?.privateKey,
    exchange?.publicKey,
    exchange?.privateKey,
  ];

  if (requiredFields.some((f) => !f || typeof f !== "string")) {
    throw new Error(
      "Keypair file is incomplete — one or more key fields are missing."
    );
  }

  let keypair;
  try {
    keypair = {
      signing: {
        publicKey: fromBase64url(signing.publicKey),
        privateKey: fromBase64url(signing.privateKey),
      },
      exchange: {
        publicKey: fromBase64url(exchange.publicKey),
        privateKey: fromBase64url(exchange.privateKey),
      },
    };
  } catch {
    throw new Error(
      "One or more keys in the file could not be decoded. The file may be corrupted."
    );
  }

  return { username, keypair };
}

// ─── Component ────────────────────────────────────────────────────────────────

const MODES = { IDLE: "idle", LOADING: "loading", ERROR: "error", SUCCESS: "success" };

export function VaultUnlock({ onUnlocked, className = "" }) {
  const [mode, setMode] = useState(MODES.IDLE);
  const [errorMsg, setErrorMsg] = useState("");
  const [dragging, setDragging] = useState(false);
  const [pasteMode, setPasteMode] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const fileInputRef = useRef(null);

  // ── Core unlock logic ────────────────────────────────────────────────────────

  const unlock = useCallback(
    async (jsonText) => {
      setMode(MODES.LOADING);
      setErrorMsg("");

      let username, keypair;
      try {
        ({ username, keypair } = parseKeypairFile(jsonText));
      } catch (err) {
        setMode(MODES.ERROR);
        setErrorMsg(err.message);
        return;
      }

      try {
        const { publicKeys } = await login(username, keypair);
        setMode(MODES.SUCCESS);
        onUnlocked?.(publicKeys);
      } catch (err) {
        setMode(MODES.ERROR);
        // Translate technical errors to actionable messages
        if (err?.code === "KEYSET_BAD_KEY_FORMAT") {
          setErrorMsg(
            "The keypair file is malformed or missing required key data."
          );
        } else if (err?.status === 401) {
          setErrorMsg(
            "The server rejected this keypair. Make sure you're using the keypair for this account."
          );
        } else if (err?.code === "NETWORK_ERROR") {
          setErrorMsg(
            "Could not reach the server. Check your connection and try again."
          );
        } else {
          setErrorMsg(err?.message ?? "Login failed. Please try again.");
        }
      }
    },
    [onUnlocked]
  );

  // ── File input ───────────────────────────────────────────────────────────────

  const handleFile = useCallback(
    (file) => {
      if (!file) return;
      if (!file.name.endsWith(".json")) {
        setMode(MODES.ERROR);
        setErrorMsg("Please select a .json keypair file.");
        return;
      }
      const reader = new FileReader();
      reader.onload = (e) => unlock(e.target.result);
      reader.onerror = () => {
        setMode(MODES.ERROR);
        setErrorMsg("Could not read the file.");
      };
      reader.readAsText(file);
    },
    [unlock]
  );

  const handleFileChange = (e) => handleFile(e.target.files?.[0]);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragging(false);
      handleFile(e.dataTransfer.files?.[0]);
    },
    [handleFile]
  );

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragging(true);
  };

  const handleDragLeave = () => setDragging(false);

  // ── Paste mode ───────────────────────────────────────────────────────────────

  const handlePasteSubmit = () => {
    if (pasteText.trim()) unlock(pasteText.trim());
  };

  // ── Render ───────────────────────────────────────────────────────────────────

  const isLoading = mode === MODES.LOADING;

  return (
    <div className={`vu-root ${className}`}>
      <div className="vu-card">
        {/* Logo / heading */}
        <div className="vu-header">
          <div className="vu-lock-anim" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              <circle cx="12" cy="16" r="1" fill="currentColor" />
            </svg>
          </div>
          <h1 className="vu-title">Unlock vault</h1>
          <p className="vu-subtitle">
            Supply the keypair file you downloaded at registration.
          </p>
        </div>

        {/* Error banner */}
        {mode === MODES.ERROR && (
          <div className="vu-error" role="alert">
            <svg className="vu-icon-error" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <p>{errorMsg}</p>
          </div>
        )}

        {!pasteMode ? (
          <>
            {/* Drop zone */}
            <button
              type="button"
              className={`vu-dropzone ${dragging ? "vu-dropzone--active" : ""} ${isLoading ? "vu-dropzone--loading" : ""}`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => !isLoading && fileInputRef.current?.click()}
              aria-label="Drop keypair file or click to browse"
              disabled={isLoading}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                className="vu-file-input"
                onChange={handleFileChange}
                aria-hidden="true"
                tabIndex={-1}
              />

              {isLoading ? (
                <div className="vu-spinner" aria-label="Unlocking…">
                  <div className="vu-spinner-ring" />
                </div>
              ) : (
                <>
                  <svg className="vu-icon-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                  <span className="vu-dropzone-label">
                    {dragging
                      ? "Drop to unlock"
                      : "Drop keypair file here, or click to browse"}
                  </span>
                  <span className="vu-dropzone-hint">medledger-keypair-*.json</span>
                </>
              )}
            </button>

            {/* Paste toggle */}
            <button
              type="button"
              className="vu-toggle"
              onClick={() => setPasteMode(true)}
            >
              Paste JSON instead
            </button>
          </>
        ) : (
          <>
            {/* Paste mode */}
            <label className="vu-paste-label" htmlFor="vu-paste">
              Paste keypair JSON
            </label>
            <textarea
              id="vu-paste"
              className="vu-textarea"
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
              placeholder='{ "_medledger": "keypair-v1", … }'
              rows={7}
              spellCheck={false}
              autoComplete="off"
              disabled={isLoading}
            />

            <div className="vu-paste-actions">
              <button
                type="button"
                className="vu-btn vu-btn--primary"
                onClick={handlePasteSubmit}
                disabled={!pasteText.trim() || isLoading}
              >
                {isLoading ? "Unlocking…" : "Unlock"}
              </button>
              <button
                type="button"
                className="vu-btn vu-btn--ghost"
                onClick={() => {
                  setPasteMode(false);
                  setPasteText("");
                  setMode(MODES.IDLE);
                  setErrorMsg("");
                }}
                disabled={isLoading}
              >
                Back
              </button>
            </div>
          </>
        )}

        {/* Footer note */}
        <p className="vu-footer">
          Keys are loaded into memory only. They are never sent to any server.
        </p>
      </div>

      <style>{`
        /* ── Root ── */
        .vu-root {
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          padding: 2rem 1rem;
          background: #0f1623;
          font-family: system-ui, -apple-system, sans-serif;
        }

        .vu-card {
          background: #1a2333;
          border: 1px solid #2a3a50;
          border-radius: 14px;
          padding: 2.25rem 2rem;
          max-width: 440px;
          width: 100%;
          box-shadow: 0 32px 80px rgba(0,0,0,0.6);
        }

        /* ── Header ── */
        .vu-header {
          text-align: center;
          margin-bottom: 1.75rem;
        }

        .vu-lock-anim {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 56px;
          height: 56px;
          border-radius: 14px;
          background: rgba(0, 191, 165, 0.08);
          border: 1px solid rgba(0, 191, 165, 0.2);
          margin-bottom: 1rem;
          color: #00bfa5;
        }

        .vu-lock-anim svg {
          width: 28px;
          height: 28px;
          stroke: currentColor;
          animation: vu-lock-bob 3s ease-in-out infinite;
        }

        @keyframes vu-lock-bob {
          0%, 100% { transform: translateY(0); }
          50%       { transform: translateY(-2px); }
        }

        .vu-title {
          margin: 0 0 0.375rem;
          font-size: 1.375rem;
          font-weight: 700;
          color: #e8edf4;
          letter-spacing: -0.02em;
        }

        .vu-subtitle {
          margin: 0;
          font-size: 0.875rem;
          color: #6b7e96;
          line-height: 1.5;
        }

        /* ── Error ── */
        .vu-error {
          display: flex;
          align-items: flex-start;
          gap: 0.625rem;
          background: rgba(217, 79, 79, 0.08);
          border: 1px solid rgba(217, 79, 79, 0.25);
          border-radius: 8px;
          padding: 0.75rem 0.875rem;
          margin-bottom: 1.25rem;
          animation: vu-shake 0.3s ease;
        }

        @keyframes vu-shake {
          0%, 100% { transform: translateX(0); }
          25%       { transform: translateX(-4px); }
          75%       { transform: translateX(4px); }
        }

        .vu-icon-error {
          flex-shrink: 0;
          width: 16px;
          height: 16px;
          color: #d94f4f;
          margin-top: 1px;
        }

        .vu-error p {
          margin: 0;
          font-size: 0.84rem;
          color: #c05050;
          line-height: 1.45;
        }

        /* ── Drop zone ── */
        .vu-dropzone {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 0.625rem;
          width: 100%;
          padding: 2.5rem 1.5rem;
          border: 1.5px dashed #2a3a50;
          border-radius: 10px;
          background: #111a28;
          cursor: pointer;
          transition: border-color 0.15s, background 0.15s;
          margin-bottom: 0.75rem;
          outline-offset: 3px;
        }

        .vu-dropzone:hover:not(:disabled) {
          border-color: #00bfa5;
          background: rgba(0, 191, 165, 0.04);
        }

        .vu-dropzone--active {
          border-color: #00bfa5 !important;
          background: rgba(0, 191, 165, 0.08) !important;
        }

        .vu-dropzone--loading {
          cursor: default;
          opacity: 0.7;
        }

        .vu-file-input {
          display: none;
        }

        .vu-icon-upload {
          width: 32px;
          height: 32px;
          color: #4a6280;
          transition: color 0.15s;
        }

        .vu-dropzone:hover .vu-icon-upload,
        .vu-dropzone--active .vu-icon-upload {
          color: #00bfa5;
        }

        .vu-dropzone-label {
          font-size: 0.875rem;
          color: #8a9eb8;
          text-align: center;
        }

        .vu-dropzone-hint {
          font-size: 0.75rem;
          font-family: ui-monospace, monospace;
          color: #3d5268;
        }

        /* ── Spinner ── */
        .vu-spinner {
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 0.5rem 0;
        }

        .vu-spinner-ring {
          width: 32px;
          height: 32px;
          border: 2.5px solid #2a3a50;
          border-top-color: #00bfa5;
          border-radius: 50%;
          animation: vu-spin 0.7s linear infinite;
        }

        @keyframes vu-spin {
          to { transform: rotate(360deg); }
        }

        /* ── Toggle ── */
        .vu-toggle {
          display: block;
          width: 100%;
          background: none;
          border: none;
          cursor: pointer;
          font-size: 0.8rem;
          color: #4a6280;
          text-align: center;
          padding: 0.25rem;
          transition: color 0.12s;
          outline-offset: 2px;
          margin-bottom: 0.25rem;
        }

        .vu-toggle:hover {
          color: #00bfa5;
        }

        /* ── Paste mode ── */
        .vu-paste-label {
          display: block;
          font-size: 0.8rem;
          color: #6b7e96;
          margin-bottom: 0.5rem;
          font-weight: 500;
          letter-spacing: 0.02em;
        }

        .vu-textarea {
          width: 100%;
          background: #111a28;
          border: 1px solid #2a3a50;
          border-radius: 8px;
          padding: 0.75rem;
          font-family: ui-monospace, "Cascadia Code", monospace;
          font-size: 0.78rem;
          color: #8a9eb8;
          resize: vertical;
          outline: none;
          transition: border-color 0.15s;
          box-sizing: border-box;
          margin-bottom: 0.75rem;
          line-height: 1.5;
        }

        .vu-textarea:focus {
          border-color: #00bfa5;
        }

        .vu-paste-actions {
          display: flex;
          gap: 0.5rem;
          margin-bottom: 0.25rem;
        }

        /* ── Buttons ── */
        .vu-btn {
          flex: 1;
          padding: 0.65rem 1rem;
          border-radius: 8px;
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          border: none;
          transition: background 0.12s, opacity 0.12s;
          outline-offset: 3px;
        }

        .vu-btn:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        .vu-btn--primary {
          background: #00bfa5;
          color: #061018;
        }

        .vu-btn--primary:hover:not(:disabled) {
          background: #00d4b8;
        }

        .vu-btn--ghost {
          background: #111a28;
          color: #6b7e96;
          border: 1px solid #2a3a50;
        }

        .vu-btn--ghost:hover:not(:disabled) {
          background: #1a2a3a;
        }

        /* ── Footer ── */
        .vu-footer {
          margin: 1.25rem 0 0;
          font-size: 0.75rem;
          color: #2a3a50;
          text-align: center;
          line-height: 1.4;
        }

        /* ── Responsive ── */
        @media (max-width: 480px) {
          .vu-card {
            padding: 1.75rem 1.25rem;
          }
        }

        /* ── Reduced motion ── */
        @media (prefers-reduced-motion: reduce) {
          .vu-lock-anim svg,
          .vu-spinner-ring { animation: none; }
          .vu-error { animation: none; }
          .vu-dropzone,
          .vu-icon-upload,
          .vu-toggle,
          .vu-btn { transition: none; }
        }
      `}</style>
    </div>
  );
}
