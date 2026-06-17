// components/LoginFlow.jsx
import { useState, useCallback } from "react";
import { useAuth } from "../hooks/useAuth";

/**
 * LoginFlow
 *
 * Auth flow per hooks_guide:
 *   useAuth.login(username, keypair) → boolean
 *
 * The keypair file format is set by KeypairSaveDialog (version:1, hex-encoded keys)
 * and KeypairDownload (_medledger:"keypair-v1", base64url-encoded keys).
 * Both formats are supported here.
 *
 * Props:
 *   onLogin — () => void   called after successful login
 */
export function LoginFlow({ onLogin }) {
  const { login, loading, error, clearError } = useAuth();

  const [username, setUsername] = useState("");
  const [keypair, setKeypair]   = useState(null);
  const [fileError, setFileError] = useState(null);
  const [fileName, setFileName]   = useState(null);

  const displayError = fileError || error;

  // ── Keypair file parsing ──────────────────────────────────────────────────

  /** base64url → Uint8Array */
  function fromBase64url(str) {
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  }

  /** hex → Uint8Array */
  function fromHex(hex) {
    if (!hex || hex.length % 2 !== 0) throw new Error("Invalid hex string.");
    return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  }

  /**
   * Parses both keypair file variants:
   *   - KeypairDownload: { _medledger: "keypair-v1", signing/exchange: base64url }
   *   - KeypairSaveDialog: { version: 1, signing/exchange: hex }
   */
  function parseKeypairFile(jsonText) {
    let parsed;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      throw new Error("This file is not valid JSON.");
    }

    const isMedledger = parsed._medledger === "keypair-v1";
    const isEnvoi     = parsed.version === 1 && parsed.signing?.privateKey;

    if (!isMedledger && !isEnvoi) {
      throw new Error(
        "Unrecognised keypair file. Upload the file you downloaded at registration."
      );
    }

    const { username: fileUsername, signing, exchange } = parsed;

    if (!signing?.privateKey || !exchange?.privateKey) {
      throw new Error("Keypair file is incomplete — private key fields are missing.");
    }

    const decode = isMedledger ? fromBase64url : fromHex;

    try {
      return {
        username: fileUsername ?? null,
        keypair: {
          signing: {
            publicKey:  signing.publicKey  ? decode(signing.publicKey)  : new Uint8Array(0),
            privateKey: decode(signing.privateKey),
          },
          exchange: {
            publicKey:  exchange.publicKey  ? decode(exchange.publicKey)  : new Uint8Array(0),
            privateKey: decode(exchange.privateKey),
          },
        },
      };
    } catch {
      throw new Error("One or more keys could not be decoded. The file may be corrupted.");
    }
  }

  // ── File upload handler ───────────────────────────────────────────────────

  const handleFile = useCallback((e) => {
    setFileError(null);
    clearError();
    setKeypair(null);
    setFileName(null);

    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith(".json")) {
      setFileError("Please select a .json keypair file.");
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => setFileError("Could not read the file.");
    reader.onload  = (ev) => {
      try {
        const { username: fileUsername, keypair: parsed } = parseKeypairFile(ev.target.result);
        // Pre-fill username from file if the field is still empty
        if (fileUsername && !username) setUsername(fileUsername);
        setKeypair(parsed);
        setFileName(file.name);
      } catch (err) {
        setFileError(err.message);
      }
    };
    reader.readAsText(file);
  }, [username, clearError]);

  // ── Submit ────────────────────────────────────────────────────────────────

  const handleLogin = useCallback(async () => {
    if (!keypair || !username.trim()) return;
    clearError();
    const success = await login(username.trim(), keypair);
    if (success) onLogin?.();
  }, [keypair, username, login, clearError, onLogin]);

  const canSubmit = !!keypair && !!username.trim() && !loading;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="auth-root">
      <div className="auth-card stack stack-20">
        <div className="stack stack-4">
          <h1 className="auth-title">Sign in</h1>
          <p className="text-muted" style={{ fontSize: "0.875rem" }}>
            Upload the keypair file you saved at registration.
          </p>
        </div>

        {displayError && (
          <p className="error-msg" role="alert">{displayError}</p>
        )}

        {/* Username */}
        <div className="field">
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            type="text"
            value={username}
            onChange={(e) => { clearError(); setFileError(null); setUsername(e.target.value); }}
            placeholder="your-username"
            autoComplete="username"
            spellCheck={false}
            disabled={loading}
          />
        </div>

        {/* Keypair file */}
        <div className="field">
          <label htmlFor="login-keypair">Keypair file</label>
          <input
            id="login-keypair"
            type="file"
            accept=".json"
            onChange={handleFile}
            disabled={loading}
          />
          {fileName && !fileError && (
            <span className="text-faint" style={{ fontSize: "0.8125rem" }}>
              ✓ {fileName}
            </span>
          )}
        </div>

        <button
          className="btn btn--primary btn--full"
          onClick={handleLogin}
          disabled={!canSubmit}
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </div>
    </div>
  );
}
