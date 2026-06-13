// components/VaultUnlock.jsx
import { useState, useRef } from "react";
import { unlockVault, previewKeypair } from "../shared/loginBridge.js";
import { KeysetError, ERRORS } from "../key_manager/key_manager.js";

/**
 * VaultUnlock — Modal/screen for unlocking the crypto vault.
 *
 * Props:
 *   - onUnlock({ username, userIdHex, publicKeys })  → called on success
 *   - onCancel()                                     → called when user dismisses
 *   - serverPublicKeys? { signingPublicKey, exchangePublicKey }  → optional verification
 */
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

    setError("");
    setFileName(file.name);

    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const preview = await previewKeypair(parsed);
      if (!preview.valid) {
        setError(`Invalid keypair file: ${preview.error}`);
        setKeypairFile(null);
        return;
      }
      // Pre-fill username if file has one and field is empty
      if (preview.username && !username) {
        setUsername(preview.username);
      }
      setKeypairFile(parsed);
    } catch (err) {
      setError("Failed to read keypair file. Ensure it is valid JSON.");
      setKeypairFile(null);
    }
  };

  const handleUnlock = async () => {
    if (!username.trim()) {
      setError("Please enter your username.");
      return;
    }
    if (!keypairFile) {
      setError("Please select your .medledger-key.json file.");
      return;
    }

    setError("");
    setLoading(true);

    try {
      const result = await unlockVault(username.trim(), keypairFile, serverPublicKeys);
      onUnlock(result);
    } catch (err) {
      if (err instanceof KeysetError) {
        switch (err.code) {
          case ERRORS.BAD_KEY_FORMAT:
            setError("Keypair file is corrupted or does not match this account.");
            break;
          case ERRORS.SESSION_LOCKED:
            setError("Vault is already locked. Please try again.");
            break;
          default:
            setError(err.message || "Unlock failed.");
        }
      } else {
        setError(err.message || "Network or server error.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const fakeEvent = { target: { files } };
      handleFileSelect(fakeEvent);
    }
  };

  return (
    <div className="vault-unlock-overlay">
      <div className="vault-unlock-modal">
        <h2>🔐 Unlock Vault</h2>
        <p className="subtitle">
          Load your keypair file to access encrypted shares.
        </p>

        <div className="form-group">
          <label htmlFor="vault-username">Username</label>
          <input
            id="vault-username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="your_username"
            autoComplete="username"
            disabled={loading}
          />
        </div>

        <div
          className={`drop-zone ${fileName ? "has-file" : ""}`}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            onChange={handleFileSelect}
            style={{ display: "none" }}
          />
          {fileName ? (
            <span className="file-name">📄 {fileName}</span>
          ) : (
            <>
              <span className="drop-icon">📂</span>
              <span>Drop your .medledger-key.json here or click to browse</span>
            </>
          )}
        </div>

        {error && (
          <div className="error-banner" role="alert">
            {error}
          </div>
        )}

        <div className="button-row">
          <button
            className="btn-primary"
            onClick={handleUnlock}
            disabled={loading || !username || !keypairFile}
          >
            {loading ? "Unlocking…" : "Unlock Vault"}
          </button>
          <button className="btn-secondary" onClick={onCancel} disabled={loading}>
            Cancel
          </button>
        </div>

        <p className="hint">
          Lost your keypair file? You cannot recover past shares — register a new account.
        </p>
      </div>
    </div>
  );
}
