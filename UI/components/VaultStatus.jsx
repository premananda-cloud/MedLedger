// components/VaultStatus.jsx
import { useState, useEffect } from "react";
import { KeysetManager } from "../key_manager/key_manager.js";

/**
 * VaultStatus — Small indicator showing whether the crypto vault is locked/unlocked.
 *
 * Props:
 *   - onUnlockRequest() → called when user clicks to unlock (shows VaultUnlock modal)
 *   - onLockRequest()   → called when user clicks to lock
 *   - compact?          → if true, renders as a small inline badge instead of a card
 */
export default function VaultStatus({ onUnlockRequest, onLockRequest, compact = false }) {
  const [locked, setLocked] = useState(true);
  const [keys, setKeys] = useState(null);

  useEffect(() => {
    // Poll vault status every 2s (cheap check, no network)
    const check = () => {
      const isLocked = KeysetManager.isLocked();
      setLocked(isLocked);
      if (!isLocked) {
        try {
          const k = KeysetManager.getPublicKeys();
          setKeys(k);
        } catch {
          setKeys(null);
        }
      } else {
        setKeys(null);
      }
    };
    check();
    const id = setInterval(check, 2000);
    return () => clearInterval(id);
  }, []);

  if (compact) {
    return (
      <button
        className={`vault-badge ${locked ? "locked" : "unlocked"}`}
        onClick={locked ? onUnlockRequest : onLockRequest}
        title={locked ? "Vault locked — click to unlock" : "Vault unlocked — click to lock"}
      >
        {locked ? "🔒 Locked" : "🔓 Unlocked"}
      </button>
    );
  }

  return (
    <div className={`vault-status-card ${locked ? "locked" : "unlocked"}`}>
      <div className="status-header">
        <span className="status-icon">{locked ? "🔒" : "🔓"}</span>
        <span className="status-text">
          {locked ? "Vault Locked" : "Vault Unlocked"}
        </span>
      </div>

      {!locked && keys && (
        <div className="key-summary">
          <div className="key-row">
            <span className="key-label">User:</span>
            <span className="key-value">{keys.username}</span>
          </div>
          <div className="key-row">
            <span className="key-label">ID:</span>
            <span className="key-value mono">{keys.userIdHex}</span>
          </div>
          <div className="key-row">
            <span className="key-label">Signing:</span>
            <span className="key-value mono truncate">{keys.signingPublicKey}</span>
          </div>
          <div className="key-row">
            <span className="key-label">Exchange:</span>
            <span className="key-value mono truncate">{keys.exchangePublicKey}</span>
          </div>
        </div>
      )}

      <div className="status-actions">
        {locked ? (
          <button className="btn-primary" onClick={onUnlockRequest}>
            Unlock Vault
          </button>
        ) : (
          <button className="btn-secondary" onClick={onLockRequest}>
            Lock Vault
          </button>
        )}
      </div>

      {locked && (
        <p className="status-hint">
          Unlock to decrypt received shares and sign outgoing grants.
        </p>
      )}
    </div>
  );
}
