/**
 * VaultStatus.jsx
 *
 * Compact vault status badge for nav bars / headers.
 *
 * Per hooks_guide, this component owns its own useKeyset() call.
 * The old prop-driven API (locked, publicKeys, onLock, onUnlock) is gone —
 * callers just render <VaultStatus compact /> or <VaultStatus />.
 *
 * Props:
 *   compact   — boolean (default false)  shrinks the label for tight headers
 *   className — string (optional)
 */

import { useRef, useState } from "react";
import { useKeyset } from "../hooks/useKeyset";

/** Truncate a hex string to a readable fingerprint: first 6 + last 4 chars. */
function fingerprint(hex) {
  if (!hex || hex.length < 10) return hex ?? "";
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

export default function VaultStatus({ compact = false, className = "" }) {
  const {
    vaultStatus,
    VAULT_STATUS,
    isUnlocked,
    publicKeys,
    lockSession,
  } = useKeyset();

  const [showConfirm, setShowConfirm] = useState(false);
  const confirmRef  = useRef(null);
  const isLocked    = vaultStatus !== VAULT_STATUS.UNLOCKED;

  const handleStatusClick = () => {
    if (isUnlocked) {
      setShowConfirm(true);
      setTimeout(() => confirmRef.current?.focus(), 50);
    }
    // If locked/uninitialized, clicking does nothing from here —
    // the parent (App.jsx) controls routing to VaultUnlock.
  };

  const handleConfirmLock = () => {
    setShowConfirm(false);
    lockSession();
  };

  // Label text
  let label;
  if (vaultStatus === VAULT_STATUS.UNINITIALIZED) {
    label = compact ? "…" : "Initialising…";
  } else if (isLocked) {
    label = "Locked";
  } else {
    label = publicKeys?.username ?? "Unlocked";
  }

  return (
    <div
      className={`vs-root ${isLocked ? "vs-root--locked" : "vs-root--unlocked"} ${className}`}
    >
      {/* Status pill */}
      <button
        type="button"
        className="vs-status-btn"
        onClick={handleStatusClick}
        aria-label={
          isLocked
            ? "Vault locked"
            : `Vault unlocked as ${publicKeys?.username ?? "unknown"} — click to lock`
        }
        title={isUnlocked ? "Click to lock vault" : undefined}
        disabled={vaultStatus === VAULT_STATUS.UNINITIALIZED}
      >
        <span className="vs-icon" aria-hidden="true">
          {isLocked ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                 strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                 strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 9.9-1" />
            </svg>
          )}
        </span>

        {!compact && <span className="vs-label">{label}</span>}

        {/* Fingerprint — only when unlocked */}
        {isUnlocked && publicKeys?.userIdHex && !compact && (
          <span className="vs-fingerprint" title={`User ID: ${publicKeys.userIdHex}`}>
            {fingerprint(publicKeys.userIdHex)}
          </span>
        )}

        <span className="vs-pip" aria-hidden="true" />
      </button>

      {/* Lock confirmation popover */}
      {showConfirm && isUnlocked && (
        <div className="vs-confirm" role="dialog" aria-label="Confirm lock">
          <p className="vs-confirm-msg">Lock vault and wipe session keys?</p>
          <div className="vs-confirm-actions">
            <button
              ref={confirmRef}
              type="button"
              className="vs-confirm-btn vs-confirm-btn--lock"
              onClick={handleConfirmLock}
            >
              Lock
            </button>
            <button
              type="button"
              className="vs-confirm-btn vs-confirm-btn--cancel"
              onClick={() => setShowConfirm(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <style>{`
        .vs-root {
          position: relative;
          display: inline-flex;
          align-items: center;
          font-family: system-ui, -apple-system, sans-serif;
        }

        .vs-status-btn {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.375rem 0.75rem 0.375rem 0.5rem;
          border-radius: 999px;
          border: 1px solid transparent;
          background: transparent;
          cursor: pointer;
          font-size: 0.8rem;
          font-weight: 500;
          transition: background 0.15s, border-color 0.15s;
          outline-offset: 3px;
        }

        .vs-status-btn:disabled {
          cursor: default;
          opacity: 0.5;
        }

        .vs-root--locked .vs-status-btn {
          color: #6b7e96;
          border-color: #2a3a50;
          background: #111a28;
        }

        .vs-root--locked .vs-status-btn:hover:not(:disabled) {
          background: #1a2a3a;
          border-color: #3a4e66;
        }

        .vs-root--unlocked .vs-status-btn {
          color: #00bfa5;
          border-color: rgba(0, 191, 165, 0.25);
          background: rgba(0, 191, 165, 0.06);
        }

        .vs-root--unlocked .vs-status-btn:hover {
          background: rgba(0, 191, 165, 0.1);
          border-color: rgba(0, 191, 165, 0.4);
        }

        .vs-icon {
          display: flex;
          align-items: center;
          flex-shrink: 0;
        }

        .vs-icon svg {
          width: 14px;
          height: 14px;
        }

        .vs-label {
          white-space: nowrap;
          max-width: 120px;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .vs-fingerprint {
          font-family: ui-monospace, "Cascadia Code", monospace;
          font-size: 0.7rem;
          letter-spacing: 0.04em;
          opacity: 0.6;
          white-space: nowrap;
        }

        .vs-pip {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          flex-shrink: 0;
        }

        .vs-root--locked .vs-pip {
          background: #4a6280;
        }

        .vs-root--unlocked .vs-pip {
          background: #00bfa5;
          box-shadow: 0 0 0 2px rgba(0, 191, 165, 0.25);
          animation: vs-pulse 2.5s ease-in-out infinite;
        }

        @keyframes vs-pulse {
          0%, 100% { box-shadow: 0 0 0 2px rgba(0, 191, 165, 0.25); }
          50%       { box-shadow: 0 0 0 4px rgba(0, 191, 165, 0.08); }
        }

        .vs-confirm {
          position: absolute;
          top: calc(100% + 8px);
          right: 0;
          background: #1a2333;
          border: 1px solid #2a3a50;
          border-radius: 10px;
          padding: 0.875rem 1rem;
          min-width: 200px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.5);
          z-index: 100;
          animation: vs-pop 0.12s ease-out;
        }

        @keyframes vs-pop {
          from { opacity: 0; transform: translateY(-4px) scale(0.97); }
          to   { opacity: 1; transform: translateY(0) scale(1); }
        }

        .vs-confirm-msg {
          margin: 0 0 0.75rem;
          font-size: 0.82rem;
          color: #8a9eb8;
          line-height: 1.4;
        }

        .vs-confirm-actions {
          display: flex;
          gap: 0.5rem;
        }

        .vs-confirm-btn {
          flex: 1;
          padding: 0.4rem 0.75rem;
          border-radius: 6px;
          border: none;
          font-size: 0.8rem;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.12s;
          outline-offset: 2px;
        }

        .vs-confirm-btn--lock {
          background: rgba(217, 79, 79, 0.15);
          color: #d94f4f;
          border: 1px solid rgba(217, 79, 79, 0.25);
        }

        .vs-confirm-btn--lock:hover { background: rgba(217, 79, 79, 0.25); }

        .vs-confirm-btn--cancel {
          background: #111a28;
          color: #6b7e96;
          border: 1px solid #2a3a50;
        }

        .vs-confirm-btn--cancel:hover { background: #1a2a3a; }

        @media (prefers-reduced-motion: reduce) {
          .vs-pip { animation: none; }
          .vs-confirm { animation: none; }
          .vs-status-btn, .vs-confirm-btn { transition: none; }
        }
      `}</style>
    </div>
  );
}
