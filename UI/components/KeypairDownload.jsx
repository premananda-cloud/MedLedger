// components/KeypairDownload.jsx
import { useState } from "react";

/**
 * KeypairDownload — Post-registration prompt to save the keypair file.
 *
 * Props:
 *   - keypairResult { signingPublicKey, exchangePublicKey, userIdHex, username,
 *                     signingPrivateKey?, exchangePrivateKey? } — from KeysetManager.createUser()
 *   - onDownloaded() — called after user confirms they saved the file
 *   - onSkip()       — called if user dismisses (warns them about data loss)
 */
export default function KeypairDownload({ keypairResult, onDownloaded, onSkip }) {
  const [downloaded, setDownloaded] = useState(false);
  const [warningAck, setWarningAck] = useState(false);

  const handleDownload = () => {
    if (!keypairResult) return;

    const keypairFile = {
      version: "medledger-keypair-v1",
      username: keypairResult.username,
      userIdHex: keypairResult.userIdHex,
      signingPublicKey: keypairResult.signingPublicKey,
      exchangePublicKey: keypairResult.exchangePublicKey,
      signingPrivateKey: keypairResult.signingPrivateKey,
      exchangePrivateKey: keypairResult.exchangePrivateKey,
      createdAt: new Date().toISOString(),
    };

    const blob = new Blob([JSON.stringify(keypairFile, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${keypairResult.username}.medledger-key.json`;
    a.click();
    URL.revokeObjectURL(url);

    setDownloaded(true);
  };

  const handleSkip = () => {
    if (!warningAck) {
      // First click: show warning, require acknowledgment
      setWarningAck(true);
      return;
    }
    onSkip();
  };

  return (
    <div className="keypair-download-overlay">
      <div className="keypair-download-modal">
        <h2>🔑 Save Your Keypair</h2>

        <div className="warning-box">
          <strong>⚠️ This is your only chance to save these keys.</strong>
          <p>
            MedLedger does <strong>not</strong> store your private keys on the server.
            If you lose this file, you will <strong>permanently lose access</strong> to
            all encrypted shares and there is <strong>no recovery path</strong>.
          </p>
        </div>

        <div className="keypair-details">
          <div className="detail-row">
            <span className="label">Username:</span>
            <span className="value">{keypairResult?.username}</span>
          </div>
          <div className="detail-row">
            <span className="label">User ID:</span>
            <span className="value mono">{keypairResult?.userIdHex}</span>
          </div>
          <div className="detail-row">
            <span className="label">Signing Key:</span>
            <span className="value mono truncate">{keypairResult?.signingPublicKey}</span>
          </div>
          <div className="detail-row">
            <span className="label">Exchange Key:</span>
            <span className="value mono truncate">{keypairResult?.exchangePublicKey}</span>
          </div>
        </div>

        <div className="button-row">
          {!downloaded ? (
            <button className="btn-primary btn-download" onClick={handleDownload}>
              📥 Download {keypairResult?.username}.medledger-key.json
            </button>
          ) : (
            <button className="btn-primary btn-confirm" onClick={onDownloaded}>
              ✅ I have saved the file — Continue to App
            </button>
          )}

          <button
            className={`btn-secondary ${warningAck ? "btn-danger" : ""}`}
            onClick={handleSkip}
          >
            {warningAck
              ? "⚠️ I understand — Skip anyway (DATA LOSS RISK)"
              : "Skip for now"}
          </button>
        </div>

        {warningAck && (
          <div className="danger-banner" role="alert">
            Clicking "Skip anyway" will discard your private keys. You will need to
            re-register to get new keys. Past shares will be unrecoverable.
          </div>
        )}

        <p className="hint">
          Recommended: store this file in a password manager (1Password, Bitwarden) or
          an encrypted USB drive. Never email it or store it in plain cloud storage.
        </p>
      </div>
    </div>
  );
}
