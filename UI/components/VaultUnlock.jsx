// components/VaultUnlock.jsx
import React, { useState } from "react";

export function VaultUnlock({ onUnlock, username }) {
  const [keypairFile, setKeypairFile] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file && file.name.endsWith(".medledger-key.json")) {
      setKeypairFile(file);
      setError(null);
    } else {
      setError("Please select a valid .medledger-key.json file");
      setKeypairFile(null);
    }
  };

  const handleUnlock = async () => {
    if (!keypairFile) {
      setError("Please select your keypair file");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // The server public keys would come from props or context
      const serverPublicKeys = {
        signingPublicKey: props.serverPublicKeys?.signingPublicKey,
        exchangePublicKey: props.serverPublicKeys?.exchangePublicKey,
      };

      await onUnlock(keypairFile, serverPublicKeys);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="vault-unlock">
      <h2>Unlock Vault</h2>
      <p>
        Username: <strong>{username}</strong>
      </p>
      <p>Please upload your keypair file to unlock encrypted operations.</p>

      <div className="file-input">
        <label htmlFor="keypair-file">
          Keypair File (.medledger-key.json):
        </label>
        <input
          type="file"
          id="keypair-file"
          accept=".json"
          onChange={handleFileChange}
        />
      </div>

      {error && <div className="error">{error}</div>}

      <button onClick={handleUnlock} disabled={!keypairFile || loading}>
        {loading ? "Unlocking..." : "Unlock Vault"}
      </button>

      <div className="info">
        <strong>Lost your keypair file?</strong>
        <p>
          Unfortunately, you cannot recover encrypted data without it. You can
          still log in, but you won't be able to decrypt shares or create new
          encrypted shares.
        </p>
      </div>
    </div>
  );
}
