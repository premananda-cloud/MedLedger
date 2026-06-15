// components/LoginFlow.jsx
import React, { useState } from "react";
import { useAuthWithCrypto } from "../hooks/useAuthWithCrypto";

export function LoginFlow({ onLogin }) {
  const { login, unlockCrypto, cryptoLocked } = useAuthWithCrypto();

  const [step, setStep] = useState("auth");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [keypairFile, setKeypairFile] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [publicKeys, setPublicKeys] = useState(null);

  const handleAuthLogin = async () => {
    setLoading(true);
    const result = await login(username, password, totpCode);

    if (result.success) {
      if (result.requiresKeyUnlock) {
        setPublicKeys(result.publicKeys);
        setStep("unlock_crypto");
      } else {
        onLogin({ username, authenticated: true });
      }
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleKeypairUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const keyData = JSON.parse(e.target.result);

        // Reconstruct Uint8Arrays from saved data
        const keypair = {
          signing: {
            publicKey: new Uint8Array(keyData.signingPublicKey || []),
            privateKey: new Uint8Array(keyData.signingPrivateKey),
          },
          exchange: {
            publicKey: new Uint8Array(keyData.exchangePublicKey || []),
            privateKey: new Uint8Array(keyData.exchangePrivateKey),
          },
        };

        const result = await unlockCrypto(username, keypair);

        if (result.unlocked) {
          onLogin({
            username,
            authenticated: true,
            cryptoUnlocked: true,
            publicKeys: result.publicKeys,
          });
        } else {
          setError(result.error);
        }
      } catch (err) {
        setError("Invalid keypair file format");
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-6">Login</h2>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-2 rounded mb-4">
          {error}
        </div>
      )}

      {step === "auth" && (
        <div className="space-y-4">
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
          <input
            type="text"
            placeholder="TOTP Code"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            className="w-full px-3 py-2 border rounded"
            maxLength={6}
          />
          <button
            onClick={handleAuthLogin}
            disabled={!username || !password || totpCode.length !== 6}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
          >
            {loading ? "Verifying..." : "Login"}
          </button>
        </div>
      )}

      {step === "unlock_crypto" && (
        <div className="space-y-4">
          <div className="bg-blue-50 p-4 rounded">
            <p className="text-sm text-blue-800">
              ✓ Authentication successful! Your public keys:
            </p>
            <code className="text-xs block mt-2 break-all">
              User ID: {publicKeys?.userIdHex}
              <br />
              Signing Key: {publicKeys?.signingPublicKey?.substring(0, 32)}...
            </code>
          </div>
          <div className="mt-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Upload Your Crypto Keypair File
            </label>
            <input
              type="file"
              accept=".json"
              onChange={handleKeypairUpload}
              className="w-full"
            />
            <p className="text-xs text-gray-500 mt-2">
              Upload the key file you downloaded during registration
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
