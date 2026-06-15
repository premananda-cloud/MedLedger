// App.jsx - Complete integration example
import React, { useState } from "react";
import { AuthProvider } from "./hooks/useAuthWithCrypto";
import { RegistrationFlow } from "./components/RegistrationFlow";
import { LoginFlow } from "./components/LoginFlow";

function SecureDashboard({ user }) {
  const { encryptFile, signData, cryptoLocked } = useAuthWithCrypto();
  const [encryptedResult, setEncryptedResult] = useState(null);

  const handleEncryptFile = async () => {
    // Example: Encrypt a file for a recipient
    const fileBytes = new TextEncoder().encode("Secret medical record content");
    const recipientPublicKey = "base64_encoded_recipient_public_key";

    try {
      const result = encryptFile(fileBytes, recipientPublicKey);
      setEncryptedResult(result);
      console.log("File encrypted successfully:", result);
    } catch (error) {
      console.error("Encryption failed:", error);
    }
  };

  const handleSignData = () => {
    const payload = {
      action: "grant_access",
      patientId: "12345",
      expiresAt: Date.now() + 86400000,
    };

    try {
      const signed = signData(payload);
      console.log("Signed payload:", signed);
      alert(`Signature created: ${signed.signature.substring(0, 32)}...`);
    } catch (error) {
      console.error("Signing failed:", error);
    }
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Welcome, {user.username}!</h1>

      <div className="bg-yellow-100 p-4 rounded mb-4">
        <p>Crypto Status: {cryptoLocked ? "🔒 Locked" : "🔓 Unlocked"}</p>
      </div>

      <div className="space-x-4">
        <button
          onClick={handleEncryptFile}
          disabled={cryptoLocked}
          className="bg-green-600 text-white px-4 py-2 rounded disabled:bg-gray-400"
        >
          Encrypt Test File
        </button>

        <button
          onClick={handleSignData}
          disabled={cryptoLocked}
          className="bg-purple-600 text-white px-4 py-2 rounded disabled:bg-gray-400"
        >
          Sign Test Data
        </button>
      </div>

      {encryptedResult && (
        <div className="mt-4 p-4 bg-gray-100 rounded">
          <h3 className="font-bold">Encryption Result:</h3>
          <pre className="text-xs overflow-auto">
            {JSON.stringify(encryptedResult, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function App() {
  const [view, setView] = useState("login");
  const [user, setUser] = useState(null);

  const handleRegistrationComplete = (userData) => {
    console.log("Registration complete:", userData);
    setView("login");
  };

  const handleLoginComplete = (session) => {
    setUser(session);
    setView("dashboard");
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="container mx-auto">
        <nav className="bg-white shadow mb-6">
          <div className="px-6 py-4 flex justify-between">
            <h1 className="text-xl font-bold">MedLedger Secure Health</h1>
            <div>
              {user && (
                <button
                  onClick={() => {
                    setUser(null);
                    setView("login");
                  }}
                  className="text-red-600"
                >
                  Logout
                </button>
              )}
            </div>
          </div>
        </nav>

        {view === "login" && (
          <>
            <div className="flex justify-center space-x-4 mb-4">
              <button
                onClick={() => setView("login")}
                className="px-4 py-2 bg-blue-600 text-white rounded"
              >
                Login
              </button>
              <button
                onClick={() => setView("register")}
                className="px-4 py-2 bg-gray-600 text-white rounded"
              >
                Register
              </button>
            </div>
            <LoginFlow onLogin={handleLoginComplete} />
          </>
        )}

        {view === "register" && (
          <RegistrationFlow onComplete={handleRegistrationComplete} />
        )}

        {view === "dashboard" && user && <SecureDashboard user={user} />}
      </div>
    </div>
  );
}

// Wrap with provider
export default function AppWithProvider() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}
