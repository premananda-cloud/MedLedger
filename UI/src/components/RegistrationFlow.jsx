// components/RegistrationFlow.jsx
import React, { useState } from "react";
import { useAuthWithCrypto } from "../hooks/useAuthWithCrypto";
import { KeypairSaveDialog } from "./KeypairSaveDialog";
import QRCode from "qrcode.react";

export function RegistrationFlow({ onComplete }) {
  const {
    initialized,
    registrationState,
    startRegistration,
    verifyPoW,
    submitEmail,
    verifyEmailCode,
    verifyTOTP,
    createAccount,
  } = useAuthWithCrypto();

  const [step, setStep] = useState("init");
  const [email, setEmail] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [sessionToken, setSessionToken] = useState(null);
  const [totpInfo, setTotpInfo] = useState(null);
  const [generatedKeys, setGeneratedKeys] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // Step 1: Get PoW challenge
  const handleStart = () => {
    const challenge = startRegistration();
    setStep("pow");
    solvePoW(challenge.data);
  };

  // Simulate PoW solving (in production, this would be client-side computation)
  const solvePoW = async (challenge) => {
    setLoading(true);
    // This would be actual PoW solving in production
    // For demo, we'll simulate with a timeout
    setTimeout(async () => {
      const result = await verifyPoW(challenge.challenge_id, "simulated_nonce");
      if (result.success) {
        setSessionToken(result.sessionToken);
        setStep("email");
      } else {
        setError(result.error);
      }
      setLoading(false);
    }, 1000);
  };

  // Step 2: Submit email
  const handleSubmitEmail = async () => {
    setLoading(true);
    const result = await submitEmail(sessionToken, email);
    if (result.success) {
      setStep("verify_email");
      alert(
        `Verification code sent to ${email}. Check console for code (demo mode).`,
      );
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  // Step 3: Verify email code
  const handleVerifyEmail = async () => {
    setLoading(true);
    const result = await verifyEmailCode(sessionToken, emailCode);
    if (result.success) {
      setTotpInfo(result.totpInfo);
      setStep("totp_setup");
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  // Step 4: Verify TOTP
  const handleVerifyTOTP = async () => {
    setLoading(true);
    const result = await verifyTOTP(sessionToken, totpCode);
    if (result.success) {
      setStep("create_account");
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  // Step 5: Create account with keys
  const handleCreateAccount = async () => {
    setLoading(true);
    const result = await createAccount(sessionToken, username, password);
    if (result.success) {
      setGeneratedKeys(result.keys);
      setStep("save_keys");
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleKeysSaved = () => {
    onComplete({
      username,
      email,
      keysSaved: true,
    });
  };

  if (!initialized) {
    return <div>Initializing secure environment...</div>;
  }

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-6">Create Account</h2>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-2 rounded mb-4">
          {error}
        </div>
      )}

      {step === "init" && (
        <button
          onClick={handleStart}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
        >
          Start Registration
        </button>
      )}

      {step === "pow" && loading && (
        <div className="text-center">Verifying security challenge...</div>
      )}

      {step === "email" && (
        <div className="space-y-4">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
          <button
            onClick={handleSubmitEmail}
            disabled={!email}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
          >
            Send Verification Code
          </button>
        </div>
      )}

      {step === "verify_email" && (
        <div className="space-y-4">
          <input
            type="text"
            placeholder="6-digit code"
            value={emailCode}
            onChange={(e) => setEmailCode(e.target.value)}
            className="w-full px-3 py-2 border rounded"
            maxLength={6}
          />
          <button
            onClick={handleVerifyEmail}
            disabled={emailCode.length !== 6}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
          >
            Verify Email
          </button>
        </div>
      )}

      {step === "totp_setup" && totpInfo && (
        <div className="space-y-4">
          <div className="text-center">
            <h3 className="font-bold mb-2">
              Scan QR Code with Authenticator App
            </h3>
            <QRCode value={totpInfo.qrCodeUri} size={200} className="mx-auto" />
            <p className="text-sm text-gray-600 mt-2">
              Or enter key manually:{" "}
              <code className="bg-gray-100 px-2 py-1 rounded">
                {totpInfo.manualKey}
              </code>
            </p>
          </div>
          <input
            type="text"
            placeholder="Enter 6-digit code from app"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            className="w-full px-3 py-2 border rounded"
            maxLength={6}
          />
          <button
            onClick={handleVerifyTOTP}
            disabled={totpCode.length !== 6}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
          >
            Verify TOTP
          </button>
        </div>
      )}

      {step === "create_account" && (
        <div className="space-y-4">
          <input
            type="text"
            placeholder="Username (3-30 chars, alphanumeric + underscore)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
          <input
            type="password"
            placeholder="Password (min 8 chars, 3 of 5 complexity)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
          <button
            onClick={handleCreateAccount}
            disabled={!username || !password}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
          >
            Create Account & Generate Keys
          </button>
        </div>
      )}

      {step === "save_keys" && generatedKeys && (
        <KeypairSaveDialog
          keys={generatedKeys}
          onSaved={handleKeysSaved}
          onSkip={() =>
            alert(
              "WARNING: Without saved keys, you will lose access to encrypted data!",
            )
          }
        />
      )}
    </div>
  );
}
