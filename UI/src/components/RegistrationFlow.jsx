// components/RegistrationFlow.jsx
import { useState, useEffect } from "react";
import { useRegister } from "../hooks/useRegister";
import { KeypairSaveDialog } from "./KeypairSaveDialog";
import { QRCodeSVG } from "qrcode.react";

/**
 * RegistrationFlow
 *
 * Drives the six-step useRegister state machine:
 *   idle → pow → emailVerify → totp → createAccount → keypairReady
 *
 * Per hooks_guide:
 *   - useRegister owns all async state; no local sessionToken
 *   - startPoW() called on mount (safe, aborts any in-flight PoW)
 *   - KeypairSaveDialog receives `keypair` + `publicKeys` (not `keys`)
 *   - onConfirmed fires clearKeypair() then calls onComplete
 *
 * Props:
 *   onComplete — ({ username, email }) => void   called after keys are saved
 */
export function RegistrationFlow({ onComplete }) {
  const {
    step,
    STEPS,
    loading,
    error,
    startPoW,
    submitEmail,
    verifyEmailCode,
    totpInfo,
    verifyTOTP,
    createAccount,
    keypair,
    publicKeys,
    clearKeypair,
    reset,
  } = useRegister();

  const [email, setEmail] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [totpToken, setTotpToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  // Track whether the email submit has been sent so we can show the code input
  const [emailSent, setEmailSent] = useState(false);

  // Kick off PoW automatically — useRegister.startPoW() is safe to call on mount
  useEffect(() => {
    startPoW();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Handlers ───────────────────────────────────────────────────────────────

  async function handleSubmitEmail() {
    const result = await submitEmail(email);
    if (result) setEmailSent(true);
  }

  async function handleVerifyEmail() {
    await verifyEmailCode(emailCode);
    // On success useRegister advances step to TOTP and sets totpInfo
  }

  async function handleVerifyTOTP() {
    await verifyTOTP(totpToken);
  }

  async function handleCreateAccount() {
    await createAccount(username, password);
    // On success useRegister advances step to KEYPAIR_READY and sets keypair
  }

  function handleKeysSaved() {
    clearKeypair();
    onComplete?.({ username, email });
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  // Preparing PoW
  if (step === STEPS.IDLE || step === STEPS.POW) {
    return (
      <div className="auth-root">
        <div
          className="auth-card stack stack-16"
          style={{ textAlign: "center" }}
        >
          <p className="text-muted">
            {loading ? "Preparing registration…" : "Starting…"}
          </p>
        </div>
      </div>
    );
  }

  // Email verification
  if (step === STEPS.EMAIL_VERIFY) {
    return (
      <div className="auth-root">
        <div className="auth-card stack stack-20">
          <div className="stack stack-4">
            <h1 className="auth-title">Verify your email</h1>
            <p className="text-muted" style={{ fontSize: "0.875rem" }}>
              Enter your email address to receive a verification code.
            </p>
          </div>

          {error && (
            <p className="error-msg" role="alert">
              {error}
            </p>
          )}

          <div className="field">
            <label htmlFor="reg-email">Email address</label>
            <input
              id="reg-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
              disabled={loading || emailSent}
            />
          </div>

          {!emailSent ? (
            <button
              className="btn btn--primary btn--full"
              onClick={handleSubmitEmail}
              disabled={loading || !email.trim()}
            >
              {loading ? "Sending…" : "Send verification code"}
            </button>
          ) : (
            <>
              <div className="field">
                <label htmlFor="reg-email-code">6-digit code</label>
                <input
                  id="reg-email-code"
                  type="text"
                  inputMode="numeric"
                  value={emailCode}
                  onChange={(e) =>
                    setEmailCode(e.target.value.replace(/\D/g, ""))
                  }
                  placeholder="123456"
                  maxLength={6}
                  disabled={loading}
                  className="text-mono"
                />
              </div>
              <button
                className="btn btn--primary btn--full"
                onClick={handleVerifyEmail}
                disabled={loading || emailCode.length !== 6}
              >
                {loading ? "Verifying…" : "Verify code"}
              </button>
              <button
                className="btn btn--ghost btn--full"
                onClick={() => {
                  setEmailSent(false);
                  setEmailCode("");
                }}
                disabled={loading}
                style={{ fontSize: "0.8125rem" }}
              >
                Re-send code
              </button>
            </>
          )}
        </div>
      </div>
    );
  }

  // TOTP setup
  if (step === STEPS.TOTP) {
    return (
      <div className="auth-root">
        <div className="auth-card stack stack-20">
          <div className="stack stack-4">
            <h1 className="auth-title">Set up two-factor auth</h1>
            <p className="text-muted" style={{ fontSize: "0.875rem" }}>
              Scan the QR code with your authenticator app, then enter the
              6-digit code.
            </p>
          </div>

          {error && (
            <p className="error-msg" role="alert">
              {error}
            </p>
          )}

          {totpInfo && (
            <>
              <div style={{ display: "flex", justifyContent: "center" }}>
                <QRCodeSVG
                  value={totpInfo.qrCodeUri}
                  size={180}
                  bgColor="transparent"
                  fgColor="#e8edf4"
                />
              </div>
              <div className="field">
                <label
                  style={{ fontSize: "0.75rem", color: "var(--c-text-faint)" }}
                >
                  Or enter key manually
                </label>
                <code
                  className="text-mono"
                  style={{
                    display: "block",
                    background: "var(--c-bg)",
                    border: "1px solid var(--c-border)",
                    borderRadius: "var(--r-sm)",
                    padding: "8px 10px",
                    fontSize: "0.8125rem",
                    wordBreak: "break-all",
                    color: "var(--c-text-muted)",
                  }}
                >
                  {totpInfo.manualKey}
                </code>
              </div>
            </>
          )}

          <div className="field">
            <label htmlFor="reg-totp">Code from authenticator app</label>
            <input
              id="reg-totp"
              type="text"
              inputMode="numeric"
              value={totpToken}
              onChange={(e) => setTotpToken(e.target.value.replace(/\D/g, ""))}
              placeholder="123456"
              maxLength={6}
              disabled={loading}
              className="text-mono"
            />
          </div>

          <button
            className="btn btn--primary btn--full"
            onClick={handleVerifyTOTP}
            disabled={loading || totpToken.length !== 6}
          >
            {loading ? "Verifying…" : "Verify code"}
          </button>
        </div>
      </div>
    );
  }

  // Create account
  if (step === STEPS.CREATE_ACCOUNT) {
    return (
      <div className="auth-root">
        <div className="auth-card stack stack-20">
          <div className="stack stack-4">
            <h1 className="auth-title">Create your account</h1>
            <p className="text-muted" style={{ fontSize: "0.875rem" }}>
              Choose a username and password. Your keypair will be generated
              next.
            </p>
          </div>

          {error && (
            <p className="error-msg" role="alert">
              {error}
            </p>
          )}

          <div className="field">
            <label htmlFor="reg-username">Username</label>
            <input
              id="reg-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="min 2 characters, alphanumeric"
              autoComplete="username"
              spellCheck={false}
              disabled={loading}
            />
          </div>

          <div className="field">
            <label htmlFor="reg-password">Password</label>
            <input
              id="reg-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="min 8 characters"
              autoComplete="new-password"
              disabled={loading}
            />
          </div>

          <button
            className="btn btn--primary btn--full"
            onClick={handleCreateAccount}
            disabled={loading || !username.trim() || !password.trim()}
          >
            {loading ? "Creating account…" : "Create account and generate keys"}
          </button>
        </div>
      </div>
    );
  }

  // Keypair ready — must download before continuing
  // keypair prop name is `keypair` + `publicKeys` (not `keys`/`onSaved`)
  if (step === STEPS.KEYPAIR_READY && keypair) {
    return (
      <KeypairSaveDialog
        keypair={keypair}
        publicKeys={publicKeys}
        onConfirmed={handleKeysSaved}
      />
    );
  }

  // Fallback — should not normally be reached
  return null;
}
