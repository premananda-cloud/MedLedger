import React, { useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { useKeyset } from "./hooks/useKeyset";
import { useRegister } from "./hooks/useRegister";

function App() {
  const [showRegister, setShowRegister] = useState(false);

  // Auth hook for login/logout
  const auth = useAuth();

  // Keyset hook for crypto operations
  const keyset = useKeyset();

  // Register hook for new user registration
  const register = useRegister();

  // Login form handler
  const handleLogin = async (username, keypairFile) => {
    // Parse keypair file and call auth.login()
    const success = await auth.login(username, keypairFile);
    if (success) {
      // Also unlock the crypto session
      await keyset.unlockSession(username, keypairFile);
    }
  };

  // If not authenticated, show login/register
  if (!auth.isAuthenticated) {
    return (
      <div className="auth-container">
        <h1>Welcome</h1>

        {!showRegister ? (
          // Login Form
          <div>
            <h2>Login</h2>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                // Handle login with keypair file
              }}
            >
              <input name="username" placeholder="Username" required />
              <input type="file" name="keypair" accept=".json" required />
              <button type="submit">Login</button>
            </form>
            <button onClick={() => setShowRegister(true)}>
              Create Account
            </button>
            {auth.error && <div className="error">{auth.error}</div>}
          </div>
        ) : (
          // Registration Flow
          <div>
            <h2>Create Account</h2>

            {/* Step 1: PoW */}
            {register.step === "idle" && (
              <button onClick={register.startPoW} disabled={register.loading}>
                Start Registration{" "}
              </button>
            )}

            {/* Step 2: Email */}
            {register.step === "pow" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const formData = new FormData(e.target);
                  register.submitEmail(formData.get("email"));
                }}
              >
                <input name="email" type="email" placeholder="Email" required />
                <button type="submit">Send Code</button>
              </form>
            )}

            {/* Step 3: Email Verification */}
            {register.step === "emailVerify" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const formData = new FormData(e.target);
                  register.verifyEmailCode(formData.get("code"));
                }}
              >
                <input name="code" placeholder="6-digit code" required />
                <button type="submit">Verify Email</button>
              </form>
            )}

            {/* Step 4: TOTP Setup */}
            {register.step === "totp" && register.totpInfo && (
              <div>
                <h3>Setup 2FA</h3>
                <p>Scan this QR code with Google Authenticator:</p>
                <img src={register.totpInfo.qrCodeUri} alt="TOTP QR Code" />
                <p>Or enter this key manually: {register.totpInfo.manualKey}</p>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    const formData = new FormData(e.target);
                    register.verifyTOTP(formData.get("totp"));
                  }}
                >
                  <input name="totp" placeholder="6-digit TOTP" required />
                  <button type="submit">Verify TOTP</button>
                </form>
              </div>
            )}

            {/* Step 5: Create Account */}
            {register.step === "createAccount" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const formData = new FormData(e.target);
                  register.createAccount(
                    formData.get("username"),
                    formData.get("password"),
                  );
                }}
              >
                <input
                  name="username"
                  placeholder="Username (min 2 chars)"
                  required
                />
                <input
                  name="password"
                  type="password"
                  placeholder="Password (min 8 chars)"
                  required
                />
                <button type="submit">Create Account</button>
              </form>
            )}

            {/* Step 6: Download Keypair */}
            {register.step === "keypairReady" && register.keypair && (
              <div>
                <h3>Save Your Keypair!</h3>
                <p className="warning">
                  ⚠️ IMPORTANT: Download and save this keypair file. You'll need
                  it to log in. This is the only time it's shown!
                </p>
                <button
                  onClick={() => {
                    const keypairJson = JSON.stringify({
                      signing: {
                        publicKey: Array.from(
                          register.keypair.signing.publicKey,
                        ),
                        privateKey: Array.from(
                          register.keypair.signing.privateKey,
                        ),
                      },
                      exchange: {
                        publicKey: Array.from(
                          register.keypair.exchange.publicKey,
                        ),
                        privateKey: Array.from(
                          register.keypair.exchange.privateKey,
                        ),
                      },
                    });
                    const blob = new Blob([keypairJson], {
                      type: "application/json",
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `${register.publicKeys?.username}_keypair.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                    register.clearKeypair();
                    setShowRegister(false);
                  }}
                >
                  Download Keypair & Continue to Login
                </button>
              </div>
            )}

            <button
              onClick={() => {
                register.reset();
                setShowRegister(false);
              }}
            >
              Back to Login
            </button>

            {register.error && <div className="error">{register.error}</div>}
          </div>
        )}
      </div>
    );
  }

  // Authenticated - Main App
  return (
    <div className="app">
      <header>
        <h1>Secure App</h1>
        <div className="user-info">
          <span>User: {auth.publicKeys?.username}</span>
          <button onClick={auth.logout}>Logout</button>
        </div>
      </header>

      <main>
        <div className="crypto-status">
          <h3>Crypto Status: {keyset.vaultStatus}</h3>
          {keyset.isLocked && (
            <button
              onClick={() => {
                // Re-prompt for keypair to unlock
                const input = document.createElement("input");
                input.type = "file";
                input.onchange = async (e) => {
                  const file = e.target.files[0];
                  const text = await file.text();
                  const keypair = JSON.parse(text);
                  await keyset.unlockSession(
                    auth.publicKeys?.username,
                    keypair,
                  );
                };
                input.click();
              }}
            >
              Unlock Vault
            </button>
          )}
        </div>

        {/* Your app content here */}
        <div className="content">
          <h2>Welcome to your secure dashboard</h2>
          <p>Crypto session is {keyset.isUnlocked ? "unlocked" : "locked"}</p>
        </div>
      </main>
    </div>
  );
}

export default App;
