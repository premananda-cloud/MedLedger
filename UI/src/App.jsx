// src/App.jsx
import { useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { useKeyset } from "./hooks/useKeyset";
import { LoginFlow } from "./components/LoginFlow";
import { RegistrationFlow } from "./components/RegistrationFlow";
import { VaultUnlock } from "./components/VaultUnlock";
import Dashboard from "./components/Dashboard";
import { ErrorBoundary } from "./components/ErrorBoundary";

export default function App() {
  const { isAuthenticated, login } = useAuth();
  const { isUnlocked, initialized, unlockSession, isLoading } = useKeyset();
  const [showRegistration, setShowRegistration] = useState(false);

  // Handle login
  const handleLogin = async (username, keypair) => {
    const success = await login(username, keypair);
    if (success) {
      // React will re-render due to state change
    }
  };

  // Handle unlock
  const handleUnlock = async (keypair) => {
    const success = await unlockSession(keypair);
    if (success) {
      // React will re-render
    }
  };

  // Handle registration complete
  const handleRegistrationComplete = ({ username, email }) => {
    // Switch back to login after successful registration
    setShowRegistration(false);
    // You might want to show a success message here
    console.log(`Account created for ${username} (${email})`);
  };

  // Loading state
  if (isLoading || !initialized) {
    return (
      <div className="auth-root">
        <div className="auth-card">
          <p>Loading your vault...</p>
        </div>
      </div>
    );
  }

  // Screen decision tree
  if (!isAuthenticated) {
    if (showRegistration) {
      return (
        <div>
          <RegistrationFlow onComplete={handleRegistrationComplete} />
          <div style={{ textAlign: "center", marginTop: "1rem" }}>
            <button
              onClick={() => setShowRegistration(false)}
              className="btn btn--ghost"
            >
              ← Back to login
            </button>
          </div>
        </div>
      );
    }

    return (
      <div>
        <LoginFlow onLogin={handleLogin} />
        <div style={{ textAlign: "center", marginTop: "1rem" }}>
          <button
            onClick={() => setShowRegistration(true)}
            className="btn btn--ghost"
          >
            Create new account
          </button>
        </div>
      </div>
    );
  }

  if (!isUnlocked) {
    return <VaultUnlock onUnlocked={handleUnlock} />;
  }

  return <Dashboard />;
}
