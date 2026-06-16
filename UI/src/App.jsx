import { useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { useKeyset } from "./hooks/useKeyset";
import LoginFlow from "./components/LoginFlow";
import RegistrationFlow from "./components/RegistrationFlow";
import VaultUnlock from "./components/VaultUnlock";
import Dashboard from "./components/Dashboard";

/*
  Screen routing:

  ┌─ not authenticated ──────────────────────────────────────────┐
  │  showRegister=false  →  LoginFlow                            │
  │  showRegister=true   →  RegistrationFlow                     │
  └──────────────────────────────────────────────────────────────┘
  ┌─ authenticated + vault locked ───────────────────────────────┐
  │  VaultUnlock                                                 │
  └──────────────────────────────────────────────────────────────┘
  ┌─ authenticated + vault unlocked ─────────────────────────────┐
  │  Dashboard                                                   │
  └──────────────────────────────────────────────────────────────┘
*/

export default function App() {
  const { isAuthenticated } = useAuth();
  const { initialized, isUnlocked } = useKeyset();
  const [showRegister, setShowRegister] = useState(false);

  // Wait for libsodium WASM to initialise before rendering anything crypto-dependent.
  if (!initialized) {
    return (
      <div className="page-center">
        <span className="text-faint text-mono">initialising…</span>
      </div>
    );
  }

  // ── Authenticated ─────────────────────────────────────────────
  if (isAuthenticated) {
    if (!isUnlocked) {
      return (
        <div className="page-center">
          <div className="card">
            <div className="wordmark">envoi</div>
            <VaultUnlock />
          </div>
        </div>
      );
    }

    return <Dashboard />;
  }

  // ── Not authenticated ─────────────────────────────────────────
  return (
    <div className="page-center">
      <div className="card">
        <div className="wordmark">envoi</div>

        {showRegister ? (
          <>
            <RegistrationFlow
              onRegistered={() => setShowRegister(false)}
            />
            <hr className="divider" />
            <p className="text-muted" style={{ textAlign: "center" }}>
              Already have an account?{" "}
              <button
                className="btn btn--ghost"
                style={{ fontSize: "0.875rem", padding: "4px 10px" }}
                onClick={() => setShowRegister(false)}
              >
                Sign in
              </button>
            </p>
          </>
        ) : (
          <>
            <LoginFlow />
            <hr className="divider" />
            <p className="text-muted" style={{ textAlign: "center" }}>
              No account?{" "}
              <button
                className="btn btn--ghost"
                style={{ fontSize: "0.875rem", padding: "4px 10px" }}
                onClick={() => setShowRegister(true)}
              >
                Register
              </button>
            </p>
          </>
        )}
      </div>
    </div>
  );
}
