// src/components/AuthGate.jsx (new component)
import { useState } from "react";
import { LoginFlow } from "./LoginFlow";
import { RegistrationFlow } from "./RegistrationFlow";

export function AuthGate({ onLogin, onRegister }) {
  const [mode, setMode] = useState("login");

  if (mode === "login") {
    return (
      <div>
        <LoginFlow onLogin={onLogin} />
        <button onClick={() => setMode("register")}>Create new account</button>
      </div>
    );
  }

  return (
    <div>
      <RegistrationFlow onComplete={onRegister} />
      <button onClick={() => setMode("login")}>Back to login</button>
    </div>
  );
}
