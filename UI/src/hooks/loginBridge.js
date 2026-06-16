/**
 * shared/loginBridge.js — compatibility shim
 *
 * VaultUnlock.jsx imports { login } from "../shared/loginBridge.js".
 * The real loginBridge lives at services/loginBridge.js — re-export from there.
 */
export { login, logout, isSessionActive } from "../services/loginBridge.js";
