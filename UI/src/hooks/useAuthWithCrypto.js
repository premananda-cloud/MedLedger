/**
 * useAuthWithCrypto — compatibility shim
 *
 * LoginFlow.jsx and RegistrationFlow.jsx import from this path.
 * The real implementation lives in useAuth.js; we re-export it here
 * so nothing needs to change in the existing components.
 *
 * All API surface is identical to useAuth:
 *   isAuthenticated, publicKeys, loading, error,
 *   login(username, keypair), logout(), clearError()
 */
export { useAuth as useAuthWithCrypto } from "./useAuth.js";
