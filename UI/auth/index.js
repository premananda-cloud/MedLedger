// auth/index.js - Main entry point
export { getAuthFlow } from "./orchestrator/authFlow.js";
export { getPoW } from "./modules/pow.js";
export { getEmailVerifier } from "./modules/email.js";
export { getTOTPManager } from "./modules/totp.js";
export { getUserManager } from "./modules/user.js";
export { getStorage, Storage } from "./modules/storage.js";

// Re-export for convenience
export { AuthFlow } from "./orchestrator/authFlow.js";
export { PoW } from "./modules/pow.js";
export { EmailVerifier } from "./modules/email.js";
export { TOTPManager } from "./modules/totp.js";
export { UserManager } from "./modules/user.js";
