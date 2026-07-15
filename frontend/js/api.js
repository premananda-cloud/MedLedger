// api.js - Core MedLedger API Helper & Cryptographic Utilities

const DEFAULT_API_BASE_URL = "http://localhost:8000/api";

function getApiBaseUrl() {
    return localStorage.getItem("ml_api_base_url") || DEFAULT_API_BASE_URL;
}

function setApiBaseUrl(url) {
    localStorage.setItem("ml_api_base_url", url);
}

// Token Storage Helpers
function getAccessToken() {
    return localStorage.getItem("ml_access_token");
}

// Check if we are currently logged in (have access token)
function isAuthenticated() {
    return !!getAccessToken();
}

function getRefreshToken() {
    return localStorage.getItem("ml_refresh_token");
}

function getUser() {
    try {
        const u = localStorage.getItem("ml_user");
        return u ? JSON.parse(u) : null;
    } catch (e) {
        return null;
    }
}

function setTokens(tokens, user) {
    if (tokens) {
        if (tokens.access_token) localStorage.setItem("ml_access_token", tokens.access_token);
        if (tokens.refresh_token) localStorage.setItem("ml_refresh_token", tokens.refresh_token);
    }
    if (user) {
        localStorage.setItem("ml_user", JSON.stringify(user));
    }
}

function clearTokens() {
    localStorage.removeItem("ml_access_token");
    localStorage.removeItem("ml_refresh_token");
    localStorage.removeItem("ml_user");
}

// HTTP API Request Handler with Auto-Refresh
async function apiRequest(method, path, body = null, requiresAuth = true) {
    const baseUrl = getApiBaseUrl();
    const url = `${baseUrl}${path}`;
    
    const headers = {};
    if (body && !(body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
    }
    
    if (requiresAuth) {
        const token = getAccessToken();
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }
    }
    
    const config = {
        method: method.toUpperCase(),
        headers: headers
    };
    
    if (body) {
        if (body instanceof FormData) {
            config.body = body;
        } else {
            config.body = JSON.stringify(body);
        }
    }
    
    try {
        let response = await fetch(url, config);
        
        // Auto-refresh token if 401 Unauthorized
        if (response.status === 401 && requiresAuth) {
            const refreshSuccess = await attemptTokenRefresh();
            if (refreshSuccess) {
                // Retry request with new token
                const newToken = getAccessToken();
                config.headers["Authorization"] = `Bearer ${newToken}`;
                response = await fetch(url, config);
            } else {
                // Clear tokens and redirect to signin
                clearTokens();
                const signinPath = getSignInRedirectPath();
                if (window.location.pathname !== signinPath) {
                    window.location.href = signinPath;
                }
                throw new Error("Session expired. Please log in again.");
            }
        }
        
        if (!response.ok) {
            let errorText = "An error occurred";
            try {
                const errData = await response.json();
                errorText = errData.detail || errData.error || errorText;
            } catch (e) {
                errorText = await response.text();
            }
            throw new Error(errorText);
        }
        
        // Return JSON or stream/blob depending on content type
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
            return await response.json();
        }
        return response; // Return full response for non-JSON (like streaming file)
    } catch (error) {
        console.error(`API request failed: ${method} ${path}`, error);
        throw error;
    }
}

async function attemptTokenRefresh() {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;
    
    try {
        const baseUrl = getApiBaseUrl();
        const response = await fetch(`${baseUrl}/auth/refresh`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ refresh_token: refreshToken })
        });
        
        if (response.ok) {
            const data = await response.json();
            setTokens(data);
            return true;
        }
    } catch (e) {
        console.error("Token refresh failed", e);
    }
    return false;
}

function getSignInRedirectPath() {
    const path = window.location.pathname;
    if (path.includes("/dashboard/") || path.includes("/record_details/") || path.includes("/confirm_account_deletion/")) {
        return "../Sign_in_sign_up/signin.html";
    }
    if (path.includes("/reset_access_password/") || path.includes("/set_new_password/")) {
        return "../Sign_in_sign_up/signin.html";
    }
    return "signin.html";
}

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic Helpers (Web Crypto API)
// ─────────────────────────────────────────────────────────────────────────────

function hexToBytes(hex) {
    if (!hex) return new Uint8Array(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    return bytesToHex(new Uint8Array(hashBuffer));
}

// PoW Solver
async function solvePoW(challenge, difficulty) {
    const prefix = "0".repeat(difficulty);
    let nonce = 0;
    while (true) {
        const solution = nonce.toString();
        const hash = await sha256(challenge + solution);
        if (hash.startsWith(prefix)) {
            return solution;
        }
        nonce++;
        if (nonce % 1000 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
}

// Key Pair Generation — Ed25519 (signing) + X25519 (exchange).
// These produce 32-byte raw public keys; encoded as base64 they fit the
// backend's VARCHAR(64) key columns and satisfy the users.signing_public_key
// base64-decode trigger. Public keys are shared/stored as base64 throughout.
async function generateKeyPair() {
    let signingKeyPair, exchangeKeyPair;
    try {
        signingKeyPair = await crypto.subtle.generateKey(
            { name: "Ed25519" },
            true,
            ["sign", "verify"]
        );
        exchangeKeyPair = await crypto.subtle.generateKey(
            { name: "X25519" },
            true,
            ["deriveBits"]
        );
    } catch (e) {
        throw new Error("This browser does not support Ed25519/X25519 key generation. Please use an up-to-date Chrome, Edge, or Firefox.");
    }

    const rawSigningPub = new Uint8Array(await crypto.subtle.exportKey("raw", signingKeyPair.publicKey));
    const rawExchangePub = new Uint8Array(await crypto.subtle.exportKey("raw", exchangeKeyPair.publicKey));

    const signingPublicKey = bytesToBase64(rawSigningPub);
    const exchangePublicKey = bytesToBase64(rawExchangePub);

    const signingPrivJwk = await crypto.subtle.exportKey("jwk", signingKeyPair.privateKey);
    const exchangePrivJwk = await crypto.subtle.exportKey("jwk", exchangeKeyPair.privateKey);

    localStorage.setItem("ml_signing_priv", JSON.stringify(signingPrivJwk));
    localStorage.setItem("ml_exchange_priv", JSON.stringify(exchangePrivJwk));
    localStorage.setItem("ml_signing_pub", signingPublicKey);
    localStorage.setItem("ml_exchange_pub", exchangePublicKey);

    return {
        signingPublicKey,
        exchangePublicKey,
        signingPrivJwk,
        exchangePrivJwk
    };
}

async function getStoredExchangePrivateKey() {
    const jwkStr = localStorage.getItem("ml_exchange_priv");
    if (!jwkStr) return null;
    return await crypto.subtle.importKey(
        "jwk",
        JSON.parse(jwkStr),
        { name: "X25519" },
        true,
        ["deriveBits"]
    );
}

async function importExchangePublicKey(b64String) {
    const bytes = base64ToBytes(b64String);
    return await crypto.subtle.importKey(
        "raw",
        bytes,
        { name: "X25519" },
        true,
        []
    );
}

async function generateDEK() {
    return await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function deriveSharedKey(privateKey, publicKey) {
    const sharedBits = await crypto.subtle.deriveBits(
        { name: "X25519", public: publicKey },
        privateKey,
        256
    );
    const aesKeyBytes = await crypto.subtle.digest("SHA-256", sharedBits);
    return await crypto.subtle.importKey(
        "raw",
        aesKeyBytes,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypt a DEK with a Recipient's Exchange Public Key (ECIES over X25519)
async function encryptDEK(aesKeyObj, recipientPublicB64) {
    const rawDEK = await crypto.subtle.exportKey("raw", aesKeyObj);
    const rawDEKHex = bytesToHex(new Uint8Array(rawDEK));

    const ephemeralKeyPair = await crypto.subtle.generateKey(
        { name: "X25519" },
        true,
        ["deriveBits"]
    );

    const recipientPub = await importExchangePublicKey(recipientPublicB64);
    const sharedAesKeyObj = await deriveSharedKey(ephemeralKeyPair.privateKey, recipientPub);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedDEK = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sharedAesKeyObj,
        new TextEncoder().encode(rawDEKHex)
    );

    const rawEphemeralPub = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey));
    const ephemeralPublicB64 = bytesToBase64(rawEphemeralPub);

    return {
        alg: "X25519-AES-GCM-256",
        ephemeral_public_key: ephemeralPublicB64,
        ciphertext_hex: bytesToHex(new Uint8Array(encryptedDEK)),
        iv_hex: bytesToHex(iv)
    };
}

// Decrypt a DEK bundle using our exchange private key (ECIES over X25519)
async function decryptDEK(dekBundle) {
    const ourPrivateEx = await getStoredExchangePrivateKey();
    if (!ourPrivateEx) throw new Error("No private exchange key found. Restore from backup key.");

    const ephemeralPub = await importExchangePublicKey(dekBundle.ephemeral_public_key);
    const sharedAesKeyObj = await deriveSharedKey(ourPrivateEx, ephemeralPub);
    
    const ciphertext = hexToBytes(dekBundle.ciphertext_hex);
    const iv = hexToBytes(dekBundle.iv_hex);
    
    const decryptedDEKText = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        sharedAesKeyObj,
        ciphertext
    );
    
    const rawDEKHex = new TextDecoder().decode(decryptedDEKText);
    const rawDEKBytes = hexToBytes(rawDEKHex);
    
    return await crypto.subtle.importKey(
        "raw",
        rawDEKBytes,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypt file ArrayBuffer
async function encryptFile(arrayBuffer) {
    const dek = await generateDEK();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        dek,
        arrayBuffer
    );
    
    const ourPublicHex = localStorage.getItem("ml_exchange_pub");
    if (!ourPublicHex) throw new Error("Owner public key not found in storage.");
    const dekBundle = await encryptDEK(dek, ourPublicHex);
    
    return {
        ciphertextHex: bytesToHex(new Uint8Array(ciphertext)),
        ivHex: bytesToHex(iv),
        dekBundle
    };
}

// Decrypt file ciphertext bytes
async function decryptFile(ciphertextBytes, ivHex, dekBundle) {
    const dek = await decryptDEK(dekBundle);
    const iv = hexToBytes(ivHex);
    
    return await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        dek,
        ciphertextBytes
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ⭐ EXPOSE FUNCTIONS GLOBALLY ⭐
// This makes all functions available from HTML inline scripts
// ─────────────────────────────────────────────────────────────────────────────

// Core API functions
window.isAuthenticated = isAuthenticated;
window.getAccessToken = getAccessToken;
window.getRefreshToken = getRefreshToken;
window.getUser = getUser;
window.setTokens = setTokens;
window.clearTokens = clearTokens;
window.apiRequest = apiRequest;
window.attemptTokenRefresh = attemptTokenRefresh;
window.getApiBaseUrl = getApiBaseUrl;
window.setApiBaseUrl = setApiBaseUrl;
window.getSignInRedirectPath = getSignInRedirectPath;

// Crypto functions
window.generateKeyPair = generateKeyPair;
window.getStoredExchangePrivateKey = getStoredExchangePrivateKey;
window.importExchangePublicKey = importExchangePublicKey;
window.generateDEK = generateDEK;
window.deriveSharedKey = deriveSharedKey;
window.encryptDEK = encryptDEK;
window.decryptDEK = decryptDEK;
window.encryptFile = encryptFile;
window.decryptFile = decryptFile;
window.solvePoW = solvePoW;
window.sha256 = sha256;
window.bytesToBase64 = bytesToBase64;
window.base64ToBytes = base64ToBytes;
window.hexToBytes = hexToBytes;
window.bytesToHex = bytesToHex;