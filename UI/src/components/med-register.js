/**
 * med-register.js — Registration flow.
 *
 * Steps:
 *   1. Collect fields (email, username, password, full name)
 *   2. Validate client-side
 *   3. Solve PoW (background, spinner shown)
 *   4. Generate keys via crypto.createUser()
 *   5. POST /api/auth/register
 *   6. Gate: force bundle download before Continue is enabled
 *   7. Navigate to /verify-email
 */

import { register } from '../services/auth.js';
import { solvePoW } from '../services/pow.js';
import { createUser } from '../services/crypto.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import './common/med-spinner.js';
import authStore from '../state/authStore.js';

// Reuse auth card styles from med-login.js (injected once)
function injectStyles() {
  if (document.querySelector('[data-med-register-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-register-styles', '');
  style.textContent = `
    .bundle-gate {
      margin-top: 1.5rem;
      padding: 1rem;
      background: var(--color-bg, #13151a);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 8px;
    }

    .bundle-gate p {
      margin: 0 0 0.75rem;
      font-size: 0.875rem;
      color: var(--color-text, #e8eaf0);
      line-height: 1.5;
    }

    .bundle-gate strong {
      color: #f59e0b;
    }

    .bundle-download-btn {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background: #1a3a2a;
      border: 1px solid #34c76f;
      border-radius: 6px;
      color: #34c76f;
      font-size: 0.875rem;
      cursor: pointer;
      width: 100%;
      justify-content: center;
      transition: opacity 150ms ease;
    }

    .bundle-download-btn:hover { opacity: 0.85; }
    .bundle-download-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .bundle-checkbox-row {
      display: flex;
      align-items: flex-start;
      gap: 0.625rem;
      margin-top: 0.75rem;
    }

    .bundle-checkbox-row input[type="checkbox"] {
      width: 1rem;
      height: 1rem;
      flex-shrink: 0;
      margin-top: 0.1rem;
      cursor: pointer;
      accent-color: var(--color-accent, #3b82f6);
    }

    .bundle-checkbox-row label {
      font-size: 0.8125rem;
      color: var(--color-text-muted, #9ca3af);
      cursor: pointer;
      line-height: 1.4;
    }

    .pow-status {
      font-size: 0.8125rem;
      color: var(--color-text-muted, #9ca3af);
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.75rem;
    }
  `;
  document.head.appendChild(style);
}

class MedRegister extends HTMLElement {
  constructor() {
    super();
    this._bundleB64 = null;
    this._bundleDownloaded = false;
    this._pendingUserId = null;
    this._beforeUnloadHandler = null;
  }

  connectedCallback() {
    injectStyles();
    this._renderForm();
  }

  disconnectedCallback() {
    if (this._beforeUnloadHandler) {
      window.removeEventListener('beforeunload', this._beforeUnloadHandler);
    }
  }

  _renderForm() {
    this.innerHTML = `
      <div class="auth-card" style="max-width:30rem">
        <h1>Create account</h1>
        <p class="auth-subtitle">Your keys are generated in your browser — we never see them.</p>

        <div class="auth-field">
          <label for="reg-fullname">Full name</label>
          <input id="reg-fullname" type="text" autocomplete="name" placeholder="Ada Lovelace">
        </div>

        <div class="auth-field">
          <label for="reg-username">Username</label>
          <input id="reg-username" type="text" autocomplete="username" placeholder="ada">
        </div>

        <div class="auth-field">
          <label for="reg-email">Email</label>
          <input id="reg-email" type="email" autocomplete="email" placeholder="ada@example.com">
        </div>

        <div class="auth-field">
          <label for="reg-password">Passphrase</label>
          <input id="reg-password" type="password" autocomplete="new-password"
                 placeholder="Used to lock your key file">
          <div class="auth-error" id="reg-error" hidden></div>
        </div>

        <div class="auth-field">
          <label for="reg-password2">Confirm passphrase</label>
          <input id="reg-password2" type="password" autocomplete="new-password" placeholder="••••••••">
        </div>

        <div class="pow-status" id="pow-status" hidden>
          <med-spinner size="sm"></med-spinner>
          Generating keys and solving proof-of-work…
        </div>

        <button class="auth-submit" id="reg-submit">
          <med-spinner size="sm" id="reg-spinner" hidden></med-spinner>
          Create account
        </button>

        <div class="auth-links">
          <span>Already have an account? <button id="go-login">Sign in</button></span>
        </div>
      </div>
    `;

    this.querySelector('#reg-submit').addEventListener('click', () => this._handleSubmit());
    this.querySelector('#go-login').addEventListener('click', () => navigate('/login'));
  }

  _renderBundleGate(username) {
    // Replace form with download gate — user cannot skip this
    this.innerHTML = `
      <div class="auth-card" style="max-width:30rem">
        <h1>Save your key file</h1>

        <div class="bundle-gate">
          <p>
            <strong>This is the only copy of your encryption keys.</strong>
            If you lose this file, your records cannot be recovered.
            We do not store your private keys anywhere.
          </p>
          <button class="bundle-download-btn" id="bundle-download">
            ↓ Download medledger-keys-${escapeHtml(username)}.mledger
          </button>

          <div class="bundle-checkbox-row">
            <input type="checkbox" id="bundle-confirm">
            <label for="bundle-confirm">
              I have saved the key file in a safe location and understand I cannot recover my
              account without it.
            </label>
          </div>
        </div>

        <button class="auth-submit" id="bundle-continue" disabled style="margin-top:1rem">
          Continue to verify email
        </button>
      </div>
    `;

    const downloadBtn  = this.querySelector('#bundle-download');
    const checkbox     = this.querySelector('#bundle-confirm');
    const continueBtn  = this.querySelector('#bundle-continue');

    downloadBtn.addEventListener('click', () => {
      this._triggerDownload(username);
      this._bundleDownloaded = true;
      this._updateContinueState();
    });

    checkbox.addEventListener('change', () => this._updateContinueState());

    continueBtn.addEventListener('click', () => {
      if (this._pendingUserId) {
        navigate(`/verify-email?uid=${encodeURIComponent(this._pendingUserId)}`);
      }
    });

    // Warn if user tries to leave without downloading
    this._beforeUnloadHandler = (e) => {
      if (!this._bundleDownloaded) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', this._beforeUnloadHandler);
  }

  _updateContinueState() {
    const checkbox    = this.querySelector('#bundle-confirm');
    const continueBtn = this.querySelector('#bundle-continue');
    if (!checkbox || !continueBtn) return;
    continueBtn.disabled = !(this._bundleDownloaded && checkbox.checked);
  }

  _triggerDownload(username) {
    if (!this._bundleB64) return;
    // Decode base64 → Uint8Array → Blob
    const binary = atob(this._bundleB64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `medledger-keys-${username}.mledger`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async _handleSubmit() {
    const fullName  = this.querySelector('#reg-fullname').value.trim();
    const username  = this.querySelector('#reg-username').value.trim();
    const email     = this.querySelector('#reg-email').value.trim();
    const password  = this.querySelector('#reg-password').value;
    const password2 = this.querySelector('#reg-password2').value;
    const errorEl   = this.querySelector('#reg-error');
    const submitBtn = this.querySelector('#reg-submit');
    const spinner   = this.querySelector('#reg-spinner');
    const powStatus = this.querySelector('#pow-status');

    const setError = (msg) => {
      errorEl.textContent = msg;
      errorEl.hidden = !msg;
    };
    const setLoading = (loading) => {
      submitBtn.disabled = loading;
      spinner.hidden = !loading;
    };

    setError('');

    if (!fullName || !username || !email || !password) {
      setError('All fields are required.');
      return;
    }
    if (password !== password2) {
      setError('Passphrases do not match.');
      return;
    }
    if (password.length < 12) {
      setError('Passphrase must be at least 12 characters.');
      return;
    }

    setLoading(true);
    powStatus.hidden = false;

    try {
      // Step 1: PoW (in parallel with key generation is fine — both are CPU tasks)
      const [powResult, cryptoResult] = await Promise.all([
        solvePoW(),
        createUser(username, password),
      ]);

      powStatus.hidden = true;

      // Save bundle before network call so we can offer download even on 4xx
      this._bundleB64 = cryptoResult.bundleB64;

      // Step 2: Register
      const user = await register({
        email,
        username,
        password,
        fullName,
        signingPublicKey:  cryptoResult.signingPublicKey,
        exchangePublicKey: cryptoResult.exchangePublicKey,
      });

      this._pendingUserId = user.user_id_hex;

      // Step 3: Force bundle download gate
      this._renderBundleGate(username);

    } catch (err) {
      powStatus.hidden = true;
      setLoading(false);
      const detail = err.body?.detail;
      const msg = typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map(d => d.msg).join('; ')
          : 'Registration failed. Please try again.';
      setError(msg);
    }
  }
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

customElements.define('med-register', MedRegister);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-register></med-register>';
}
