/**
 * med-login.js — Login screen.
 *
 * Flow:
 *   1. User submits email + password
 *   2a. If requires_totp → navigate to /login/totp (hash stores userIdHex)
 *   2b. If success → navigate to /unlock
 *   3. /unlock handles bundle file + passphrase
 *
 * Rendered into #med-content by router.
 */

import { login } from '../services/auth.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import './common/med-spinner.js';

function injectStyles() {
  if (document.querySelector('[data-med-auth-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-auth-styles', '');
  style.textContent = `
    .auth-card {
      max-width: 26rem;
      margin: 4rem auto 0;
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 10px;
      padding: 2rem;
    }

    .auth-card h1 {
      margin: 0 0 0.25rem;
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--color-text, #e8eaf0);
    }

    .auth-card .auth-subtitle {
      margin: 0 0 1.75rem;
      font-size: 0.875rem;
      color: var(--color-text-muted, #9ca3af);
    }

    .auth-field {
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
      margin-bottom: 1rem;
    }

    .auth-field label {
      font-size: 0.8125rem;
      font-weight: 500;
      color: var(--color-text, #e8eaf0);
    }

    .auth-field input {
      padding: 0.5rem 0.75rem;
      background: var(--color-bg, #13151a);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 6px;
      color: var(--color-text, #e8eaf0);
      font-size: 0.9rem;
      outline: none;
      transition: border-color 150ms ease;
      width: 100%;
      box-sizing: border-box;
    }

    .auth-field input:focus {
      border-color: var(--color-accent, #3b82f6);
    }

    .auth-field input.invalid {
      border-color: #e05555;
    }

    .auth-error {
      font-size: 0.8125rem;
      color: #e05555;
      margin-top: 0.25rem;
    }

    .auth-submit {
      width: 100%;
      padding: 0.625rem;
      background: var(--color-accent, #3b82f6);
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      margin-top: 0.5rem;
      transition: opacity 150ms ease;
    }

    .auth-submit:hover:not(:disabled) { opacity: 0.9; }
    .auth-submit:disabled { opacity: 0.6; cursor: not-allowed; }

    .auth-links {
      margin-top: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      align-items: center;
    }

    .auth-links a, .auth-links button {
      font-size: 0.8125rem;
      color: var(--color-accent, #3b82f6);
      background: none;
      border: none;
      cursor: pointer;
      padding: 0;
      text-decoration: underline;
      text-underline-offset: 2px;
    }
  `;
  document.head.appendChild(style);
}

class MedLogin extends HTMLElement {
  connectedCallback() {
    injectStyles();
    this._render();
    this._bindEvents();
  }

  _render() {
    this.innerHTML = `
      <div class="auth-card">
        <h1>Sign in</h1>
        <p class="auth-subtitle">MedLedger — encrypted health records</p>

        <div class="auth-field">
          <label for="login-email">Email</label>
          <input id="login-email" type="email" autocomplete="email" placeholder="you@example.com">
        </div>

        <div class="auth-field">
          <label for="login-password">Password</label>
          <input id="login-password" type="password" autocomplete="current-password" placeholder="••••••••">
          <div class="auth-error" id="login-error" hidden></div>
        </div>

        <button class="auth-submit" id="login-submit">
          <med-spinner size="sm" id="login-spinner" hidden></med-spinner>
          Sign in
        </button>

        <div class="auth-links">
          <a href="#/forgot-password">Forgot password?</a>
          <span>No account? <button id="go-register">Create one</button></span>
        </div>
      </div>
    `;
  }

  _bindEvents() {
    const emailEl    = this.querySelector('#login-email');
    const passwordEl = this.querySelector('#login-password');
    const submitBtn  = this.querySelector('#login-submit');
    const spinner    = this.querySelector('#login-spinner');
    const errorEl    = this.querySelector('#login-error');

    const setError = (msg) => {
      errorEl.textContent = msg;
      errorEl.hidden = !msg;
      if (msg) passwordEl.classList.add('invalid');
      else passwordEl.classList.remove('invalid');
    };

    const setLoading = (loading) => {
      submitBtn.disabled = loading;
      spinner.hidden = !loading;
    };

    const submit = async () => {
      setError('');
      const email    = emailEl.value.trim();
      const password = passwordEl.value;

      if (!email || !password) {
        setError('Email and password are required.');
        return;
      }

      setLoading(true);
      try {
        const result = await login(email, password);
        if (result.requiresTotp) {
          // Store userIdHex in hash so the TOTP screen can read it
          navigate(`/login/totp?uid=${encodeURIComponent(result.userIdHex)}`);
        } else {
          navigate('/unlock');
        }
      } catch (err) {
        const msg = err.body?.detail ?? 'Invalid email or password.';
        setError(typeof msg === 'string' ? msg : 'Login failed.');
      } finally {
        setLoading(false);
      }
    };

    submitBtn.addEventListener('click', submit);
    this.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submit();
    });

    this.querySelector('#go-register').addEventListener('click', () => {
      navigate('/register');
    });
  }
}

customElements.define('med-login', MedLogin);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-login></med-login>';
}
