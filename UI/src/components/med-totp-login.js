/**
 * med-totp-login.js — TOTP verification step after login.
 *
 * Reads ?uid= from the hash query string (set by med-login.js).
 * On success navigates to /unlock.
 */

import { verifyTotpLogin } from '../services/auth.js';
import { navigate } from '../services/router.js';
import './common/med-spinner.js';

class MedTotpLogin extends HTMLElement {
  connectedCallback() {
    const params    = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
    this._userIdHex = params.get('uid') ?? '';

    if (!this._userIdHex) {
      navigate('/login');
      return;
    }

    this.innerHTML = `
      <div class="auth-card">
        <h1>Two-factor authentication</h1>
        <p class="auth-subtitle">Enter the 6-digit code from your authenticator app.</p>

        <div class="auth-field">
          <label for="totp-code">Authenticator code</label>
          <input id="totp-code" type="text" inputmode="numeric" pattern="[0-9]*"
                 autocomplete="one-time-code" placeholder="123456" maxlength="6">
          <div class="auth-error" id="totp-error" hidden></div>
        </div>

        <button class="auth-submit" id="totp-submit">
          <med-spinner size="sm" id="totp-spinner" hidden></med-spinner>
          Verify
        </button>

        <div class="auth-links">
          <button id="go-login">← Back</button>
        </div>
      </div>
    `;

    const codeEl   = this.querySelector('#totp-code');
    const submitBtn= this.querySelector('#totp-submit');
    const spinner  = this.querySelector('#totp-spinner');
    const errorEl  = this.querySelector('#totp-error');

    const setError   = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
    const setLoading = (v)   => { submitBtn.disabled = v; spinner.hidden = !v; };

    const submit = async () => {
      setError('');
      const code = codeEl.value.trim();
      if (!code || code.length < 6) { setError('Enter your 6-digit code.'); return; }

      setLoading(true);
      try {
        await verifyTotpLogin(this._userIdHex, code);
        navigate('/unlock');
      } catch (err) {
        setError(err.body?.detail ?? 'Invalid code — try again.');
        codeEl.value = '';
        codeEl.focus();
      } finally {
        setLoading(false);
      }
    };

    submitBtn.addEventListener('click', submit);
    codeEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    this.querySelector('#go-login').addEventListener('click', () => navigate('/login'));
  }
}

customElements.define('med-totp-login', MedTotpLogin);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-totp-login></med-totp-login>';
}
