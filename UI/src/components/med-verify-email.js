/**
 * med-verify-email.js — Email verification screen.
 *
 * Reads ?uid= from the hash query string.
 * On success navigates to /unlock.
 */

import { verifyEmail, resendVerification } from '../services/auth.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import './common/med-spinner.js';
import authStore from '../state/authStore.js';

class MedVerifyEmail extends HTMLElement {
  connectedCallback() {
    const params    = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
    this._userIdHex = params.get('uid') ?? authStore.getState()._pendingUser?.user_id_hex;
    this._email     = authStore.getState()._pendingUser?.email ?? '';
    this._render();
    this._bindEvents();
  }

  _render() {
    this.innerHTML = `
      <div class="auth-card">
        <h1>Verify your email</h1>
        <p class="auth-subtitle">
          We sent a 6-digit code to <strong>${escapeHtml(this._email || 'your email')}</strong>.
          Enter it below.
        </p>

        <div class="auth-field">
          <label for="verify-code">Verification code</label>
          <input id="verify-code" type="text" inputmode="numeric" pattern="[0-9]*"
                 autocomplete="one-time-code" placeholder="123456" maxlength="6">
          <div class="auth-error" id="verify-error" hidden></div>
        </div>

        <button class="auth-submit" id="verify-submit">
          <med-spinner size="sm" id="verify-spinner" hidden></med-spinner>
          Verify email
        </button>

        <div class="auth-links">
          <button id="resend-code">Resend code</button>
        </div>
      </div>
    `;
  }

  _bindEvents() {
    const codeEl   = this.querySelector('#verify-code');
    const submitBtn= this.querySelector('#verify-submit');
    const spinner  = this.querySelector('#verify-spinner');
    const errorEl  = this.querySelector('#verify-error');

    const setError   = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
    const setLoading = (v)   => { submitBtn.disabled = v; spinner.hidden = !v; };

    const submit = async () => {
      setError('');
      const code = codeEl.value.trim();
      if (!code || code.length < 6) { setError('Enter the 6-digit code.'); return; }
      if (!this._userIdHex)         { setError('Session expired — please register again.'); return; }

      setLoading(true);
      try {
        await verifyEmail(this._userIdHex, code);
        toast.success('Email verified! Upload your key file to continue.');
        navigate('/unlock');
      } catch (err) {
        setError(err.body?.detail ?? 'Invalid or expired code.');
      } finally {
        setLoading(false);
      }
    };

    submitBtn.addEventListener('click', submit);
    codeEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

    this.querySelector('#resend-code').addEventListener('click', async () => {
      if (!this._email) { toast.error('No email address found.'); return; }
      try {
        await resendVerification(this._email);
        toast.success('Code resent — check your email.');
      } catch (_) {
        toast.error('Could not resend code. Try again shortly.');
      }
    });
  }
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

customElements.define('med-verify-email', MedVerifyEmail);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-verify-email></med-verify-email>';
}
