/**
 * med-forgot-password.js — Request password reset.
 */

import { requestPasswordReset } from '../services/auth.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import './common/med-spinner.js';

class MedForgotPassword extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <div class="auth-card">
        <h1>Reset password</h1>
        <p class="auth-subtitle">Enter your email and we'll send a reset code.</p>

        <div class="auth-field">
          <label for="forgot-email">Email</label>
          <input id="forgot-email" type="email" autocomplete="email" placeholder="you@example.com">
          <div class="auth-error" id="forgot-error" hidden></div>
        </div>

        <button class="auth-submit" id="forgot-submit">
          <med-spinner size="sm" id="forgot-spinner" hidden></med-spinner>
          Send reset code
        </button>

        <div class="auth-links">
          <button id="go-login">Back to sign in</button>
        </div>
      </div>
    `;

    const emailEl  = this.querySelector('#forgot-email');
    const submitBtn= this.querySelector('#forgot-submit');
    const spinner  = this.querySelector('#forgot-spinner');
    const errorEl  = this.querySelector('#forgot-error');

    const setError   = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
    const setLoading = (v)   => { submitBtn.disabled = v; spinner.hidden = !v; };

    const submit = async () => {
      setError('');
      const email = emailEl.value.trim();
      if (!email) { setError('Email is required.'); return; }
      setLoading(true);
      try {
        await requestPasswordReset(email);
        // Always show success (don't reveal if email exists)
        toast.success('If that email exists, a reset code has been sent.');
        navigate('/reset-password');
      } catch (_) {
        toast.success('If that email exists, a reset code has been sent.');
        navigate('/reset-password');
      } finally {
        setLoading(false);
      }
    };

    submitBtn.addEventListener('click', submit);
    emailEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    this.querySelector('#go-login').addEventListener('click', () => navigate('/login'));
  }
}

customElements.define('med-forgot-password', MedForgotPassword);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-forgot-password></med-forgot-password>';
}
