/**
 * med-reset-password.js — Confirm password reset with code.
 */

import { confirmPasswordReset } from '../services/auth.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import './common/med-spinner.js';

class MedResetPassword extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <div class="auth-card">
        <h1>New password</h1>
        <p class="auth-subtitle">Enter the code from your email and choose a new password.</p>

        <div class="auth-field">
          <label for="reset-email">Email</label>
          <input id="reset-email" type="email" autocomplete="email" placeholder="you@example.com">
        </div>

        <div class="auth-field">
          <label for="reset-code">Reset code</label>
          <input id="reset-code" type="text" inputmode="numeric" placeholder="123456" maxlength="6">
        </div>

        <div class="auth-field">
          <label for="reset-pass">New password</label>
          <input id="reset-pass" type="password" autocomplete="new-password" placeholder="••••••••">
        </div>

        <div class="auth-field">
          <label for="reset-pass2">Confirm new password</label>
          <input id="reset-pass2" type="password" autocomplete="new-password" placeholder="••••••••">
          <div class="auth-error" id="reset-error" hidden></div>
        </div>

        <button class="auth-submit" id="reset-submit">
          <med-spinner size="sm" id="reset-spinner" hidden></med-spinner>
          Reset password
        </button>

        <div class="auth-links">
          <button id="go-login">Back to sign in</button>
        </div>
      </div>
    `;

    const emailEl  = this.querySelector('#reset-email');
    const codeEl   = this.querySelector('#reset-code');
    const passEl   = this.querySelector('#reset-pass');
    const pass2El  = this.querySelector('#reset-pass2');
    const submitBtn= this.querySelector('#reset-submit');
    const spinner  = this.querySelector('#reset-spinner');
    const errorEl  = this.querySelector('#reset-error');

    const setError   = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
    const setLoading = (v)   => { submitBtn.disabled = v; spinner.hidden = !v; };

    const submit = async () => {
      setError('');
      const email = emailEl.value.trim();
      const code  = codeEl.value.trim();
      const pass  = passEl.value;
      const pass2 = pass2El.value;

      if (!email || !code || !pass) { setError('All fields are required.'); return; }
      if (pass !== pass2)            { setError('Passwords do not match.'); return; }
      if (pass.length < 8)           { setError('Password must be at least 8 characters.'); return; }

      setLoading(true);
      try {
        await confirmPasswordReset(email, code, pass);
        toast.success('Password reset. Sign in with your new password.');
        navigate('/login');
      } catch (err) {
        setError(err.body?.detail ?? 'Reset failed — check your code and try again.');
      } finally {
        setLoading(false);
      }
    };

    submitBtn.addEventListener('click', submit);
    this.querySelector('#go-login').addEventListener('click', () => navigate('/login'));
  }
}

customElements.define('med-reset-password', MedResetPassword);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-reset-password></med-reset-password>';
}
