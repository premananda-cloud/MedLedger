/**
 * med-settings.js — User settings.
 *
 * Sections:
 *   Profile  — display name update
 *   Security — change password, TOTP setup/disable, logout all sessions
 *   Keys     — view current public keys
 */

import { getProfile, updateProfile } from '../services/user.js';
import {
  changePassword,
  setupTotp,
  confirmTotp,
  disableTotp,
  logoutAll,
} from '../services/auth.js';
import { getMyKeys } from '../services/keys.js';
import { getPublicKeys } from '../services/crypto.js';
import { navigate } from '../services/router.js';
import authStore from '../state/authStore.js';
import { toast } from './common/med-toast.js';
import { confirm } from './common/med-confirm.js';
import './common/med-spinner.js';

function injectStyles() {
  if (document.querySelector('[data-med-settings-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-settings-styles', '');
  style.textContent = `
    .settings-layout {
      display: grid;
      grid-template-columns: 200px 1fr;
      gap: 2rem;
      max-width: 760px;
    }

    @media (max-width: 600px) {
      .settings-layout { grid-template-columns: 1fr; }
      .settings-nav { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    }

    .settings-nav {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }

    .settings-nav-btn {
      text-align: left;
      padding: 0.5rem 0.875rem;
      background: none;
      border: none;
      border-radius: 6px;
      color: var(--color-text-muted, #9ca3af);
      font-size: 0.875rem;
      cursor: pointer;
      transition: background 150ms ease, color 150ms ease;
    }

    .settings-nav-btn.active,
    .settings-nav-btn:hover {
      background: var(--color-hover, rgba(255,255,255,0.06));
      color: var(--color-text, #e8eaf0);
    }

    .settings-panel { min-width: 0; }

    .settings-section {
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1rem;
    }

    .settings-section h2 {
      margin: 0 0 1.25rem;
      font-size: 0.9375rem;
      font-weight: 600;
      color: var(--color-text, #e8eaf0);
    }

    .settings-field {
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
      margin-bottom: 1rem;
    }

    .settings-field label {
      font-size: 0.8125rem;
      font-weight: 500;
      color: var(--color-text, #e8eaf0);
    }

    .settings-field input {
      padding: 0.5rem 0.75rem;
      background: var(--color-bg, #13151a);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 6px;
      color: var(--color-text, #e8eaf0);
      font-size: 0.875rem;
      outline: none;
      transition: border-color 150ms ease;
      width: 100%;
      box-sizing: border-box;
    }

    .settings-field input:focus {
      border-color: var(--color-accent, #3b82f6);
    }

    .settings-field-row {
      display: flex;
      gap: 0.75rem;
      align-items: flex-end;
    }

    .settings-field-row .settings-field { flex: 1; margin-bottom: 0; }

    .settings-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem 0;
      border-bottom: 1px solid var(--color-border, #2a2f3a);
      gap: 1rem;
    }

    .settings-row:last-child { border-bottom: none; padding-bottom: 0; }
    .settings-row:first-child { padding-top: 0; }

    .settings-row-label {
      font-size: 0.875rem;
      color: var(--color-text, #e8eaf0);
      font-weight: 500;
    }

    .settings-row-desc {
      font-size: 0.8rem;
      color: var(--color-text-muted, #9ca3af);
      margin-top: 0.125rem;
    }

    .key-display {
      font-family: monospace;
      font-size: 0.75rem;
      padding: 0.625rem 0.875rem;
      background: var(--color-bg, #13151a);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 6px;
      color: var(--color-text-muted, #9ca3af);
      word-break: break-all;
      line-height: 1.5;
    }

    .key-label {
      font-size: 0.75rem;
      color: var(--color-text-muted, #9ca3af);
      margin-bottom: 0.25rem;
      margin-top: 0.875rem;
    }

    .key-label:first-child { margin-top: 0; }

    .totp-qr {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      padding: 1rem;
      background: var(--color-bg, #13151a);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 8px;
      margin-bottom: 0.75rem;
    }

    .totp-uri {
      font-family: monospace;
      font-size: 0.72rem;
      word-break: break-all;
      color: var(--color-text-muted, #9ca3af);
    }

    .backup-codes {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 0.375rem;
      margin: 0.75rem 0;
    }

    .backup-code {
      font-family: monospace;
      font-size: 0.875rem;
      padding: 0.375rem 0.625rem;
      background: var(--color-bg, #13151a);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 4px;
      text-align: center;
      color: var(--color-text, #e8eaf0);
    }

    .badge-on  { color: #34c76f; font-size: 0.8rem; font-weight: 500; }
    .badge-off { color: var(--color-text-muted, #9ca3af); font-size: 0.8rem; }
  `;
  document.head.appendChild(style);
}

class MedSettings extends HTMLElement {
  constructor() {
    super();
    this._activeSection = 'profile';
    this._profile = null;
  }

  connectedCallback() {
    injectStyles();
    this._render();
    this._loadProfile();
  }

  _render() {
    this.innerHTML = `
      <h1 style="font-size:1.25rem;font-weight:700;color:var(--color-text,#e8eaf0);margin:0 0 1.5rem">
        Settings
      </h1>
      <div class="settings-layout">
        <nav class="settings-nav">
          <button class="settings-nav-btn active" data-section="profile">Profile</button>
          <button class="settings-nav-btn" data-section="security">Security</button>
          <button class="settings-nav-btn" data-section="keys">Keys</button>
        </nav>
        <div class="settings-panel" id="settings-panel">
          <div style="text-align:center;padding:2rem"><med-spinner label="Loading…"></med-spinner></div>
        </div>
      </div>
    `;

    this.querySelector('.settings-nav').addEventListener('click', (e) => {
      const section = e.target.closest('[data-section]')?.dataset.section;
      if (!section || section === this._activeSection) return;
      this._activeSection = section;
      this.querySelectorAll('.settings-nav-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.section === section)
      );
      this._renderSection(section);
    });
  }

  async _loadProfile() {
    try {
      this._profile = await getProfile();
    } catch (_) {
      this._profile = authStore.getState().user;
    }
    this._renderSection(this._activeSection);
  }

  _renderSection(section) {
    const panel = this.querySelector('#settings-panel');
    if (section === 'profile')  this._renderProfile(panel);
    if (section === 'security') this._renderSecurity(panel);
    if (section === 'keys')     this._renderKeys(panel);
  }

  // ── Profile ───────────────────────────────────────────────────────────────

  _renderProfile(panel) {
    const u = this._profile ?? {};
    panel.innerHTML = `
      <div class="settings-section">
        <h2>Profile</h2>

        <div class="settings-field">
          <label>Username</label>
          <input type="text" value="${escapeHtml(u.username ?? '')}" disabled
                 style="opacity:0.5;cursor:not-allowed">
        </div>

        <div class="settings-field">
          <label for="fullname-input">Full name</label>
          <input id="fullname-input" type="text" value="${escapeHtml(u.full_name ?? '')}">
        </div>

        <div class="settings-field">
          <label>Email</label>
          <input type="email" value="${escapeHtml(u.email ?? '')}" disabled
                 style="opacity:0.5;cursor:not-allowed">
        </div>

        <div class="auth-error" id="profile-error" hidden></div>

        <button class="btn-primary" id="save-profile-btn" style="margin-top:0.5rem">
          <med-spinner size="sm" id="profile-spinner" hidden></med-spinner>
          Save changes
        </button>
      </div>
    `;

    const btn     = panel.querySelector('#save-profile-btn');
    const spinner = panel.querySelector('#profile-spinner');
    const errorEl = panel.querySelector('#profile-error');

    btn.addEventListener('click', async () => {
      const fullName = panel.querySelector('#fullname-input').value.trim();
      if (!fullName) { errorEl.textContent = 'Full name is required.'; errorEl.hidden = false; return; }
      errorEl.hidden = true;
      btn.disabled = true; spinner.hidden = false;

      try {
        this._profile = await updateProfile({ full_name: fullName });
        toast.success('Profile updated.');
      } catch (_) {
        toast.error('Update failed.');
      } finally {
        btn.disabled = false; spinner.hidden = true;
      }
    });
  }

  // ── Security ──────────────────────────────────────────────────────────────

  _renderSecurity(panel) {
    const totpEnabled = this._profile?.totp_enabled ?? false;
    panel.innerHTML = `
      <div class="settings-section">
        <h2>Password</h2>

        <div class="settings-field">
          <label for="cur-pass">Current password</label>
          <input id="cur-pass" type="password" autocomplete="current-password">
        </div>
        <div class="settings-field">
          <label for="new-pass">New password</label>
          <input id="new-pass" type="password" autocomplete="new-password">
        </div>
        <div class="settings-field">
          <label for="new-pass2">Confirm new password</label>
          <input id="new-pass2" type="password" autocomplete="new-password">
          <div class="auth-error" id="pw-error" hidden></div>
        </div>
        <button class="btn-primary" id="change-pw-btn">
          <med-spinner size="sm" id="pw-spinner" hidden></med-spinner>
          Change password
        </button>
      </div>

      <div class="settings-section">
        <h2>Two-factor authentication</h2>
        <div class="settings-row">
          <div>
            <div class="settings-row-label">Authenticator app</div>
            <div class="settings-row-desc">
              ${totpEnabled ? 'TOTP is active on your account.' : 'Add an extra layer of security.'}
            </div>
          </div>
          <div>
            ${totpEnabled
              ? '<span class="badge-on">● Enabled</span>'
              : '<span class="badge-off">○ Disabled</span>'}
          </div>
        </div>
        <div style="margin-top:0.75rem">
          ${totpEnabled
            ? '<button class="btn-danger" id="disable-totp-btn">Disable TOTP</button>'
            : '<button class="btn-primary" id="setup-totp-btn">Set up TOTP</button>'}
        </div>
        <div id="totp-setup-flow" hidden></div>
      </div>

      <div class="settings-section">
        <h2>Sessions</h2>
        <div class="settings-row">
          <div>
            <div class="settings-row-label">Sign out all devices</div>
            <div class="settings-row-desc">Revokes all active sessions including this one.</div>
          </div>
          <button class="btn-danger" id="logout-all-btn">Sign out all</button>
        </div>
      </div>
    `;

    // Password change
    const pwBtn    = panel.querySelector('#change-pw-btn');
    const pwSpinner= panel.querySelector('#pw-spinner');
    const pwError  = panel.querySelector('#pw-error');

    pwBtn.addEventListener('click', async () => {
      const cur  = panel.querySelector('#cur-pass').value;
      const next = panel.querySelector('#new-pass').value;
      const next2= panel.querySelector('#new-pass2').value;
      if (!cur || !next) { pwError.textContent = 'All fields required.'; pwError.hidden = false; return; }
      if (next !== next2) { pwError.textContent = 'Passwords do not match.'; pwError.hidden = false; return; }
      pwError.hidden = true;
      pwBtn.disabled = true; pwSpinner.hidden = false;
      try {
        await changePassword(cur, next);
        toast.success('Password changed.');
        panel.querySelector('#cur-pass').value = '';
        panel.querySelector('#new-pass').value = '';
        panel.querySelector('#new-pass2').value = '';
      } catch (err) {
        pwError.textContent = err.body?.detail ?? 'Change failed.';
        pwError.hidden = false;
      } finally {
        pwBtn.disabled = false; pwSpinner.hidden = true;
      }
    });

    // TOTP setup
    panel.querySelector('#setup-totp-btn')?.addEventListener('click', () => this._startTotpSetup(panel));
    panel.querySelector('#disable-totp-btn')?.addEventListener('click', () => this._disableTotp(panel));

    // Logout all
    panel.querySelector('#logout-all-btn').addEventListener('click', async () => {
      const ok = await confirm('Sign out of all devices?', {
        detail: 'You will need to sign in again on every device.',
        confirmLabel: 'Sign out all',
      });
      if (!ok) return;
      await logoutAll();
      navigate('/login');
    });
  }

  async _startTotpSetup(panel) {
    const flow = panel.querySelector('#totp-setup-flow');
    flow.hidden = false;
    flow.innerHTML = '<med-spinner label="Generating QR code…"></med-spinner>';

    try {
      const { uri, backup_codes } = await setupTotp();

      flow.innerHTML = `
        <div class="totp-qr">
          <p style="margin:0;font-size:0.8125rem;color:var(--color-text,#e8eaf0)">
            Scan this URI in your authenticator app (Google Authenticator, Aegis, etc.):
          </p>
          <div class="totp-uri">${escapeHtml(uri)}</div>
          <p style="margin:0;font-size:0.775rem;color:var(--color-text-muted,#9ca3af)">
            Or enter it manually into your app.
          </p>
        </div>

        <p style="font-size:0.8125rem;font-weight:600;color:#f59e0b;margin:0 0 0.375rem">
          Save these backup codes — they will not be shown again.
        </p>
        <div class="backup-codes">
          ${backup_codes.map(c => `<div class="backup-code">${escapeHtml(c)}</div>`).join('')}
        </div>

        <div class="settings-field" style="margin-top:0.75rem">
          <label for="totp-confirm-code">Enter code from app to confirm</label>
          <input id="totp-confirm-code" type="text" inputmode="numeric"
                 placeholder="123456" maxlength="6" autocomplete="one-time-code">
          <div class="auth-error" id="totp-confirm-error" hidden></div>
        </div>

        <div style="display:flex;gap:0.75rem">
          <button class="btn-primary" id="confirm-totp-btn">
            <med-spinner size="sm" id="confirm-totp-spinner" hidden></med-spinner>
            Activate TOTP
          </button>
          <button class="btn-ghost" id="cancel-totp-btn">Cancel</button>
        </div>
      `;

      flow.querySelector('#cancel-totp-btn').addEventListener('click', () => {
        flow.hidden = true;
        flow.innerHTML = '';
      });

      flow.querySelector('#confirm-totp-btn').addEventListener('click', async () => {
        const code    = flow.querySelector('#totp-confirm-code').value.trim();
        const errorEl = flow.querySelector('#totp-confirm-error');
        const btn     = flow.querySelector('#confirm-totp-btn');
        const spinner = flow.querySelector('#confirm-totp-spinner');

        if (!code) { errorEl.textContent = 'Enter the code.'; errorEl.hidden = false; return; }
        errorEl.hidden = true;
        btn.disabled = true; spinner.hidden = false;

        try {
          await confirmTotp(code);
          toast.success('TOTP enabled.');
          if (this._profile) this._profile.totp_enabled = true;
          this._renderSecurity(panel);
        } catch (_) {
          errorEl.textContent = 'Wrong code — try again.';
          errorEl.hidden = false;
          btn.disabled = false; spinner.hidden = true;
        }
      });

    } catch (_) {
      flow.innerHTML = '<p style="color:#e05555">Failed to start TOTP setup.</p>';
    }
  }

  async _disableTotp(panel) {
    const ok = await confirm('Disable two-factor authentication?', {
      detail: 'Your account will be less secure without TOTP.',
      confirmLabel: 'Disable TOTP',
    });
    if (!ok) return;

    // Need password + TOTP code to disable
    const password = window.prompt('Enter your current password to confirm:');
    if (!password) return;
    const code = window.prompt('Enter your authenticator code:');
    if (!code) return;

    try {
      await disableTotp(password, code);
      toast.success('TOTP disabled.');
      if (this._profile) this._profile.totp_enabled = false;
      this._renderSecurity(panel);
    } catch (_) {
      toast.error('Failed to disable TOTP — check your password and code.');
    }
  }

  // ── Keys ──────────────────────────────────────────────────────────────────

  async _renderKeys(panel) {
    panel.innerHTML = `
      <div class="settings-section">
        <h2>Your public keys</h2>
        <div style="text-align:center;padding:1rem"><med-spinner label="Loading keys…"></med-spinner></div>
      </div>
    `;

    // Try in-memory first (no round-trip if already unlocked)
    let keys = getPublicKeys();
    if (!keys) {
      try { keys = await getMyKeys(); } catch (_) {}
    }

    if (!keys) {
      panel.querySelector('.settings-section').innerHTML = `
        <h2>Your public keys</h2>
        <p style="color:var(--color-text-muted,#9ca3af);font-size:0.875rem">
          Keys are only available when your crypto session is unlocked.
        </p>
      `;
      return;
    }

    panel.querySelector('.settings-section').innerHTML = `
      <h2>Your public keys</h2>
      <p style="font-size:0.8125rem;color:var(--color-text-muted,#9ca3af);margin:0 0 1rem;line-height:1.5">
        Share your signing key with others so they can verify files you've shared.
        Never share your private key file.
      </p>

      <div class="key-label">Signing public key (Ed25519)</div>
      <div class="key-display">${escapeHtml(keys.signingPublicKey ?? keys.signing_public_key ?? '–')}</div>

      <div class="key-label">Exchange public key (X25519)</div>
      <div class="key-display">${escapeHtml(keys.exchangePublicKey ?? keys.exchange_public_key ?? '–')}</div>

      <div class="key-label">User ID</div>
      <div class="key-display">${escapeHtml(keys.userIdHex ?? keys.user_id_hex ?? '–')}</div>
    `;
  }
}

function escapeHtml(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

customElements.define('med-settings', MedSettings);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-settings></med-settings>';
}
