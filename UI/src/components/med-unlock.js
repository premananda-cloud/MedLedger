/**
 * med-unlock.js — Crypto session unlock screen.
 *
 * Shown after login (or after inactivity lock) when the server session
 * is valid but the crypto session is locked.
 *
 * Reads cryptoStore.lockReason to show the appropriate message:
 *   'inactivity' → "Your session locked after inactivity"
 *   null/other   → "Upload your key file to continue"
 *
 * On success navigates to /vault (or the intended route if one was stored).
 */

import { loadAndUnlock } from '../services/crypto.js';
import { navigate } from '../services/router.js';
import cryptoStore from '../state/cryptoStore.js';
import authStore from '../state/authStore.js';
import './common/med-spinner.js';

function injectStyles() {
  if (document.querySelector('[data-med-unlock-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-unlock-styles', '');
  style.textContent = `
    .unlock-card {
      max-width: 26rem;
      margin: 4rem auto 0;
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 10px;
      padding: 2rem;
    }

    .unlock-card h1 {
      margin: 0 0 0.25rem;
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--color-text, #e8eaf0);
    }

    .unlock-card .unlock-subtitle {
      margin: 0 0 1.75rem;
      font-size: 0.875rem;
      color: var(--color-text-muted, #9ca3af);
      line-height: 1.5;
    }

    .unlock-reason-banner {
      display: flex;
      align-items: flex-start;
      gap: 0.625rem;
      padding: 0.75rem 1rem;
      background: #2a2018;
      border: 1px solid #78490a;
      border-radius: 6px;
      margin-bottom: 1.25rem;
      font-size: 0.875rem;
      color: #f59e0b;
      line-height: 1.4;
    }

    .unlock-reason-banner[hidden] { display: none; }

    .unlock-file-drop {
      border: 2px dashed var(--color-border, #2a2f3a);
      border-radius: 8px;
      padding: 1.5rem 1rem;
      text-align: center;
      cursor: pointer;
      transition: border-color 150ms ease, background 150ms ease;
      margin-bottom: 1rem;
    }

    .unlock-file-drop:hover,
    .unlock-file-drop.dragover {
      border-color: var(--color-accent, #3b82f6);
      background: rgba(59,130,246,0.05);
    }

    .unlock-file-drop p {
      margin: 0;
      font-size: 0.875rem;
      color: var(--color-text-muted, #9ca3af);
    }

    .unlock-file-name {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.5rem 0.75rem;
      background: #1a3a2a;
      border: 1px solid #34c76f;
      border-radius: 6px;
      font-size: 0.875rem;
      color: #34c76f;
      margin-bottom: 1rem;
    }

    .unlock-file-name[hidden] { display: none; }
    .unlock-file-name button {
      background: none; border: none; color: inherit;
      cursor: pointer; opacity: 0.7; padding: 0;
    }
    .unlock-file-name button:hover { opacity: 1; }

    .unlock-passphrase { margin-bottom: 1rem; }
  `;
  document.head.appendChild(style);
}

class MedUnlock extends HTMLElement {
  constructor() {
    super();
    this._fileBytes = null;
    this._fileName  = null;
  }

  connectedCallback() {
    injectStyles();
    this._render();
    this._bindEvents();
  }

  _render() {
    const { lockReason } = cryptoStore.getState();
    const { user }       = authStore.getState();
    const username       = user?.username ?? '';

    const isInactivity = lockReason === 'inactivity';

    this.innerHTML = `
      <div class="unlock-card">
        <h1>Unlock your session</h1>
        <p class="unlock-subtitle">
          Upload your <code>.mledger</code> key file and enter your passphrase to access your vault.
        </p>

        <div class="unlock-reason-banner" id="inactivity-banner" ${isInactivity ? '' : 'hidden'}>
          ⏱ Your session locked after 15 minutes of inactivity. Sign back in with your key file.
        </div>

        <div class="unlock-file-drop" id="file-drop">
          <p>Drop your <strong>.mledger</strong> file here, or click to browse</p>
          <input type="file" id="file-input" accept=".mledger" hidden>
        </div>

        <div class="unlock-file-name" id="file-name-row" hidden>
          <span id="file-name-label">–</span>
          <button id="clear-file" aria-label="Remove file">✕</button>
        </div>

        <div class="auth-field unlock-passphrase">
          <label for="unlock-pass">Passphrase</label>
          <input id="unlock-pass" type="password" autocomplete="current-password"
                 placeholder="Your key file passphrase">
          <div class="auth-error" id="unlock-error" hidden></div>
        </div>

        <button class="auth-submit" id="unlock-submit" disabled>
          <med-spinner size="sm" id="unlock-spinner" hidden></med-spinner>
          Unlock
        </button>
      </div>
    `;
  }

  _bindEvents() {
    const dropZone   = this.querySelector('#file-drop');
    const fileInput  = this.querySelector('#file-input');
    const fileRow    = this.querySelector('#file-name-row');
    const nameLabel  = this.querySelector('#file-name-label');
    const clearBtn   = this.querySelector('#clear-file');
    const passEl     = this.querySelector('#unlock-pass');
    const submitBtn  = this.querySelector('#unlock-submit');
    const spinner    = this.querySelector('#unlock-spinner');
    const errorEl    = this.querySelector('#unlock-error');

    const setError = (msg) => {
      errorEl.textContent = msg;
      errorEl.hidden = !msg;
    };

    const setLoading = (v) => {
      submitBtn.disabled = v || !this._fileBytes;
      spinner.hidden = !v;
    };

    const setFile = (file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const ab = e.target.result;
        this._fileBytes = new Uint8Array(ab);
        this._fileName  = file.name;
        dropZone.hidden     = true;
        fileRow.hidden      = false;
        nameLabel.textContent = file.name;
        submitBtn.disabled  = false;
        setError('');
      };
      reader.readAsArrayBuffer(file);
    };

    const clearFile = () => {
      this._fileBytes     = null;
      this._fileName      = null;
      dropZone.hidden     = false;
      fileRow.hidden      = true;
      nameLabel.textContent = '–';
      submitBtn.disabled  = true;
    };

    // Click to open file picker
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      if (e.target.files[0]) setFile(e.target.files[0]);
    });

    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) setFile(file);
    });

    clearBtn.addEventListener('click', clearFile);

    const unlock = async () => {
      setError('');
      const passphrase = passEl.value;
      const { user }   = authStore.getState();

      if (!this._fileBytes) { setError('Please upload your key file.'); return; }
      if (!passphrase)       { setError('Passphrase is required.'); return; }

      setLoading(true);

      try {
        // Convert Uint8Array → base64 for the worker
        let binary = '';
        for (const b of this._fileBytes) binary += String.fromCharCode(b);
        const bundleB64 = btoa(binary);

        await loadAndUnlock(user?.username ?? '', bundleB64, passphrase);
        navigate('/vault');
      } catch (err) {
        const msg = err.code === 'WRONG_PASSPHRASE'
          ? 'Wrong passphrase — check your key file and try again.'
          : err.message ?? 'Unlock failed. Check your key file and passphrase.';
        setError(msg);
      } finally {
        setLoading(false);
      }
    };

    submitBtn.addEventListener('click', unlock);
    passEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  }
}

customElements.define('med-unlock', MedUnlock);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-unlock></med-unlock>';
}
