/**
 * med-vault.js — Vault record list.
 *
 * FIX: getPublicKeys() was being dynamically imported inside _upload().
 * It is synchronous and already in memory — use a static top-level import.
 *
 * Handles: list, upload (encrypt → upload), delete.
 * Navigate to /vault/:recordId for the detail/download view.
 */

import { listRecords, uploadRecord, deleteRecord } from '../services/vault.js';
import { encryptRecord, getPublicKeys } from '../services/crypto.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import { confirm } from './common/med-confirm.js';
import './common/med-spinner.js';

function injectStyles() {
  if (document.querySelector('[data-med-vault-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-vault-styles', '');
  style.textContent = `
    .vault-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.5rem;
      gap: 1rem;
    }
    .vault-header h1 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--color-text, #e8eaf0);
    }
    .vault-empty {
      text-align: center;
      padding: 4rem 1rem;
      color: var(--color-text-muted, #9ca3af);
    }
    .vault-empty p { margin: 0.5rem 0 0; font-size: 0.875rem; }
    .vault-list { display: flex; flex-direction: column; gap: 0.5rem; }
    .vault-record {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.875rem 1rem;
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 8px;
      cursor: pointer;
      transition: border-color 150ms ease;
    }
    .vault-record:hover { border-color: #4b5563; }
    .vault-record-icon { font-size: 1.5rem; flex-shrink: 0; width: 2rem; text-align: center; }
    .vault-record-info { flex: 1; min-width: 0; }
    .vault-record-name {
      font-weight: 500;
      font-size: 0.9rem;
      color: var(--color-text, #e8eaf0);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .vault-record-meta {
      font-size: 0.775rem;
      color: var(--color-text-muted, #9ca3af);
      margin-top: 0.125rem;
    }
    .vault-record-actions { display: flex; gap: 0.375rem; flex-shrink: 0; }
    .upload-progress {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.875rem 1rem;
      background: var(--color-surface, #1c1f26);
      border: 1px dashed var(--color-accent, #3b82f6);
      border-radius: 8px;
      font-size: 0.875rem;
      color: var(--color-text-muted, #9ca3af);
      margin-bottom: 0.5rem;
    }
    .upload-progress[hidden] { display: none; }
  `;
  document.head.appendChild(style);
}

function mimeIcon(mimeType) {
  if (!mimeType) return '📄';
  if (mimeType.startsWith('image/')) return '🖼';
  if (mimeType === 'application/pdf') return '📑';
  if (mimeType.startsWith('video/')) return '🎬';
  if (mimeType.startsWith('audio/')) return '🎵';
  return '📄';
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function formatDate(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function escapeHtml(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

class MedVault extends HTMLElement {
  constructor() {
    super();
    this._records = [];
  }

  connectedCallback() {
    injectStyles();
    this._render();
    this._loadRecords();
  }

  _render() {
    this.innerHTML = `
      <div class="vault-header">
        <h1>Vault</h1>
        <button class="btn-primary" id="upload-btn">+ Upload record</button>
        <input type="file" id="file-input" hidden>
      </div>
      <div class="upload-progress" id="upload-progress" hidden>
        <med-spinner size="sm"></med-spinner>
        <span id="upload-label">Encrypting…</span>
      </div>
      <div id="vault-list-container">
        <div style="text-align:center;padding:2rem">
          <med-spinner label="Loading records…"></med-spinner>
        </div>
      </div>
    `;

    this.querySelector('#upload-btn').addEventListener('click', () => {
      this.querySelector('#file-input').click();
    });

    this.querySelector('#file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) this._upload(file);
      e.target.value = '';
    });

    // Event delegation — registered once here, never inside _renderList
    this.querySelector('#vault-list-container').addEventListener('click', (e) => {
      const row      = e.target.closest('.vault-record');
      const recordId = row?.dataset.id;
      if (!recordId) return;

      if (e.target.classList.contains('btn-danger')) {
        e.stopPropagation();
        const name = row.querySelector('.vault-record-name')?.textContent;
        this._deleteRecord(recordId, name);
        return;
      }

      navigate(`/vault/${recordId}`);
    });
  }

  async _loadRecords() {
    try {
      this._records = await listRecords();
      this._renderList();
    } catch (_) {
      this.querySelector('#vault-list-container').innerHTML =
        '<p style="color:#e05555;text-align:center">Failed to load records.</p>';
    }
  }

  _renderList() {
    const container = this.querySelector('#vault-list-container');
    if (!this._records.length) {
      container.innerHTML = `
        <div class="vault-empty">
          <div style="font-size:2.5rem">🔒</div>
          <p>No records yet. Upload your first file to get started.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div class="vault-list">
        ${this._records.map(r => `
          <div class="vault-record" data-id="${escapeHtml(r.record_id)}">
            <div class="vault-record-icon">${mimeIcon(r.mime_type)}</div>
            <div class="vault-record-info">
              <div class="vault-record-name">${escapeHtml(r.filename ?? r.file_name ?? '')}</div>
              <div class="vault-record-meta">
                ${escapeHtml(r.mime_type ?? '')} · ${formatBytes(r.size_bytes ?? 0)} · ${formatDate(r.created_at)}
              </div>
            </div>
            <div class="vault-record-actions">
              <button class="btn-danger">Delete</button>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  async _upload(file) {
    const progressEl = this.querySelector('#upload-progress');
    const labelEl    = this.querySelector('#upload-label');
    const uploadBtn  = this.querySelector('#upload-btn');

    progressEl.hidden  = false;
    uploadBtn.disabled = true;

    try {
      labelEl.textContent = 'Encrypting…';

      const fileBytes  = new Uint8Array(await file.arrayBuffer());

      // FIX: static import — getPublicKeys() is synchronous, no dynamic import needed
      const publicKeys = getPublicKeys();
      if (!publicKeys) throw new Error('Crypto session is not unlocked.');

      const encrypted = await encryptRecord(fileBytes, publicKeys.exchangePublicKey);

      labelEl.textContent = 'Uploading…';

      await uploadRecord({
        title:           file.name,
        description:     '',
        encryptedRecord: encrypted.encryptedRecord,
        nonce:           encrypted.nonce,
        dekBundle:       encrypted.dekBundle,
        fileHash:        encrypted.fileHash,
        mimeType:        file.type || 'application/octet-stream',
        fileName:        file.name,
      });

      toast.success(`${file.name} uploaded`);
      await this._loadRecords();
    } catch (err) {
      toast.error('Upload failed — ' + (err.message ?? 'unknown error'));
    } finally {
      progressEl.hidden  = true;
      uploadBtn.disabled = false;
    }
  }

  async _deleteRecord(recordId, name) {
    const ok = await confirm(`Delete "${name ?? 'this record'}"?`, {
      detail: 'This cannot be undone.',
      confirmLabel: 'Delete',
    });
    if (!ok) return;

    try {
      await deleteRecord(recordId);
      toast.success('Record deleted.');
      this._records = this._records.filter(r => r.record_id !== recordId);
      this._renderList();
    } catch (_) {
      toast.error('Delete failed.');
    }
  }
}

customElements.define('med-vault', MedVault);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-vault></med-vault>';
}
