/**
 * med-vault-detail.js — Single vault record view.
 *
 * FIX: connectedCallback() was calling _loadRecord() before _recordId was set
 * by render(). Guard added: only load if _recordId is already present.
 * render() sets _recordId then calls _loadRecord() directly.
 */

import { getRecord, deleteRecord } from '../services/vault.js';
import { http } from '../services/http.js';
import { decryptShare } from '../services/crypto.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import { confirm } from './common/med-confirm.js';
import './common/med-spinner.js';

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function formatDate(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleString();
}

function escapeHtml(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function injectStyles() {
  if (document.querySelector('[data-med-detail-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-detail-styles', '');
  style.textContent = `
    .detail-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .detail-back {
      background: none;
      border: none;
      color: var(--color-text-muted, #9ca3af);
      cursor: pointer;
      font-size: 1.25rem;
      padding: 0;
      line-height: 1;
      transition: color 150ms ease;
    }
    .detail-back:hover { color: var(--color-text, #e8eaf0); }
    .detail-header h1 {
      margin: 0;
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--color-text, #e8eaf0);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .detail-card {
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1rem;
    }
    .detail-meta {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr));
      gap: 1rem;
      margin-bottom: 1.25rem;
    }
    .detail-meta-item label {
      display: block;
      font-size: 0.75rem;
      color: var(--color-text-muted, #9ca3af);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.25rem;
    }
    .detail-meta-item span {
      font-size: 0.9rem;
      color: var(--color-text, #e8eaf0);
    }
    .detail-actions { display: flex; gap: 0.75rem; flex-wrap: wrap; }
  `;
  document.head.appendChild(style);
}

class MedVaultDetail extends HTMLElement {
  constructor() {
    super();
    this._record   = null;
    this._recordId = null;
  }

  connectedCallback() {
    injectStyles();
    this._renderShell();
    // FIX: only load if recordId was already set (e.g. if element was
    // re-connected). render() sets _recordId and calls _loadRecord() itself.
    if (this._recordId) this._loadRecord();
  }

  _renderShell() {
    this.innerHTML = `
      <div class="detail-header">
        <button class="detail-back" id="back-btn" aria-label="Back to vault">←</button>
        <h1 id="detail-title">Loading…</h1>
      </div>
      <div id="detail-body">
        <div style="text-align:center;padding:2rem">
          <med-spinner label="Loading record…"></med-spinner>
        </div>
      </div>
    `;
    this.querySelector('#back-btn').addEventListener('click', () => navigate('/vault'));
  }

  async _loadRecord() {
    try {
      this._record = await getRecord(this._recordId);
      this._renderRecord();
    } catch (_) {
      this.querySelector('#detail-body').innerHTML =
        '<p style="color:#e05555">Could not load record.</p>';
    }
  }

  _renderRecord() {
    const r = this._record;
    this.querySelector('#detail-title').textContent = r.filename ?? r.file_name ?? 'Record';

    this.querySelector('#detail-body').innerHTML = `
      <div class="detail-card">
        <div class="detail-meta">
          <div class="detail-meta-item">
            <label>Type</label>
            <span>${escapeHtml(r.mime_type ?? '–')}</span>
          </div>
          <div class="detail-meta-item">
            <label>Size</label>
            <span>${formatBytes(r.size_bytes ?? 0)}</span>
          </div>
          <div class="detail-meta-item">
            <label>Uploaded</label>
            <span>${formatDate(r.created_at)}</span>
          </div>
          <div class="detail-meta-item">
            <label>Record ID</label>
            <span style="font-family:monospace;font-size:0.75rem">${escapeHtml(r.record_id)}</span>
          </div>
        </div>
        <div class="detail-actions">
          <button class="btn-primary" id="download-btn">
            <med-spinner size="sm" id="dl-spinner" hidden></med-spinner>
            Download & decrypt
          </button>
          <button class="btn-ghost" id="share-btn">Share</button>
          <button class="btn-danger" id="delete-btn">Delete</button>
        </div>
      </div>
    `;

    this.querySelector('#download-btn').addEventListener('click', () => this._downloadRecord());
    this.querySelector('#share-btn').addEventListener('click', () => {
      navigate(`/shares/new?record=${encodeURIComponent(this._recordId)}`);
    });
    this.querySelector('#delete-btn').addEventListener('click', () => this._deleteRecord());
  }

  async _downloadRecord() {
    const btn     = this.querySelector('#download-btn');
    const spinner = this.querySelector('#dl-spinner');
    btn.disabled   = true;
    spinner.hidden = false;

    try {
      const cipher = await http(`/api/vault/records/${this._recordId}/ciphertext`);

      const plaintext = await decryptShare(
        cipher.encrypted_record ?? cipher.ciphertext,
        cipher.nonce,
        cipher.dek_bundle,
      );

      const blob = new Blob([plaintext], {
        type: this._record?.mime_type ?? 'application/octet-stream',
      });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = this._record?.filename ?? this._record?.file_name ?? 'record';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error('Decrypt failed — ' + (err.message ?? 'unknown error'));
    } finally {
      btn.disabled   = false;
      spinner.hidden = true;
    }
  }

  async _deleteRecord() {
    const name = this._record?.filename ?? this._record?.file_name;
    const ok = await confirm(`Delete "${name ?? 'this record'}"?`, {
      detail: 'This cannot be undone.',
      confirmLabel: 'Delete',
    });
    if (!ok) return;

    try {
      await deleteRecord(this._recordId);
      toast.success('Record deleted.');
      navigate('/vault');
    } catch (_) {
      toast.error('Delete failed.');
    }
  }
}

customElements.define('med-vault-detail', MedVaultDetail);

export function render(params) {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-vault-detail></med-vault-detail>';
  const el = content.querySelector('med-vault-detail');
  // FIX: set _recordId BEFORE connectedCallback fires on next tick,
  // then call _loadRecord() explicitly — connectedCallback guards on null _recordId
  el._recordId = params.recordId;
  el._loadRecord();
}
