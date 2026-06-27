/**
 * med-shares.js — Share management: sent, received, and pending tabs.
 *
 * Tabs:
 *   Sent     — shares I've created (can revoke)
 *   Received — shares sent to me (can decrypt + download)
 *   Pending  — incoming share requests (owner sees these; can send or reject)
 */

import {
  listSentShares,
  listReceivedShares,
  revokeShare,
} from '../services/shares.js';
import { http } from '../services/http.js';
import { decryptShare } from '../services/crypto.js';
import { navigate } from '../services/router.js';
import { toast } from './common/med-toast.js';
import { confirm } from './common/med-confirm.js';
import './common/med-spinner.js';

function injectStyles() {
  if (document.querySelector('[data-med-shares-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-shares-styles', '');
  style.textContent = `
    .shares-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.25rem;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .shares-header h1 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--color-text, #e8eaf0);
    }

    .tab-bar {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--color-border, #2a2f3a);
      margin-bottom: 1.25rem;
    }

    .tab-btn {
      padding: 0.625rem 1.125rem;
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--color-text-muted, #9ca3af);
      font-size: 0.875rem;
      cursor: pointer;
      transition: color 150ms ease, border-color 150ms ease;
      margin-bottom: -1px;
    }

    .tab-btn.active {
      color: var(--color-accent, #3b82f6);
      border-bottom-color: var(--color-accent, #3b82f6);
    }

    .tab-btn:hover:not(.active) {
      color: var(--color-text, #e8eaf0);
    }

    .share-list { display: flex; flex-direction: column; gap: 0.5rem; }

    .share-row {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.875rem 1rem;
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 8px;
    }

    .share-row-info { flex: 1; min-width: 0; }

    .share-row-name {
      font-weight: 500;
      font-size: 0.9rem;
      color: var(--color-text, #e8eaf0);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .share-row-meta {
      font-size: 0.775rem;
      color: var(--color-text-muted, #9ca3af);
      margin-top: 0.125rem;
    }

    .share-badge {
      font-size: 0.75rem;
      padding: 0.175rem 0.5rem;
      border-radius: 9999px;
      font-weight: 500;
    }

    .share-badge.active   { background: #1a3a2a; color: #34c76f; }
    .share-badge.expired  { background: #2a2018; color: #f59e0b; }
    .share-badge.revoked  { background: #2a1a1a; color: #e05555; }

    .share-actions { display: flex; gap: 0.375rem; flex-shrink: 0; }

    .pending-row {
      display: flex;
      align-items: flex-start;
      gap: 1rem;
      padding: 1rem;
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 8px;
    }

    .pending-row-info { flex: 1; min-width: 0; }
    .pending-row-actions { display: flex; gap: 0.375rem; flex-shrink: 0; flex-direction: column; align-items: flex-end; }

    .empty-state {
      text-align: center;
      padding: 3rem 1rem;
      color: var(--color-text-muted, #9ca3af);
      font-size: 0.875rem;
    }
  `;
  document.head.appendChild(style);
}

function formatDate(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function statusBadge(status) {
  const label = status ?? 'active';
  return `<span class="share-badge ${label}">${label}</span>`;
}

class MedShares extends HTMLElement {
  constructor() {
    super();
    this._tab = 'received';
  }

  connectedCallback() {
    injectStyles();
    this._render();
    this._loadTab(this._tab);
  }

  _render() {
    this.innerHTML = `
      <div class="shares-header">
        <h1>Shares</h1>
        <button class="btn-primary" id="new-share-btn">+ New share</button>
      </div>

      <div class="tab-bar">
        <button class="tab-btn ${this._tab === 'received' ? 'active' : ''}" data-tab="received">Received</button>
        <button class="tab-btn ${this._tab === 'sent'     ? 'active' : ''}" data-tab="sent">Sent</button>
        <button class="tab-btn ${this._tab === 'pending'  ? 'active' : ''}" data-tab="pending">Pending requests</button>
      </div>

      <div id="tab-content">
        <div style="text-align:center;padding:2rem"><med-spinner label="Loading…"></med-spinner></div>
      </div>
    `;

    this.querySelector('.tab-bar').addEventListener('click', (e) => {
      const tab = e.target.closest('[data-tab]')?.dataset.tab;
      if (!tab || tab === this._tab) return;
      this._tab = tab;
      this.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
      this._loadTab(tab);
    });

    this.querySelector('#new-share-btn').addEventListener('click', () => navigate('/shares/new'));
  }

  async _loadTab(tab) {
    const content = this.querySelector('#tab-content');
    content.innerHTML = '<div style="text-align:center;padding:2rem"><med-spinner label="Loading…"></med-spinner></div>';

    try {
      if (tab === 'sent') {
        const records = await listSentShares();
        this._renderSent(records);
      } else if (tab === 'received') {
        const records = await listReceivedShares();
        this._renderReceived(records);
      } else {
        const data = await http('/api/shares/pending');
        this._renderPending(data.requests ?? []);
      }
    } catch (_) {
      content.innerHTML = '<p style="color:#e05555;text-align:center">Failed to load.</p>';
    }
  }

  _renderSent(shares) {
    const content = this.querySelector('#tab-content');
    if (!shares.length) {
      content.innerHTML = '<div class="empty-state">No shares sent yet.</div>';
      return;
    }

    content.innerHTML = `<div class="share-list">${shares.map(s => `
      <div class="share-row" data-id="${escapeHtml(s.share_id)}">
        <div class="share-row-info">
          <div class="share-row-name">${escapeHtml(s.filename)}</div>
          <div class="share-row-meta">
            To: ${escapeHtml(s.grantee_username ?? '–')} ·
            Created: ${formatDate(s.created_at)} ·
            Expires: ${s.expires_at ? formatDate(s.expires_at) : 'Never'}
          </div>
        </div>
        ${statusBadge(s.status)}
        <div class="share-actions">
          ${s.status === 'active' ? `<button class="btn-danger revoke-btn">Revoke</button>` : ''}
        </div>
      </div>
    `).join('')}</div>`;

    content.addEventListener('click', async (e) => {
      if (!e.target.classList.contains('revoke-btn')) return;
      const row      = e.target.closest('[data-id]');
      const shareId  = row?.dataset.id;
      const filename = row?.querySelector('.share-row-name')?.textContent;
      if (!shareId) return;

      const ok = await confirm(`Revoke share of "${filename}"?`, {
        detail: 'The recipient will lose access immediately.',
        confirmLabel: 'Revoke',
      });
      if (!ok) return;

      try {
        await revokeShare(shareId);
        toast.success('Share revoked.');
        this._loadTab('sent');
      } catch (_) {
        toast.error('Revoke failed.');
      }
    }, { once: true });
  }

  _renderReceived(shares) {
    const content = this.querySelector('#tab-content');
    if (!shares.length) {
      content.innerHTML = '<div class="empty-state">No shares received yet.</div>';
      return;
    }

    content.innerHTML = `<div class="share-list">${shares.map(s => `
      <div class="share-row" data-id="${escapeHtml(s.share_id)}">
        <div class="share-row-info">
          <div class="share-row-name">${escapeHtml(s.filename)}</div>
          <div class="share-row-meta">
            From: ${escapeHtml(s.owner_username ?? '–')} ·
            ${s.expires_at ? `Expires: ${formatDate(s.expires_at)}` : 'No expiry'}
          </div>
        </div>
        ${statusBadge(s.status)}
        <div class="share-actions">
          ${s.status === 'active' ? `<button class="btn-primary download-btn">Download</button>` : ''}
        </div>
      </div>
    `).join('')}</div>`;

    content.addEventListener('click', async (e) => {
      if (!e.target.classList.contains('download-btn')) return;
      const row     = e.target.closest('[data-id]');
      const shareId = row?.dataset.id;
      if (!shareId) return;
      await this._downloadShare(shareId, row?.querySelector('.share-row-name')?.textContent ?? 'file');
    });
  }

  _renderPending(requests) {
    const content = this.querySelector('#tab-content');
    if (!requests.length) {
      content.innerHTML = '<div class="empty-state">No pending share requests.</div>';
      return;
    }

    content.innerHTML = `<div class="share-list">${requests.map(r => `
      <div class="pending-row" data-id="${escapeHtml(r.share_id ?? r.request_id ?? '')}">
        <div class="pending-row-info">
          <div class="share-row-name">Request for record ${escapeHtml(r.record_id ?? '–')}</div>
          <div class="share-row-meta">
            From: ${escapeHtml(r.requester_username ?? r.requester_public_key?.slice(0, 16) + '…' ?? '–')} ·
            ${formatDate(r.created_at)}
          </div>
        </div>
        <div class="pending-row-actions">
          <button class="btn-primary send-btn">Send share</button>
          <button class="btn-danger reject-btn">Reject</button>
        </div>
      </div>
    `).join('')}</div>`;

    content.addEventListener('click', async (e) => {
      const row = e.target.closest('[data-id]');
      if (!row) return;

      if (e.target.classList.contains('send-btn')) {
        // Navigate to new share flow pre-filled with this request context
        navigate(`/shares/new?request=${encodeURIComponent(row.dataset.id)}`);
      }

      if (e.target.classList.contains('reject-btn')) {
        const ok = await confirm('Reject this share request?', { confirmLabel: 'Reject' });
        if (!ok) return;
        try {
          await http('/api/shares/reject', {
            method: 'POST',
            body: { share_id: row.dataset.id },
          });
          toast.info('Request rejected.');
          this._loadTab('pending');
        } catch (_) {
          toast.error('Reject failed.');
        }
      }
    });
  }

  async _downloadShare(shareId, filename) {
    try {
      const cipher = await http(`/api/shares/${shareId}/ciphertext`);
      const plaintext = await decryptShare(
        cipher.ciphertext ?? cipher.encrypted_payload,
        cipher.nonce,
        cipher.dek_bundle,
      );
      const blob = new Blob([plaintext], { type: 'application/octet-stream' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('File decrypted and downloaded.');
    } catch (err) {
      toast.error('Decrypt failed — ' + (err.message ?? 'unknown error'));
    }
  }
}

function escapeHtml(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

customElements.define('med-shares', MedShares);

export function render() {
  const content = window._medContent;
  if (!content) return;
  content.innerHTML = '<med-shares></med-shares>';
  // Clear notification badge when user visits shares
  document.querySelector('med-app')?.clearNotifBadge?.();
}
