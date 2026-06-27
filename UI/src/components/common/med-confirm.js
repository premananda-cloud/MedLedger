/**
 * med-confirm.js — Confirmation dialog for destructive actions.
 *
 * Usage:
 *   import { confirm } from './common/med-confirm.js';
 *
 *   const ok = await confirm('Delete this record?', {
 *     detail: 'This cannot be undone.',
 *     confirmLabel: 'Delete',       // default: 'Confirm'
 *     danger: true,                 // default: true — red confirm button
 *   });
 *   if (ok) { ... }
 *
 * Returns a Promise<boolean>. Resolves true on confirm, false on cancel/dismiss.
 * No component needs to add anything to markup — mounts itself.
 */

import './med-modal.js';

function injectStyles() {
  if (document.querySelector('[data-med-confirm-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-confirm-styles', '');
  style.textContent = `
    .med-confirm-detail {
      color: var(--color-text-muted, #9ca3af);
      font-size: 0.9rem;
      margin-top: 0.5rem;
      line-height: 1.5;
    }

    .med-confirm-actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
      margin-top: 1.5rem;
    }

    .med-confirm-cancel {
      padding: 0.5rem 1.25rem;
      border-radius: 6px;
      border: 1px solid var(--color-border, #2a2f3a);
      background: transparent;
      color: var(--color-text, #e8eaf0);
      cursor: pointer;
      font-size: 0.875rem;
      transition: background 150ms ease;
    }

    .med-confirm-cancel:hover {
      background: var(--color-hover, rgba(255,255,255,0.06));
    }

    .med-confirm-ok {
      padding: 0.5rem 1.25rem;
      border-radius: 6px;
      border: none;
      cursor: pointer;
      font-size: 0.875rem;
      font-weight: 500;
      transition: opacity 150ms ease;
    }

    .med-confirm-ok.danger {
      background: #c0392b;
      color: #fff;
    }

    .med-confirm-ok.safe {
      background: var(--color-accent, #3b82f6);
      color: #fff;
    }

    .med-confirm-ok:hover {
      opacity: 0.85;
    }
  `;
  document.head.appendChild(style);
}

/**
 * confirm(message, options?) → Promise<boolean>
 *
 * @param {string} message           — main question text
 * @param {object} [opts]
 *   @param {string}  [opts.title]         — modal title (default: 'Are you sure?')
 *   @param {string}  [opts.detail]        — secondary detail text
 *   @param {string}  [opts.confirmLabel]  — confirm button label (default: 'Confirm')
 *   @param {string}  [opts.cancelLabel]   — cancel button label (default: 'Cancel')
 *   @param {boolean} [opts.danger]        — red confirm button (default: true)
 */
export function confirm(message, opts = {}) {
  injectStyles();

  const {
    title        = 'Are you sure?',
    detail       = '',
    confirmLabel = 'Confirm',
    cancelLabel  = 'Cancel',
    danger       = true,
  } = opts;

  return new Promise((resolve) => {
    const modal = document.createElement('med-modal');
    modal.setAttribute('title', title);
    modal.setAttribute('size', 'sm');
    modal.setAttribute('no-close', '');

    modal.innerHTML = `
      <p style="margin:0;color:var(--color-text,#e8eaf0)">${escapeHtml(message)}</p>
      ${detail ? `<p class="med-confirm-detail">${escapeHtml(detail)}</p>` : ''}
      <div class="med-confirm-actions">
        <button class="med-confirm-cancel">${escapeHtml(cancelLabel)}</button>
        <button class="med-confirm-ok ${danger ? 'danger' : 'safe'}">${escapeHtml(confirmLabel)}</button>
      </div>
    `;

    document.body.appendChild(modal);
    modal.open();

    function finish(result) {
      modal.removeAttribute('no-close');
      modal.close();
      modal.addEventListener('med-close', () => modal.remove(), { once: true });
      resolve(result);
    }

    // Use event delegation on the modal element itself
    // (buttons are moved into modal-body by med-modal.open())
    modal.addEventListener('click', (e) => {
      if (e.target.classList.contains('med-confirm-ok'))     finish(true);
      if (e.target.classList.contains('med-confirm-cancel')) finish(false);
    });

    modal.addEventListener('med-close', () => {
      resolve(false);
      modal.remove();
    }, { once: true });
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
