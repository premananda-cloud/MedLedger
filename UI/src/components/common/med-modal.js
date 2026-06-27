/**
 * med-modal.js — Accessible modal dialog.
 *
 * Usage:
 *   import './common/med-modal.js';
 *
 *   const modal = document.createElement('med-modal');
 *   modal.setAttribute('title', 'Confirm Delete');
 *   modal.innerHTML = '<p>Are you sure?</p>';
 *   document.body.appendChild(modal);
 *   modal.open();
 *
 *   modal.addEventListener('med-close', () => modal.remove());
 *
 * Attributes:
 *   title      — modal heading (required)
 *   size       — "sm" | "md" (default) | "lg"
 *   no-close   — if present, hides the × button (use for forced-flow modals)
 *
 * Events (bubble):
 *   med-close  — fired when the user closes the modal (Escape, backdrop, × button)
 *
 * Methods:
 *   open()   — show the modal
 *   close()  — hide and fire med-close
 */

function injectStyles() {
  if (document.querySelector('[data-med-modal-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-modal-styles', '');
  style.textContent = `
    .med-modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.6);
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      opacity: 0;
      transition: opacity 200ms ease;
    }

    .med-modal-backdrop.med-modal--visible {
      opacity: 1;
    }

    .med-modal-box {
      background: var(--color-surface, #1c1f26);
      border: 1px solid var(--color-border, #2a2f3a);
      border-radius: 8px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
      width: 100%;
      max-height: calc(100vh - 2rem);
      overflow-y: auto;
      transform: translateY(8px);
      transition: transform 200ms ease;
      display: flex;
      flex-direction: column;
    }

    .med-modal-backdrop.med-modal--visible .med-modal-box {
      transform: translateY(0);
    }

    .med-modal-box[data-size="sm"] { max-width: 24rem; }
    .med-modal-box:not([data-size]),
    .med-modal-box[data-size="md"] { max-width: 36rem; }
    .med-modal-box[data-size="lg"] { max-width: 52rem; }

    .med-modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.25rem 1.5rem 1rem;
      border-bottom: 1px solid var(--color-border, #2a2f3a);
      flex-shrink: 0;
    }

    .med-modal-title {
      margin: 0;
      font-size: 1rem;
      font-weight: 600;
      color: var(--color-text, #e8eaf0);
    }

    .med-modal-close {
      background: none;
      border: none;
      color: var(--color-text-muted, #6b7280);
      cursor: pointer;
      padding: 0.25rem;
      font-size: 1.25rem;
      line-height: 1;
      border-radius: 4px;
      transition: color 150ms ease, background 150ms ease;
      flex-shrink: 0;
    }

    .med-modal-close:hover {
      color: var(--color-text, #e8eaf0);
      background: var(--color-hover, rgba(255,255,255,0.06));
    }

    .med-modal-body {
      padding: 1.5rem;
      flex: 1;
      color: var(--color-text, #e8eaf0);
    }

    .med-modal-footer {
      padding: 1rem 1.5rem;
      border-top: 1px solid var(--color-border, #2a2f3a);
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
      flex-shrink: 0;
    }

    /* Slot for footer — only shown if populated */
    .med-modal-footer:empty {
      display: none;
    }
  `;
  document.head.appendChild(style);
}

// Focus trap helpers
const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled])',
  'select:not([disabled])', 'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

function getFocusable(container) {
  return [...container.querySelectorAll(FOCUSABLE)];
}

class MedModal extends HTMLElement {
  constructor() {
    super();
    this._backdrop = null;
    this._onKeyDown = this._onKeyDown.bind(this);
    this._previousFocus = null;
  }

  connectedCallback() {
    injectStyles();
  }

  open() {
    if (this._backdrop) return; // already open

    this._previousFocus = document.activeElement;

    const title = this.getAttribute('title') ?? '';
    const size = this.getAttribute('size') ?? 'md';
    const noClose = this.hasAttribute('no-close');

    // Build backdrop
    this._backdrop = document.createElement('div');
    this._backdrop.className = 'med-modal-backdrop';
    this._backdrop.setAttribute('role', 'dialog');
    this._backdrop.setAttribute('aria-modal', 'true');
    this._backdrop.setAttribute('aria-label', title);

    const box = document.createElement('div');
    box.className = 'med-modal-box';
    box.setAttribute('data-size', size);

    box.innerHTML = `
      <div class="med-modal-header">
        <h2 class="med-modal-title">${escapeHtml(title)}</h2>
        ${noClose ? '' : '<button class="med-modal-close" aria-label="Close dialog">✕</button>'}
      </div>
      <div class="med-modal-body"></div>
      <div class="med-modal-footer"></div>
    `;

    // Move this element's children into the body slot
    const body = box.querySelector('.med-modal-body');
    // Move slotted content
    while (this.firstChild) {
      body.appendChild(this.firstChild);
    }

    this._backdrop.appendChild(box);
    document.body.appendChild(this._backdrop);

    // Prevent body scroll
    document.body.style.overflow = 'hidden';

    // Backdrop click to close
    this._backdrop.addEventListener('click', (e) => {
      if (e.target === this._backdrop) this.close();
    });

    // Close button
    const closeBtn = box.querySelector('.med-modal-close');
    if (closeBtn) closeBtn.addEventListener('click', () => this.close());

    // Keyboard trap
    document.addEventListener('keydown', this._onKeyDown);

    // Animate in
    requestAnimationFrame(() => {
      requestAnimationFrame(() => this._backdrop.classList.add('med-modal--visible'));
    });

    // Focus first focusable element
    setTimeout(() => {
      const first = getFocusable(box)[0];
      if (first) first.focus();
    }, 50);
  }

  close() {
    if (!this._backdrop) return;

    this._backdrop.classList.remove('med-modal--visible');

    setTimeout(() => {
      // Move content back before removing backdrop
      const body = this._backdrop.querySelector('.med-modal-body');
      if (body) {
        while (body.firstChild) this.appendChild(body.firstChild);
      }

      this._backdrop.remove();
      this._backdrop = null;

      document.body.style.overflow = '';
      document.removeEventListener('keydown', this._onKeyDown);

      if (this._previousFocus) {
        this._previousFocus.focus();
        this._previousFocus = null;
      }

      this.dispatchEvent(new CustomEvent('med-close', { bubbles: true }));
    }, 200);
  }

  /**
   * setFooter(htmlString) — programmatically set footer content
   */
  setFooter(html) {
    const footer = this._backdrop?.querySelector('.med-modal-footer');
    if (footer) footer.innerHTML = html;
  }

  _onKeyDown(e) {
    if (e.key === 'Escape' && !this.hasAttribute('no-close')) {
      this.close();
      return;
    }

    if (e.key === 'Tab') {
      const box = this._backdrop?.querySelector('.med-modal-box');
      if (!box) return;
      const focusable = getFocusable(box);
      if (!focusable.length) { e.preventDefault(); return; }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
  }

  disconnectedCallback() {
    if (this._backdrop) {
      this._backdrop.remove();
      this._backdrop = null;
      document.body.style.overflow = '';
      document.removeEventListener('keydown', this._onKeyDown);
    }
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

customElements.define('med-modal', MedModal);
