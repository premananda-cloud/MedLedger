/**
 * med-spinner.js — Inline loading spinner.
 *
 * Usage:
 *   import './common/med-spinner.js';
 *
 *   <!-- In markup: -->
 *   <med-spinner hidden></med-spinner>
 *   <med-spinner size="sm"></med-spinner>
 *   <med-spinner size="lg" label="Decrypting…"></med-spinner>
 *
 * Attributes:
 *   size    — "sm" | "md" (default) | "lg"
 *   label   — screen-reader text (default: "Loading")
 *             also rendered as visible text if present
 *
 * The native `hidden` attribute works as expected — add/remove it to
 * show or hide without any JavaScript API on the component itself.
 *
 * For full-screen overlay use, wrap in a positioned container.
 */

// ─── Styles ─────────────────────────────────────────────────────────────────

function injectStyles() {
  if (document.querySelector('[data-med-spinner-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-spinner-styles', '');
  style.textContent = `
    med-spinner {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      vertical-align: middle;
    }

    med-spinner[hidden] {
      display: none !important;
    }

    .med-spinner__ring {
      display: block;
      border-radius: 50%;
      border-style: solid;
      border-color: currentColor transparent transparent transparent;
      animation: med-spin 700ms linear infinite;
      flex-shrink: 0;
    }

    /* Sizes */
    med-spinner[size="sm"] .med-spinner__ring {
      width: 0.875rem;
      height: 0.875rem;
      border-width: 2px;
    }

    med-spinner:not([size]) .med-spinner__ring,
    med-spinner[size="md"] .med-spinner__ring {
      width: 1.25rem;
      height: 1.25rem;
      border-width: 2px;
    }

    med-spinner[size="lg"] .med-spinner__ring {
      width: 2rem;
      height: 2rem;
      border-width: 3px;
    }

    .med-spinner__label {
      font-size: 0.875rem;
      color: inherit;
      opacity: 0.75;
    }

    @keyframes med-spin {
      from { transform: rotate(0deg); }
      to   { transform: rotate(360deg); }
    }

    @media (prefers-reduced-motion: reduce) {
      .med-spinner__ring {
        animation-duration: 1500ms;
      }
    }
  `;
  document.head.appendChild(style);
}

// ─── Component ──────────────────────────────────────────────────────────────

class MedSpinner extends HTMLElement {
  static get observedAttributes() {
    return ['label', 'size'];
  }

  connectedCallback() {
    injectStyles();
    this._render();
  }

  attributeChangedCallback() {
    if (this.isConnected) this._render();
  }

  _render() {
    const label = this.getAttribute('label') || 'Loading';
    const hasVisibleLabel = this.hasAttribute('label');

    this.setAttribute('role', 'status');

    this.innerHTML = `
      <span class="med-spinner__ring" aria-hidden="true"></span>
      <span class="${hasVisibleLabel ? 'med-spinner__label' : 'sr-only'}">${escapeHtml(label)}</span>
    `;
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

customElements.define('med-spinner', MedSpinner);
