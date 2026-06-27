/**
 * med-toast.js — Toast notification system.
 *
 * Usage (from anywhere):
 *   import { toast } from './common/med-toast.js';
 *   toast.success('Record uploaded');
 *   toast.error('Upload failed — check your connection');
 *   toast.info('Share request sent');
 *
 * The container mounts itself once on first use.
 * No component needs to add <med-toast-container> to markup.
 */

const DURATION = 4000;      // ms before auto-dismiss
const TRANSITION = 250;     // ms for enter/exit animation

// ─── Styles ────────────────────────────────────────────────────────────────

const STYLES = `
  :host-context(body) {}   /* no shadow DOM — styles live in index.css */
`;

// Injected into <head> once. Uses a data attribute to avoid double-injection.
function injectStyles() {
  if (document.querySelector('[data-med-toast-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-toast-styles', '');
  style.textContent = `
    #med-toast-container {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 9999;
      display: flex;
      flex-direction: column-reverse;
      gap: 0.5rem;
      pointer-events: none;
      max-width: min(24rem, calc(100vw - 3rem));
    }

    .med-toast {
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-size: 0.875rem;
      line-height: 1.4;
      pointer-events: all;
      cursor: default;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);
      opacity: 0;
      transform: translateY(0.5rem);
      transition: opacity ${TRANSITION}ms ease, transform ${TRANSITION}ms ease;
      word-break: break-word;
    }

    .med-toast.med-toast--visible {
      opacity: 1;
      transform: translateY(0);
    }

    .med-toast--success {
      background: #1a3a2a;
      border-left: 3px solid #34c76f;
      color: #d4f5e2;
    }

    .med-toast--error {
      background: #3a1a1a;
      border-left: 3px solid #e05555;
      color: #f5d4d4;
    }

    .med-toast--info {
      background: #1a2a3a;
      border-left: 3px solid #4a9ede;
      color: #d4e8f5;
    }

    .med-toast__icon {
      flex-shrink: 0;
      font-size: 1rem;
      line-height: 1.4;
      user-select: none;
    }

    .med-toast__message {
      flex: 1;
    }

    .med-toast__close {
      flex-shrink: 0;
      background: none;
      border: none;
      color: inherit;
      opacity: 0.5;
      cursor: pointer;
      padding: 0;
      font-size: 1rem;
      line-height: 1;
      transition: opacity 150ms ease;
    }

    .med-toast__close:hover {
      opacity: 1;
    }
  `;
  document.head.appendChild(style);
}

// ─── Container singleton ────────────────────────────────────────────────────

function getContainer() {
  let el = document.getElementById('med-toast-container');
  if (!el) {
    injectStyles();
    el = document.createElement('div');
    el.id = 'med-toast-container';
    el.setAttribute('role', 'region');
    el.setAttribute('aria-label', 'Notifications');
    el.setAttribute('aria-live', 'polite');
    el.setAttribute('aria-atomic', 'false');
    document.body.appendChild(el);
  }
  return el;
}

// ─── Icon map ───────────────────────────────────────────────────────────────

const ICONS = {
  success: '✓',
  error: '✕',
  info: 'ℹ',
};

// ─── Core show function ─────────────────────────────────────────────────────

function show(message, type = 'info', duration = DURATION) {
  const container = getContainer();

  const el = document.createElement('div');
  el.className = `med-toast med-toast--${type}`;
  el.setAttribute('role', 'status');
  el.innerHTML = `
    <span class="med-toast__icon" aria-hidden="true">${ICONS[type] ?? ICONS.info}</span>
    <span class="med-toast__message">${escapeHtml(message)}</span>
    <button class="med-toast__close" aria-label="Dismiss notification">✕</button>
  `;

  container.appendChild(el);

  // Trigger enter animation on next frame
  requestAnimationFrame(() => {
    requestAnimationFrame(() => el.classList.add('med-toast--visible'));
  });

  // Dismiss logic
  let dismissed = false;

  function dismiss() {
    if (dismissed) return;
    dismissed = true;
    el.classList.remove('med-toast--visible');
    setTimeout(() => el.remove(), TRANSITION);
  }

  el.querySelector('.med-toast__close').addEventListener('click', dismiss);

  if (duration > 0) {
    setTimeout(dismiss, duration);
  }

  return dismiss; // caller can dismiss early if needed
}

// ─── HTML escape ────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Public API ─────────────────────────────────────────────────────────────

export const toast = {
  success: (message, duration) => show(message, 'success', duration),
  error:   (message, duration) => show(message, 'error',   duration),
  info:    (message, duration) => show(message, 'info',    duration),
};
