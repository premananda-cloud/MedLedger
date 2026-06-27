/**
 * med-app.js — Application shell.
 *
 * Renders the nav bar and the #content container.
 * Starts/stops notification polling based on session state.
 * Manages the notification badge count.
 *
 * Mounted once by main.js. Not re-created on navigation.
 * Navigation changes only the #content slot (handled by router.js).
 */

import { navigate } from '../services/router.js';
import { logout, lock } from '../services/crypto.js';
import { logout as authLogout } from '../services/auth.js';
import { startNotificationPolling, stopNotificationPolling } from '../services/shares.js';
import authStore from '../state/authStore.js';
import cryptoStore from '../state/cryptoStore.js';
import { toast } from './common/med-toast.js';

function injectStyles() {
  if (document.querySelector('[data-med-app-styles]')) return;
  const style = document.createElement('style');
  style.setAttribute('data-med-app-styles', '');
  style.textContent = `
    #med-app-shell {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      background: var(--color-bg, #13151a);
    }

    .med-nav {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      padding: 0 1.5rem;
      height: 56px;
      background: var(--color-surface, #1c1f26);
      border-bottom: 1px solid var(--color-border, #2a2f3a);
      flex-shrink: 0;
    }

    .med-nav[hidden] {
      display: none !important;
    }

    .med-nav-brand {
      font-weight: 700;
      font-size: 1rem;
      color: var(--color-text, #e8eaf0);
      letter-spacing: -0.01em;
      margin-right: 1rem;
      text-decoration: none;
    }

    .med-nav-link {
      padding: 0.375rem 0.75rem;
      border-radius: 5px;
      border: none;
      background: none;
      color: var(--color-text-muted, #9ca3af);
      cursor: pointer;
      font-size: 0.875rem;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      transition: color 150ms ease, background 150ms ease;
    }

    .med-nav-link:hover,
    .med-nav-link.active {
      color: var(--color-text, #e8eaf0);
      background: var(--color-hover, rgba(255,255,255,0.06));
    }

    .med-nav-spacer {
      flex: 1;
    }

    .med-nav-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: #e05555;
      color: #fff;
      font-size: 0.7rem;
      font-weight: 700;
      border-radius: 9999px;
      min-width: 1.1rem;
      height: 1.1rem;
      padding: 0 0.2rem;
      line-height: 1;
    }

    .med-nav-badge[hidden] {
      display: none;
    }

    #med-content {
      flex: 1;
      padding: 2rem 1.5rem;
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
      box-sizing: border-box;
    }
  `;
  document.head.appendChild(style);
}

class MedApp extends HTMLElement {
  constructor() {
    super();
    this._unsubAuth   = null;
    this._unsubCrypto = null;
    this._notifCount  = 0;
  }

  connectedCallback() {
    injectStyles();

    this.id = 'med-app-shell';
    this.innerHTML = `
      <nav class="med-nav" hidden>
        <span class="med-nav-brand">MedLedger</span>
        <button class="med-nav-link" data-route="/vault">Vault</button>
        <button class="med-nav-link" data-route="/shares">
          Shares
          <span class="med-nav-badge" id="notif-badge" hidden></span>
        </button>
        <div class="med-nav-spacer"></div>
        <button class="med-nav-link" data-route="/settings">Settings</button>
        <button class="med-nav-link" id="lock-btn">Lock</button>
        <button class="med-nav-link" id="logout-btn">Sign out</button>
      </nav>
      <main id="med-content"></main>
    `;

    // Expose content container for router
    window._medContent = this.querySelector('#med-content');

    // Nav link clicks
    this.querySelector('.med-nav').addEventListener('click', (e) => {
      const route = e.target.closest('[data-route]')?.dataset.route;
      if (route) navigate(route);
    });

    this.querySelector('#lock-btn').addEventListener('click', async () => {
      await lock();
      navigate('/unlock');
    });

    this.querySelector('#logout-btn').addEventListener('click', async () => {
      stopNotificationPolling();
      await authLogout();
      navigate('/login');
    });

    // React to session state
    this._unsubAuth   = authStore.subscribe(s => this._onAuthChange(s));
    this._unsubCrypto = cryptoStore.subscribe(s => this._onCryptoChange(s));

    // Sync initial state
    this._onAuthChange(authStore.getState());
    this._onCryptoChange(cryptoStore.getState());
  }

  disconnectedCallback() {
    this._unsubAuth?.();
    this._unsubCrypto?.();
    stopNotificationPolling();
  }

  _onAuthChange(state) {
    const nav = this.querySelector('.med-nav');
    if (!nav) return;
    nav.hidden = state.status !== 'authenticated';
  }

  _onCryptoChange(state) {
    if (state.status === 'unlocked') {
      this._startPolling();
    } else {
      stopNotificationPolling();
      this._setNotifCount(0);
    }
  }

  _startPolling() {
    startNotificationPolling((notifications) => {
      this._setNotifCount(this._notifCount + notifications.length);
      // Show a toast for the first new notification type
      const first = notifications[0];
      if (first?.type === 'share_request') {
        toast.info('New share request received');
      }
    });
  }

  _setNotifCount(n) {
    this._notifCount = n;
    const badge = this.querySelector('#notif-badge');
    if (!badge) return;
    badge.hidden = n === 0;
    badge.textContent = n > 99 ? '99+' : String(n);
  }

  /** Called by router to clear badge when user views shares */
  clearNotifBadge() {
    this._setNotifCount(0);
  }
}

customElements.define('med-app', MedApp);

/** render() — called by main.js to mount the shell once */
export function render() {
  if (document.getElementById('med-app-shell')) return;
  const app = document.createElement('med-app');
  document.getElementById('app').appendChild(app);
}
