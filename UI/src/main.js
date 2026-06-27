/**
 * main.js — Application entry point.
 *
 * Boot sequence (matches build plan step order):
 *   1. initWorker()          — start SharedWorker
 *   2. router.on(...)        — register all routes
 *   3. router.start()        — resolve initial route
 *
 * The router's guards gate on authStore + cryptoStore state,
 * so no boot-time session restore is needed beyond what's in memory.
 * (Page refresh requires re-login — see build plan notes on token strategy.)
 *
 * Notification polling is started by med-app.js after both sessions are live.
 */

import { initWorker } from './services/crypto.js';
import { router, requireAuth, requireUnlocked, requireGuest } from './router.js';

// ── 1. Start the SharedWorker ─────────────────────────────────────────────────
initWorker();

// ── 2. Register routes ────────────────────────────────────────────────────────

router
  // Guest-only routes
  .on('/login',    () => import('./components/med-login.js').then(m => m.render()),
      { guard: requireGuest })
  .on('/register', () => import('./components/med-register.js').then(m => m.render()),
      { guard: requireGuest })
  .on('/verify-email', () => import('./components/med-verify-email.js').then(m => m.render()),
      { guard: requireGuest })
  .on('/forgot-password', () => import('./components/med-forgot-password.js').then(m => m.render()),
      { guard: requireGuest })

  // Auth required, crypto may still be locked
  .on('/unlock', () => import('./components/med-unlock.js').then(m => m.render()),
      { guard: requireAuth })

  // Auth + unlocked crypto required
  .on('/vault',                  () => import('./components/med-vault.js').then(m => m.render()),
      { guard: requireUnlocked })
  .on('/vault/upload',           () => import('./components/med-vault-upload.js').then(m => m.render()),
      { guard: requireUnlocked })
  .on('/vault/:recordId',        (p) => import('./components/med-vault-detail.js').then(m => m.render(p)),
      { guard: requireUnlocked })
  .on('/shares',                 () => import('./components/med-shares.js').then(m => m.render()),
      { guard: requireUnlocked })
  .on('/shares/new',             () => import('./components/med-share-new.js').then(m => m.render()),
      { guard: requireUnlocked })
  .on('/shares/:shareId',        (p) => import('./components/med-share-detail.js').then(m => m.render(p)),
      { guard: requireUnlocked })
  .on('/settings',               () => import('./components/med-settings.js').then(m => m.render()),
      { guard: requireUnlocked })
  .on('/settings/totp',          () => import('./components/med-totp-setup.js').then(m => m.render()),
      { guard: requireUnlocked })

  // Default (root)
  .on('/', () => { window.location.hash = '/vault'; });

// ── 3. Resolve initial route ──────────────────────────────────────────────────
router.start();
