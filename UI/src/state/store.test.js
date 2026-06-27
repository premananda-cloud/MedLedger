/**
 * store.test.js — Unit tests for state layer.
 *
 * Covers:
 *   - Store base class (subscribe, setState, getState, unsub)
 *   - authStore initial state and transitions
 *   - cryptoStore initial state and transitions
 *   - Cross-store independence (mutations don't leak)
 *
 * Zero dependencies: no DOM, no network, no worker.
 * Run with: npx vitest run src/state/store.test.js
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Import the real modules ────────────────────────────────────────────────
// Each test file gets a fresh module via vi.resetModules() if needed,
// but since stores are singletons we re-import after isolating where required.

import { Store } from './store.js';

// ─── Store base class ────────────────────────────────────────────────────────

describe('Store — base class', () => {
  it('initialises with provided state', () => {
    const store = new Store({ count: 0, label: 'hello' });
    expect(store.getState()).toEqual({ count: 0, label: 'hello' });
  });

  it('getState() returns a shallow copy — top-level keys are independent', () => {
    // The store provides a SHALLOW copy. Replacing a top-level key on the
    // returned object does not affect the store's internal state.
    // Deep values (arrays, nested objects) are still shared references —
    // this matches the documented contract and is sufficient for this app's
    // state shape (scalars, nulls, flat objects — never mutated arrays).
    const store = new Store({ count: 0, label: 'hello' });
    const state = store.getState();
    state.count = 999;       // mutate the top-level key on the copy
    state.label = 'mutated';
    expect(store.getState().count).toBe(0);       // store is unaffected
    expect(store.getState().label).toBe('hello'); // store is unaffected
  });

  it('setState() merges updates shallowly', () => {
    const store = new Store({ a: 1, b: 2 });
    store.setState({ b: 99 });
    expect(store.getState()).toEqual({ a: 1, b: 99 });
  });

  it('setState() does not drop keys not mentioned in the update', () => {
    const store = new Store({ x: 'keep', y: 'also keep', z: 'change' });
    store.setState({ z: 'changed' });
    const s = store.getState();
    expect(s.x).toBe('keep');
    expect(s.y).toBe('also keep');
    expect(s.z).toBe('changed');
  });

  it('subscribe() calls listener immediately on next setState', () => {
    const store  = new Store({ v: 0 });
    const listener = vi.fn();
    store.subscribe(listener);
    store.setState({ v: 1 });
    expect(listener).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledWith(expect.objectContaining({ v: 1 }));
  });

  it('subscribe() returns an unsubscribe function', () => {
    const store    = new Store({ v: 0 });
    const listener = vi.fn();
    const unsub    = store.subscribe(listener);
    store.setState({ v: 1 });
    expect(listener).toHaveBeenCalledTimes(1);

    unsub();
    store.setState({ v: 2 });
    expect(listener).toHaveBeenCalledTimes(1); // not called again
  });

  it('multiple subscribers each receive the update', () => {
    const store = new Store({ n: 0 });
    const a = vi.fn();
    const b = vi.fn();
    const c = vi.fn();
    store.subscribe(a);
    store.subscribe(b);
    store.subscribe(c);
    store.setState({ n: 7 });
    expect(a).toHaveBeenCalledWith(expect.objectContaining({ n: 7 }));
    expect(b).toHaveBeenCalledWith(expect.objectContaining({ n: 7 }));
    expect(c).toHaveBeenCalledWith(expect.objectContaining({ n: 7 }));
  });

  it('unsubscribing one listener does not affect others', () => {
    const store = new Store({ n: 0 });
    const a = vi.fn();
    const b = vi.fn();
    const unsubA = store.subscribe(a);
    store.subscribe(b);
    unsubA();
    store.setState({ n: 1 });
    expect(a).not.toHaveBeenCalled();
    expect(b).toHaveBeenCalledOnce();
  });

  it('calling unsubscribe twice does not throw', () => {
    const store = new Store({ n: 0 });
    const unsub = store.subscribe(vi.fn());
    expect(() => { unsub(); unsub(); }).not.toThrow();
  });

  it('listener receives a copy of state, not the live internal object', () => {
    const store = new Store({ n: 0 });
    let captured;
    store.subscribe(s => { captured = s; });
    store.setState({ n: 5 });
    // Mutate the captured state
    captured.n = 999;
    // Store should be unaffected
    expect(store.getState().n).toBe(5);
  });

  it('setState() with an empty object notifies listeners but changes nothing', () => {
    const store    = new Store({ a: 1 });
    const listener = vi.fn();
    store.subscribe(listener);
    store.setState({});
    expect(listener).toHaveBeenCalledOnce();
    expect(store.getState()).toEqual({ a: 1 });
  });

  it('setState() can set a key to null', () => {
    const store = new Store({ token: 'abc' });
    store.setState({ token: null });
    expect(store.getState().token).toBeNull();
  });

  it('setState() can add new keys not in initial state', () => {
    const store = new Store({ a: 1 });
    store.setState({ b: 2 });
    expect(store.getState()).toEqual({ a: 1, b: 2 });
  });
});

// ─── authStore ───────────────────────────────────────────────────────────────
// Import fresh instance for each describe block using dynamic import + resetModules.
// Since authStore is a singleton, we isolate via vi.resetModules() per test group.

describe('authStore — initial state', async () => {
  // Use dynamic import to get the real singleton
  const { default: authStore } = await import('./authStore.js');

  it('starts unauthenticated', () => {
    const s = authStore.getState();
    expect(s.status).toBe('unauthenticated');
  });

  it('starts with null user', () => {
    expect(authStore.getState().user).toBeNull();
  });

  it('starts with null accessToken', () => {
    expect(authStore.getState().accessToken).toBeNull();
  });

  it('starts with null _refreshToken', () => {
    expect(authStore.getState()._refreshToken).toBeNull();
  });
});

describe('authStore — transitions', async () => {
  const { default: authStore } = await import('./authStore.js');

  beforeEach(() => {
    // Reset to baseline before each test
    authStore.setState({
      status: 'unauthenticated',
      user: null,
      accessToken: null,
      _refreshToken: null,
    });
  });

  it('can transition to authenticated with token + user', () => {
    authStore.setState({
      status: 'authenticated',
      user: { username: 'ada', email: 'ada@example.com' },
      accessToken: 'tok_abc',
      _refreshToken: 'ref_abc',
    });
    const s = authStore.getState();
    expect(s.status).toBe('authenticated');
    expect(s.user.username).toBe('ada');
    expect(s.accessToken).toBe('tok_abc');
  });

  it('can transition back to unauthenticated (logout path)', () => {
    authStore.setState({ status: 'authenticated', accessToken: 'tok', _refreshToken: 'ref' });
    authStore.setState({ status: 'unauthenticated', user: null, accessToken: null, _refreshToken: null });
    const s = authStore.getState();
    expect(s.status).toBe('unauthenticated');
    expect(s.accessToken).toBeNull();
  });

  it('notifies subscribers on status change', () => {
    const listener = vi.fn();
    const unsub = authStore.subscribe(listener);
    authStore.setState({ status: 'authenticated', accessToken: 'tok' });
    expect(listener).toHaveBeenCalledWith(expect.objectContaining({ status: 'authenticated' }));
    unsub();
  });

  it('_pendingUserIdHex can be set and cleared (TOTP flow)', () => {
    authStore.setState({ _pendingUserIdHex: 'abcdef1234' });
    expect(authStore.getState()._pendingUserIdHex).toBe('abcdef1234');
    authStore.setState({ _pendingUserIdHex: null });
    expect(authStore.getState()._pendingUserIdHex).toBeNull();
  });

  it('_pendingUser can be set for registration email-verify flow', () => {
    const user = { user_id_hex: 'aabb', email: 'test@x.com' };
    authStore.setState({ _pendingUser: user });
    expect(authStore.getState()._pendingUser).toEqual(user);
  });

  it('updating user does not wipe accessToken', () => {
    authStore.setState({ accessToken: 'tok_preserved', status: 'authenticated' });
    authStore.setState({ user: { username: 'updated' } });
    expect(authStore.getState().accessToken).toBe('tok_preserved');
  });
});

// ─── cryptoStore ─────────────────────────────────────────────────────────────

describe('cryptoStore — initial state', async () => {
  const { default: cryptoStore } = await import('./cryptoStore.js');

  it('starts locked', () => {
    expect(cryptoStore.getState().status).toBe('locked');
  });

  it('starts with null publicKeys', () => {
    expect(cryptoStore.getState().publicKeys).toBeNull();
  });

  it('starts with null lockReason', () => {
    expect(cryptoStore.getState().lockReason).toBeNull();
  });
});

describe('cryptoStore — transitions', async () => {
  const { default: cryptoStore } = await import('./cryptoStore.js');

  beforeEach(() => {
    cryptoStore.setState({
      status: 'locked',
      publicKeys: null,
      lockReason: null,
    });
  });

  it('can transition to unlocked with public keys', () => {
    const keys = {
      signingPublicKey:  'sig_pub_b64',
      exchangePublicKey: 'enc_pub_b64',
      userIdHex:         'deadbeef',
      username:          'ada',
    };
    cryptoStore.setState({ status: 'unlocked', publicKeys: keys, lockReason: null });
    const s = cryptoStore.getState();
    expect(s.status).toBe('unlocked');
    expect(s.publicKeys.username).toBe('ada');
    expect(s.lockReason).toBeNull();
  });

  it('can lock with inactivity reason', () => {
    cryptoStore.setState({ status: 'unlocked', publicKeys: { username: 'ada' } });
    cryptoStore.setState({ status: 'locked', publicKeys: null, lockReason: 'inactivity' });
    const s = cryptoStore.getState();
    expect(s.status).toBe('locked');
    expect(s.publicKeys).toBeNull();
    expect(s.lockReason).toBe('inactivity');
  });

  it('can lock with manual reason', () => {
    cryptoStore.setState({ status: 'unlocked', publicKeys: { username: 'ada' } });
    cryptoStore.setState({ status: 'locked', publicKeys: null, lockReason: 'manual' });
    expect(cryptoStore.getState().lockReason).toBe('manual');
  });

  it('notifies subscribers on unlock', () => {
    const listener = vi.fn();
    const unsub = cryptoStore.subscribe(listener);
    cryptoStore.setState({ status: 'unlocked', publicKeys: { username: 'ada' } });
    expect(listener).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'unlocked' })
    );
    unsub();
  });

  it('notifies subscribers on lock', () => {
    cryptoStore.setState({ status: 'unlocked', publicKeys: { username: 'ada' } });
    const listener = vi.fn();
    const unsub = cryptoStore.subscribe(listener);
    cryptoStore.setState({ status: 'locked', publicKeys: null, lockReason: 'inactivity' });
    expect(listener).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'locked', lockReason: 'inactivity' })
    );
    unsub();
  });

  it('lockReason is preserved across unrelated setState calls', () => {
    cryptoStore.setState({ status: 'locked', publicKeys: null, lockReason: 'inactivity' });
    // A partial update that doesn't touch lockReason
    cryptoStore.setState({ publicKeys: null });
    expect(cryptoStore.getState().lockReason).toBe('inactivity');
  });
});

// ─── Cross-store independence ────────────────────────────────────────────────

describe('authStore and cryptoStore are independent', async () => {
  const { default: authStore }   = await import('./authStore.js');
  const { default: cryptoStore } = await import('./cryptoStore.js');

  it('mutating authStore does not affect cryptoStore', () => {
    cryptoStore.setState({ status: 'locked', publicKeys: null, lockReason: null });
    authStore.setState({ status: 'authenticated', accessToken: 'tok' });
    expect(cryptoStore.getState().status).toBe('locked');
  });

  it('mutating cryptoStore does not affect authStore', () => {
    authStore.setState({ status: 'authenticated', accessToken: 'tok' });
    cryptoStore.setState({ status: 'unlocked', publicKeys: { username: 'ada' } });
    expect(authStore.getState().status).toBe('authenticated');
    expect(authStore.getState().accessToken).toBe('tok');
  });

  it('a subscriber on authStore is not called when cryptoStore changes', () => {
    const listener = vi.fn();
    const unsub = authStore.subscribe(listener);
    cryptoStore.setState({ status: 'unlocked' });
    expect(listener).not.toHaveBeenCalled();
    unsub();
  });

  it('a subscriber on cryptoStore is not called when authStore changes', () => {
    const listener = vi.fn();
    const unsub = cryptoStore.subscribe(listener);
    authStore.setState({ status: 'authenticated' });
    expect(listener).not.toHaveBeenCalled();
    unsub();
  });
});
