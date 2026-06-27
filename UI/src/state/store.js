/**
 * store.js — Minimal observable store.
 *
 * Usage:
 *   const store = new Store({ count: 0 });
 *   const unsub = store.subscribe(state => console.log(state));
 *   store.setState({ count: 1 });
 *   unsub();
 *
 * Fixes applied:
 *
 *   1. getState() — was returning the live internal reference. Any caller
 *      mutating the result would silently corrupt store state. Now returns
 *      a shallow copy via spread. Deep values (arrays, nested objects) are
 *      still shared references — callers must not mutate them in place.
 *      This matches the contract documented in the build plan and tested
 *      in store.test.js.
 *
 *   2. setState() / _notify — was passing this.#state (live reference) to
 *      listeners. A listener mutating the received object would corrupt
 *      internal state. Now passes { ...this.#state } to each listener.
 *
 *   3. subscribe() — was calling listener(this.#state) immediately on
 *      subscribe. This is convenient for components that need the current
 *      state on mount, but it breaks the contract that subscribe() only
 *      notifies on changes. The tests (and the components) call getState()
 *      for the initial snapshot — subscribe() is for subsequent changes only.
 *      Immediate call removed. Components that need the current value on
 *      mount should call store.getState() explicitly in connectedCallback,
 *      then subscribe for changes.
 *
 *   Note on the cross-store failures: both were caused by lingering state
 *   from previous test cases (singletons share state across test cases).
 *   The subscribe() immediate-call bug caused listeners registered in one
 *   test to fire during the beforeEach setState() in another. Removing the
 *   immediate call and ensuring unsub() is always called in tests fixes this.
 */

export class Store {
  #state;
  #listeners = new Set();

  constructor(initialState) {
    // Spread on construction so the initial object reference is not stored
    // directly — caller mutations after construction don't affect the store.
    this.#state = { ...initialState };
  }

  /**
   * Returns a shallow copy of current state.
   * Callers must not mutate nested objects in place.
   */
  getState() {
    return { ...this.#state };
  }

  /**
   * Merge partial update into state and notify all subscribers.
   * Each subscriber receives its own shallow copy.
   */
  setState(partial) {
    this.#state = { ...this.#state, ...partial };
    for (const fn of this.#listeners) fn({ ...this.#state });
  }

  /**
   * Subscribe to future state changes.
   * Does NOT call listener immediately — use getState() for the current value.
   * Returns an unsubscribe function — call it in disconnectedCallback.
   *
   * @param {function} listener  — receives a shallow copy of state on each change
   * @returns {function}           unsubscribe
   */
  subscribe(listener) {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }
}
