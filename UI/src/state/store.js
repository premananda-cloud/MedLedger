/**
 * store.js — Minimal observable store.
 *
 * Usage:
 *   const store = new Store({ count: 0 });
 *   const unsub = store.subscribe(state => console.log(state));
 *   store.setState({ count: 1 });
 *   unsub();
 */
export class Store {
  #state;
  #listeners = new Set();

  constructor(initialState) {
    this.#state = initialState;
  }

  getState() {
    return this.#state;
  }

  setState(partial) {
    this.#state = { ...this.#state, ...partial };
    for (const fn of this.#listeners) fn(this.#state);
  }

  /**
   * Subscribe to state changes. Calls listener immediately with current state.
   * Returns an unsubscribe function — MUST be called in disconnectedCallback.
   * @param {function} listener
   * @returns {function} unsubscribe
   */
  subscribe(listener) {
    this.#listeners.add(listener);
    listener(this.#state); // immediate snapshot
    return () => this.#listeners.delete(listener);
  }
}
