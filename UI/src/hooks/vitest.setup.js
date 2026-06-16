import { webcrypto } from 'node:crypto'

// Polyfill crypto.subtle for jsdom environment
if (!globalThis.crypto?.subtle) {
  globalThis.crypto = webcrypto
}
