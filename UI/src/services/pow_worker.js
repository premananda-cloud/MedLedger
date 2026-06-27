/**
 * pow_worker.js — Proof-of-Work solver (dedicated Worker).
 *
 * Spawned once per registration attempt. Solves a SHA-256 PoW challenge
 * and terminates. Stateless — no imports, no side effects outside postMessage.
 *
 * Message in (from main thread):
 *   { challenge: string, difficulty: number }
 *
 * Message out (to main thread):
 *   { solution: string }   — on success
 *   { error: string }      — on unexpected failure
 *
 * Algorithm:
 *   Find the smallest nonce (hex string) such that:
 *     SHA-256(challenge + nonce).slice(0, difficulty) === '0'.repeat(difficulty)
 *
 * The server verifies the same condition on its side.
 */

self.onmessage = async function (event) {
  const { challenge, difficulty } = event.data;

  if (!challenge || typeof difficulty !== 'number' || difficulty < 1) {
    self.postMessage({ error: 'Invalid PoW parameters' });
    return;
  }

  const prefix = '0'.repeat(difficulty);
  const encoder = new TextEncoder();

  let nonce = 0;

  try {
    while (true) {
      const nonceHex = nonce.toString(16);
      const input = challenge + nonceHex;
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input));
      const hashHex = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      if (hashHex.startsWith(prefix)) {
        self.postMessage({ solution: nonceHex });
        return;
      }

      nonce++;

      // Yield every 5000 iterations so the browser doesn't flag us as hung.
      // crypto.subtle.digest is async so this is technically yielding already,
      // but being explicit is safer across engines.
      if (nonce % 5000 === 0) {
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }
  } catch (err) {
    self.postMessage({ error: err.message ?? String(err) });
  }
};
