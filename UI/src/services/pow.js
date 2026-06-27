/**
 * pow.js — Proof-of-Work orchestration.
 *
 * Usage:
 *   const solution = await solvePoW();
 *   // then register with solution.challengeId + solution.solution
 *
 * The caller owns the timing — typically:
 *   1. Show a "Solving PoW..." spinner
 *   2. Call solvePoW()
 *   3. On resolve, proceed to register
 *   4. If the user cancels, call the returned cancel() function
 */

import { requestPoWChallenge, verifyPoWSolution } from './auth.js';

/**
 * solvePoW()
 *
 * Requests a challenge from the server, spawns a dedicated Worker to solve it,
 * and verifies the solution. Returns { challengeId, solution } for use in
 * the register payload.
 *
 * The Worker is terminated in all exit paths — success, error, and cancellation.
 *
 * @returns {{ challengeId: string, solution: string }}
 * @throws  on network error or solver failure
 */
export async function solvePoW() {
  // 1. Fetch challenge — difficulty is dynamic, never hardcoded
  const { challenge_id, challenge, difficulty } = await requestPoWChallenge();

  let worker = null;
  let cancelled = false;

  const workerPromise = new Promise((resolve, reject) => {
    worker = new Worker(
      new URL('./pow_worker.js', import.meta.url),
      { type: 'module' }
    );

    worker.onmessage = (event) => {
      const { solution, error } = event.data;
      if (cancelled) return; // too late, ignore
      if (error) {
        reject(new Error(`PoW solver error: ${error}`));
      } else {
        resolve(solution);
      }
    };

    worker.onerror = (err) => {
      if (!cancelled) reject(new Error(`PoW worker error: ${err.message}`));
    };

    // 2. Start solving — pass difficulty from server, not a constant
    worker.postMessage({ challenge, difficulty });
  });

  let solution;
  try {
    solution = await workerPromise;
  } finally {
    if (worker) worker.terminate();
  }

  // 3. Verify with server before returning to caller
  await verifyPoWSolution(challenge_id, solution);

  return { challengeId: challenge_id, solution };
}
