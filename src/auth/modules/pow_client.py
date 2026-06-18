# modules/pow_client.py
import hashlib
from typing import Optional


class PoWClient:
    """Client-side PoW solver (for testing/CLI tools)"""

    @staticmethod
    def solve(challenge: str, difficulty: int, max_attempts: int = 10_000_000) -> Optional[str]:
        """
        Solve a PoW challenge by finding a valid nonce

        Args:
            challenge: The challenge string from server
            difficulty: Number of leading zeros required
            max_attempts: Maximum attempts before giving up

        Returns:
            Valid nonce string or None if not found
        """
        prefix = "0" * difficulty
        nonce = 0

        print(f"Solving PoW (difficulty: {difficulty})...")

        while nonce < max_attempts:
            nonce_str = str(nonce)
            input_string = challenge + nonce_str
            hash_result = hashlib.sha256(input_string.encode()).hexdigest()

            if hash_result.startswith(prefix):
                print(f"Found solution! Nonce: {nonce_str}")
                print(f"Hash: {hash_result}")
                return nonce_str

            nonce += 1

            # Progress indicator
            if nonce % 100000 == 0:
                print(f"  Tried {nonce:,} nonces...")

        print(f"Failed to find solution after {max_attempts:,} attempts")
        return None

    @staticmethod
    def benchmark(difficulty: int = 4, samples: int = 5) -> Dict:
        """
        Benchmark PoW solving speed

        Args:
            difficulty: Difficulty level to test
            samples: Number of samples to average

        Returns:
            Dict with benchmark results
        """
        import time
        import secrets

        times = []

        for i in range(samples):
            challenge = secrets.token_urlsafe(32)

            start = time.time()
            nonce = PoWClient.solve(challenge, difficulty)
            elapsed = time.time() - start

            if nonce:
                times.append(elapsed)
                print(f"Sample {i+1}: {elapsed:.2f}s")

        if times:
            avg_time = sum(times) / len(times)
            return {
                'difficulty': difficulty,
                'samples': len(times),
                'average_seconds': round(avg_time, 2),
                'min_seconds': round(min(times), 2),
                'max_seconds': round(max(times), 2)
            }
        return {'error': 'No successful samples'}


# Example usage:
if __name__ == "__main__":
    # Test PoW system
    from pow import PoW

    pow_system = PoW(difficulty=3)  # Lower difficulty for testing

    # Generate challenge
    challenge = pow_system.generate_challenge()
    print(f"Challenge: {challenge}")

    # Solve it
    client = PoWClient()
    nonce = client.solve(challenge.challenge, challenge.difficulty)

    if nonce:
        # Verify
        result = pow_system.verify(challenge.challenge_id, nonce)
        print(f"Verification: {result}")

        if result.success:
            print(f"Session Token: {result.session_token}")

    # Cleanup
    pow_system.destroy()
