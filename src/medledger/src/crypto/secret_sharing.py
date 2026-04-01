"""
Shamir Secret Sharing for Key Recovery
Location: src/crypto/shamirs_secret_sharing.py

Implements threshold cryptography to split a private key into shares.
Requires k-of-n shares to reconstruct the original key.

This uses Lagrange interpolation over a finite field (Galois Field GF(256)).
- Threshold: 3 (k)
- Total Shares: 5 (n)
- Security: Information-theoretic (secure against unlimited computation)

References:
- Shamir, A. (1979). How to Share a Secret
- Adi Shamir's original algorithm
"""

from typing import List, Tuple, Optional
import os
import secrets
from dataclasses import dataclass
import json


@dataclass
class SecretShare:
    """Represents a single share of a secret"""
    share_id: int           # x-coordinate (1-5)
    share_value: bytes      # y-coordinate value
    threshold: int          # k (shares needed)
    total_shares: int       # n (total shares)
    secret_hash: str        # SHA256 of original secret for verification
    
    def to_dict(self) -> dict:
        return {
            "share_id": self.share_id,
            "share_value": self.share_value.hex(),
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "secret_hash": self.secret_hash,
        }
    
    def to_bytes(self) -> bytes:
        """Serialize share to bytes for storage"""
        # Format: [share_id:1][threshold:1][total:1][hash:32][data:variable]
        data = bytes([self.share_id, self.threshold, self.total_shares])
        data += bytes.fromhex(self.secret_hash)
        data += self.share_value
        return data
    
    @staticmethod
    def from_bytes(data: bytes) -> 'SecretShare':
        """Deserialize share from bytes"""
        share_id = data[0]
        threshold = data[1]
        total_shares = data[2]
        secret_hash = data[3:35].hex()
        share_value = data[35:]
        
        return SecretShare(
            share_id=share_id,
            share_value=share_value,
            threshold=threshold,
            total_shares=total_shares,
            secret_hash=secret_hash,
        )


class GaloisField:
    """
    Galois Field arithmetic for finite field operations
    Uses GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1
    """
    
    # Irreducible polynomial: 0x11D (100011101 in binary)
    IRRED_POLY = 0x11D
    
    # Precomputed multiplication tables for performance
    EXP_TABLE = []
    LOG_TABLE = []
    
    @classmethod
    def init_tables(cls):
        """Initialize logarithm and exponentiation tables"""
        if cls.EXP_TABLE:
            return  # Already initialized
        
        cls.EXP_TABLE = [0] * 512
        cls.LOG_TABLE = [0] * 256
        
        poly = 1
        for i in range(255):  # Only 255 iterations: g^0..g^254 (g^255=g^0=1)
            cls.EXP_TABLE[i] = poly
            cls.LOG_TABLE[poly] = i
            
            # Multiply by 2 (generator)
            poly <<= 1
            if poly & 0x100:
                poly ^= cls.IRRED_POLY
        
        cls.EXP_TABLE[255] = 1  # g^255 = 1 (wrap-around)
        
        # Extend EXP_TABLE for wraparound (period is 255, not 256)
        for i in range(256, 512):
            cls.EXP_TABLE[i] = cls.EXP_TABLE[i - 255]
    
    @classmethod
    def multiply(cls, a: int, b: int) -> int:
        """Multiply two elements in GF(256)"""
        if not cls.EXP_TABLE:
            cls.init_tables()
        
        if a == 0 or b == 0:
            return 0
        
        log_a = cls.LOG_TABLE[a]
        log_b = cls.LOG_TABLE[b]
        return cls.EXP_TABLE[log_a + log_b]
    
    @classmethod
    def divide(cls, a: int, b: int) -> int:
        """Divide a by b in GF(256)"""
        if b == 0:
            raise ValueError("Division by zero")
        if a == 0:
            return 0
        
        log_a = cls.LOG_TABLE[a]
        log_b = cls.LOG_TABLE[b]
        return cls.EXP_TABLE[log_a - log_b + 255]
    
    @classmethod
    def inverse(cls, a: int) -> int:
        """Return multiplicative inverse of a in GF(256)"""
        if a == 0:
            raise ValueError("Zero has no inverse")
        return cls.EXP_TABLE[255 - cls.LOG_TABLE[a]]


class ShamirSecretSharing:
    """
    Shamir Secret Sharing Scheme
    
    Splits a secret into n shares such that any k shares can reconstruct
    the secret, but fewer than k shares reveal no information about it.
    
    Mathematical Foundation:
    - Choose random polynomial: f(x) = a0 + a1*x + ... + a(k-1)*x^(k-1)
    - a0 = secret (the constant term)
    - Create shares: (1, f(1)), (2, f(2)), ..., (n, f(n))
    - Given k shares, use Lagrange interpolation to recover f(x)
    - Evaluate f(0) to get the secret
    
    Security:
    - Information-theoretic security (k-1 shares reveal nothing)
    - No computational assumptions needed
    - Works over any finite field (we use GF(256))
    """
    
    def __init__(self, threshold: int = 3, total_shares: int = 5):
        """
        Initialize Shamir Secret Sharing parameters
        
        Args:
            threshold: Minimum shares needed to reconstruct (k)
            total_shares: Total shares to generate (n)
            
        Raises:
            ValueError: If threshold > total_shares or parameters invalid
        """
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")
        if total_shares < threshold:
            raise ValueError("Total shares must be >= threshold")
        if total_shares > 255:
            raise ValueError("Cannot have more than 255 shares (GF(256) limit)")
        
        self.threshold = threshold
        self.total_shares = total_shares
        GaloisField.init_tables()
    
    # ==================== Polynomial Operations ====================
    
    def _generate_polynomial(self, secret_byte: int) -> List[int]:
        """
        Generate random polynomial with given secret as constant term
        
        For a secret byte, creates polynomial:
        f(x) = secret_byte + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        
        Args:
            secret_byte: The secret value (0-255)
            
        Returns:
            List of coefficients [a0, a1, ..., a(k-1)]
        """
        # a0 = secret
        # a1...a(k-1) = random bytes
        polynomial = [secret_byte]
        
        for _ in range(self.threshold - 1):
            polynomial.append(secrets.randbelow(256))
        
        return polynomial
    
    def _evaluate_polynomial(self, polynomial: List[int], x: int) -> int:
        """
        Evaluate polynomial at x using Horner's method
        
        Computes: f(x) = a0 + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        
        Using Horner: f(x) = a0 + x*(a1 + x*(a2 + ...))
        
        Args:
            polynomial: List of coefficients [a0, a1, ...]
            x: Point to evaluate at
            
        Returns:
            f(x) in GF(256)
        """
        result = 0
        for coeff in reversed(polynomial):
            result = GaloisField.multiply(result, x) ^ coeff
        return result
    
    # ==================== Splitting ====================
    
    def split_secret(self, secret: bytes) -> List[SecretShare]:
        """
        Split a secret into n shares (threshold k)
        
        Process:
        1. For each byte of secret, generate a random polynomial
        2. Evaluate polynomial at x = 1, 2, ..., n
        3. Combine byte values into shares
        
        Args:
            secret: Secret bytes to split (e.g., private key PEM)
            
        Returns:
            List of n SecretShare objects
            
        Example:
            >>> sss = ShamirSecretSharing(threshold=3, total_shares=5)
            >>> shares = sss.split_secret(b"my_secret_key")
            >>> len(shares)
            5
        """
        import hashlib
        
        secret_hash = hashlib.sha256(secret).hexdigest()
        
        # Initialize n shares (one for each x-coordinate)
        shares = [bytearray() for _ in range(self.total_shares)]
        
        # For each byte in the secret
        for secret_byte in secret:
            # Generate random polynomial with this byte as constant term
            polynomial = self._generate_polynomial(secret_byte)
            
            # Evaluate at x = 1, 2, ..., n to create share values
            for x in range(1, self.total_shares + 1):
                y = self._evaluate_polynomial(polynomial, x)
                shares[x - 1].append(y)
        
        # Convert to SecretShare objects
        result = []
        for x in range(1, self.total_shares + 1):
            result.append(SecretShare(
                share_id=x,
                share_value=bytes(shares[x - 1]),
                threshold=self.threshold,
                total_shares=self.total_shares,
                secret_hash=secret_hash,
            ))
        
        return result
    
    # ==================== Reconstruction ====================
    
    def _lagrange_coefficient(self, x_values: List[int], i: int, x: int = 0) -> int:
        """
        Compute Lagrange basis polynomial at x = 0
        
        For share points (x_i, y_i), Lagrange coefficient is:
        L_i(x) = ∏(x - x_j) / (x_i - x_j) for j ≠ i
        
        We evaluate at x = 0 to recover the constant term (secret).
        
        Args:
            x_values: List of x-coordinates (share IDs)
            i: Index of the share
            x: Point to evaluate at (default 0 for secret)
            
        Returns:
            Lagrange coefficient value in GF(256)
        """
        num = 1
        denom = 1
        
        x_i = x_values[i]
        
        for j, x_j in enumerate(x_values):
            if i == j:
                continue
            
            # numerator: (0 - x_j)
            num = GaloisField.multiply(num, x ^ x_j)
            
            # denominator: (x_i - x_j)
            denom = GaloisField.multiply(denom, x_i ^ x_j)
        
        return GaloisField.multiply(num, GaloisField.inverse(denom))
    
    def reconstruct_secret(self, shares: List[SecretShare]) -> bytes:
        """
        Reconstruct secret from k shares using Lagrange interpolation
        
        Process:
        1. Verify at least threshold shares provided
        2. For each byte position:
           a. Get the byte value from each share
           b. Compute Lagrange coefficients
           c. Sum: secret_byte = Σ(y_i * L_i) mod 256
        3. Verify against stored secret hash
        
        Args:
            shares: List of at least k SecretShare objects
            
        Returns:
            Reconstructed secret bytes
            
        Raises:
            ValueError: If fewer than threshold shares provided
            ValueError: If shares don't match (wrong shares or corrupted)
            
        Example:
            >>> sss = ShamirSecretSharing(3, 5)
            >>> all_shares = sss.split_secret(b"my_secret")
            >>> subset = all_shares[0:3]  # Use first 3 shares
            >>> recovered = sss.reconstruct_secret(subset)
            >>> recovered == b"my_secret"
            True
        """
        import hashlib
        
        if len(shares) < self.threshold:
            raise ValueError(
                f"Need at least {self.threshold} shares, got {len(shares)}"
            )
        
        # Verify all shares have same parameters
        first_share = shares[0]
        for share in shares[1:]:
            if share.threshold != first_share.threshold:
                raise ValueError("Shares have different thresholds")
            if share.total_shares != first_share.total_shares:
                raise ValueError("Shares have different total share counts")
            if share.secret_hash != first_share.secret_hash:
                raise ValueError("Shares have different secret hashes")
        
        # Get x-coordinates (share IDs)
        x_values = [share.share_id for share in shares]
        
        # Length should be same for all shares
        secret_length = len(shares[0].share_value)
        
        # Reconstruct secret byte by byte
        secret = bytearray()
        
        for byte_idx in range(secret_length):
            # Get y-values (bytes) from each share at this position
            y_values = [share.share_value[byte_idx] for share in shares]
            
            # Lagrange interpolation: secret = Σ(y_i * L_i(0)) in GF(256)
            secret_byte = 0
            for i in range(len(shares)):
                coeff = self._lagrange_coefficient(x_values, i, x=0)
                secret_byte ^= GaloisField.multiply(y_values[i], coeff)
            
            secret.append(secret_byte)
        
        secret_bytes = bytes(secret)
        
        # Verify against stored hash
        computed_hash = hashlib.sha256(secret_bytes).hexdigest()
        if computed_hash != first_share.secret_hash:
            raise ValueError(
                "Secret verification failed! Shares may be corrupted or wrong."
            )
        
        return secret_bytes
    
    # ==================== Utilities ====================
    
    def shares_from_dict(self, data: List[dict]) -> List[SecretShare]:
        """Create SecretShare objects from serialized dict data"""
        shares = []
        for share_dict in data:
            share = SecretShare(
                share_id=share_dict["share_id"],
                share_value=bytes.fromhex(share_dict["share_value"]),
                threshold=share_dict["threshold"],
                total_shares=share_dict["total_shares"],
                secret_hash=share_dict["secret_hash"],
            )
            shares.append(share)
        return shares


# ==================== Example & Testing ====================

if __name__ == "__main__":
    print("=== Shamir Secret Sharing Example ===\n")
    
    # Create SSS instance (3-of-5 sharing)
    sss = ShamirSecretSharing(threshold=3, total_shares=5)
    
    # Secret to share
    secret = b"My Private Encryption Key 12345"
    print(f"Original Secret: {secret}")
    print(f"Secret Length: {len(secret)} bytes\n")
    
    # Split into shares
    print("Splitting into 5 shares (need 3 to recover)...")
    shares = sss.split_secret(secret)
    print(f"Created {len(shares)} shares:\n")
    
    for share in shares:
        print(f"  Share {share.share_id}: {share.share_value.hex()[:32]}... "
              f"({len(share.share_value)} bytes)")
    print()
    
    # Attempt reconstruction with different combinations
    print("Attempting reconstruction with various share combinations:\n")
    
    # Test 1: Use first 3 shares (should work)
    print("Test 1: Using shares 1, 2, 3")
    recovered = sss.reconstruct_secret(shares[0:3])
    print(f"  Recovered: {recovered}")
    print(f"  Match: {recovered == secret}\n")
    
    # Test 2: Use shares 2, 4, 5 (should work)
    print("Test 2: Using shares 2, 4, 5")
    recovered = sss.reconstruct_secret([shares[1], shares[3], shares[4]])
    print(f"  Recovered: {recovered}")
    print(f"  Match: {recovered == secret}\n")
    
    # Test 3: Try with only 2 shares (should fail)
    print("Test 3: Using only 2 shares (should fail)")
    try:
        recovered = sss.reconstruct_secret(shares[0:2])
        print(f"  ERROR: Should have failed!")
    except ValueError as e:
        print(f"  Correctly rejected: {e}\n")
    
    # Test 4: Share corruption detection
    print("Test 4: Detecting corrupted share")
    corrupted_shares = [shares[0], shares[1], shares[2]]
    # Corrupt one byte in a share
    corrupted_shares[1].share_value = (
        corrupted_shares[1].share_value[:-1] + bytes([0xFF])
    )
    try:
        recovered = sss.reconstruct_secret(corrupted_shares)
        print(f"  ERROR: Should have detected corruption!")
    except ValueError as e:
        print(f"  Correctly detected: {e}\n")
    
    print("=== All Tests Complete ===")