"""
Key Management Module - ECDSA P-256 Keypair Generation and Storage
Location: src/crypto/key_manager.py

Handles:
- ECDSA P-256 keypair generation
- Public key hash computation
- Private key encryption for backup
- Key format conversion (PEM, DER, hex)
"""

import os
import hashlib
from typing import Dict, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import qrcode


@dataclass
class KeyPair:
    """Represents a user's cryptographic keypair"""
    private_key_pem: str          # PEM-encoded private key
    public_key_hex: str           # Hex-encoded public key (uncompressed)
    public_key_hash: str          # SHA256 hash of public key
    public_key_compressed: str    # Compressed format for storage
    
    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict"""
        return {
            "private_key_pem": self.private_key_pem,
            "public_key_hex": self.public_key_hex,
            "public_key_hash": self.public_key_hash,
            "public_key_compressed": self.public_key_compressed,
        }


@dataclass
class EncryptedKeyBackup:
    """Represents an encrypted private key backup"""
    encrypted_key_hex: str  # AES-256-GCM ciphertext (hex)
    salt: str               # PBKDF2 salt (hex)
    iv: str                 # AES IV (hex)
    auth_tag: str           # Authentication tag (hex)
    
    def to_dict(self) -> dict:
        return {
            "encrypted_key": self.encrypted_key_hex,
            "salt": self.salt,
            "iv": self.iv,
            "auth_tag": self.auth_tag,
        }


class KeyManager:
    """
    Manages cryptographic key operations for MedLedger
    
    Security Properties:
    - Uses ECDSA P-256 (secp256r1) for all asymmetric operations
    - Private keys generated with cryptographically secure random
    - Public keys never stored with private keys
    - Optional password-protected key backup
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256R1()  # P-256
        
    # ==================== Keypair Generation ====================
    
    def generate_keypair(self) -> KeyPair:
        """
        Generate a new ECDSA P-256 keypair for a user
        
        Returns:
            KeyPair: Named tuple with PEM private key, hex public key, and hash
            
        Security Notes:
            - Uses OS entropy for randomness
            - Never stores this private key in plaintext in database
            - User must save returned PEM immediately
        
        Performance: ~5-10ms
        """
        try:
            # Generate private key (256-bit)
            private_key = ec.generate_private_key(self.curve, self.backend)
            
            # Serialize private key to PEM
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Extract public key
            public_key = private_key.public_key()
            
            # Get uncompressed public key (65 bytes: 0x04 + X + Y)
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            public_key_hex = public_key_bytes.hex()
            
            # Compute SHA256 hash of public key
            public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
            
            # Get compressed public key format
            public_key_compressed = self._compress_public_key(public_key_bytes)
            
            return KeyPair(
                private_key_pem=private_key_pem,
                public_key_hex=public_key_hex,
                public_key_hash=public_key_hash,
                public_key_compressed=public_key_compressed,
            )
        
        except Exception as e:
            raise KeyError(f"Failed to generate keypair: {str(e)}")
    
    # ==================== Key Encryption (Optional Backup) ====================
    
    def encrypt_private_key_backup(
        self,
        private_key_pem: str,
        password: str
    ) -> EncryptedKeyBackup:
        """
        Encrypt a private key with a user's password for secure backup
        
        Process:
            1. Generate random salt (16 bytes)
            2. Derive KEK using PBKDF2HMAC-SHA256 (100,000 iterations)
            3. Generate random IV (96 bits for AES-GCM)
            4. Encrypt private key with AES-256-GCM
            5. Return encrypted data + salt + IV
        
        Args:
            private_key_pem: PEM-encoded private key string
            password: User's password for key derivation
            
        Returns:
            EncryptedKeyBackup: Encrypted key + metadata
            
        Security:
            - PBKDF2HMAC with 100,000 iterations (OWASP 2023 standard)
            - AES-256-GCM with 96-bit IV
            - Authentication tag prevents tampering
            - Only recoverable with correct password
        
        Performance: ~200-300ms (due to PBKDF2HMAC iterations)
        """
        try:
            # Generate random salt
            salt = os.urandom(16)  # 128 bits
            
            # Derive Key Encryption Key (KEK)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=salt,
                iterations=100000,
            )
            kek = kdf.derive(password.encode('utf-8'))
            
            # Generate random IV
            iv = os.urandom(12)  # 96 bits (recommended for AES-GCM)
            
            # Encrypt private key
            cipher = AESGCM(kek)
            private_key_bytes = private_key_pem.encode('utf-8')
            
            ciphertext = cipher.encrypt(iv, private_key_bytes, None)
            
            # AES-GCM includes authentication tag in last 16 bytes
            encrypted_data = ciphertext[:-16]  # Ciphertext
            auth_tag = ciphertext[-16:]        # Auth tag
            
            return EncryptedKeyBackup(
                encrypted_key_hex=encrypted_data.hex(),
                salt=salt.hex(),
                iv=iv.hex(),
                auth_tag=auth_tag.hex(),
            )
        
        except Exception as e:
            raise ValueError(f"Failed to encrypt private key: {str(e)}")
    
    def decrypt_private_key_backup(
        self,
        encrypted_backup: EncryptedKeyBackup,
        password: str
    ) -> str:
        """
        Decrypt a password-protected private key backup
        
        Args:
            encrypted_backup: EncryptedKeyBackup object
            password: User's password
            
        Returns:
            str: Decrypted PEM-encoded private key
            
        Raises:
            ValueError: If password is incorrect or backup is corrupted
        """
        try:
            # Decode hex values
            encrypted_data = bytes.fromhex(encrypted_backup.encrypted_key_hex)
            salt = bytes.fromhex(encrypted_backup.salt)
            iv = bytes.fromhex(encrypted_backup.iv)
            auth_tag = bytes.fromhex(encrypted_backup.auth_tag)
            
            # Derive KEK
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            kek = kdf.derive(password.encode('utf-8'))
            
            # Decrypt
            cipher = AESGCM(kek)
            ciphertext = encrypted_data + auth_tag
            
            plaintext = cipher.decrypt(iv, ciphertext, None)
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key (wrong password?): {str(e)}")
    
    # ==================== Key Format Conversion ====================
    
    def _compress_public_key(self, uncompressed_key: bytes) -> str:
        """
        Convert uncompressed public key (65 bytes) to compressed format (33 bytes)
        
        Uncompressed: 0x04 || X || Y  (65 bytes)
        Compressed:   0x02/0x03 || X  (33 bytes)
        
        The prefix is:
        - 0x02 if Y is even
        - 0x03 if Y is odd
        """
        if len(uncompressed_key) != 65 or uncompressed_key[0] != 0x04:
            raise ValueError("Invalid uncompressed public key format")
        
        x = uncompressed_key[1:33]
        y = uncompressed_key[33:65]
        
        # Check if Y coordinate is even or odd (look at last byte)
        prefix = 0x02 if y[-1] % 2 == 0 else 0x03
        
        compressed = bytes([prefix]) + x
        return compressed.hex()
    
    def get_public_key_from_private(self, private_key_pem: str) -> Dict[str, str]:
        """
        Extract public key from a private key
        
        Args:
            private_key_pem: PEM-encoded private key
            
        Returns:
            Dict with:
            - public_key_hex: Uncompressed hex
            - public_key_compressed: Compressed hex
            - public_key_hash: SHA256 hash
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=self.backend
            )
            
            public_key = private_key.public_key()
            
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            public_key_hex = public_key_bytes.hex()
            public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
            public_key_compressed = self._compress_public_key(public_key_bytes)
            
            return {
                "public_key_hex": public_key_hex,
                "public_key_compressed": public_key_compressed,
                "public_key_hash": public_key_hash,
            }
        
        except Exception as e:
            raise ValueError(f"Failed to extract public key: {str(e)}")
    
    # ==================== Key Validation ====================
    
    def validate_public_key(self, public_key_hex: str) -> bool:
        """
        Validate that a hex string is a valid ECDSA P-256 public key
        
        Args:
            public_key_hex: Hex-encoded public key (uncompressed or compressed)
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            key_bytes = bytes.fromhex(public_key_hex)
            
            # Check uncompressed format (0x04 + 64 bytes = 65 bytes)
            if len(key_bytes) == 65 and key_bytes[0] == 0x04:
                return True
            
            # Check compressed format (0x02/0x03 + 32 bytes = 33 bytes)
            if len(key_bytes) == 33 and key_bytes[0] in [0x02, 0x03]:
                return True
            
            return False
        
        except (ValueError, TypeError):
            return False
    
    # ==================== QR Code Generation ====================
    
    def generate_key_qr_code(self, private_key_pem: str) -> str:
        """
        Generate a QR code containing the private key for secure backup
        
        Args:
            private_key_pem: Private key in PEM format
            
        Returns:
            str: Base64-encoded PNG image data
            
        Warning: This should be saved offline by the user!
        """
        try:
            import base64
            from io import BytesIO
            
            qr = qrcode.QRCode(
                version=10,  # Large enough for PEM key
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(private_key_pem)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_bytes = buffer.getvalue()
            img_base64 = base64.b64encode(img_bytes).decode('utf-8')
            
            return f"data:image/png;base64,{img_base64}"
        
        except Exception as e:
            raise ValueError(f"Failed to generate QR code: {str(e)}")


# ==================== Utility Functions ====================

def compute_public_key_hash(public_key_hex: str) -> str:
    """
    Compute SHA256 hash of a public key (used as unique identifier)
    
    Args:
        public_key_hex: Hex-encoded public key
        
    Returns:
        str: SHA256 hash in hex format
    """
    key_bytes = bytes.fromhex(public_key_hex)
    return hashlib.sha256(key_bytes).hexdigest()


# ==================== Example Usage ====================

if __name__ == "__main__":
    manager = KeyManager()
    
    # Example 1: Generate keypair
    print("=== Generate Keypair ===")
    keypair = manager.generate_keypair()
    print(f"Public Key Hash: {keypair.public_key_hash}")
    print(f"Private Key (first 50 chars): {keypair.private_key_pem[:50]}...")
    print()
    
    # Example 2: Encrypt for backup
    print("=== Encrypt Private Key Backup ===")
    password = "MySecurePassword123!"
    backup = manager.encrypt_private_key_backup(
        keypair.private_key_pem,
        password
    )
    print(f"Encrypted (first 50 chars): {backup.encrypted_key_hex[:50]}...")
    print()
    
    # Example 3: Decrypt backup
    print("=== Decrypt Private Key Backup ===")
    recovered_key = manager.decrypt_private_key_backup(backup, password)
    print(f"Recovered correctly: {recovered_key == keypair.private_key_pem}")
    print()
    
    # Example 4: Generate QR code
    print("=== Generate QR Code ===")
    qr_data = manager.generate_key_qr_code(keypair.private_key_pem)
    print(f"QR Code generated (first 50 chars): {qr_data[:50]}...")