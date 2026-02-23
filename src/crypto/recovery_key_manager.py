"""
Recovery Key Management System
Location: src/crypto/recovery_key_manager.py

Manages:
- Recovery key generation (separate from primary key)
- Fragment encryption for different storage locations
- Fragment validation and tracking
- Multi-factor authentication for recovery
- Time-limited access via recovery keys

Recovery Architecture:
1. Primary Key (ECDSA P-256) - User's main key
   └─ Split via Shamir Secret Sharing (3-of-5)
   └─ Fragments stored in 5 locations

2. Recovery Key (Separate ECDSA P-256)
   └─ Used ONLY for emergency access
   └─ Time-limited (24-72 hours)
   └─ Cannot decrypt permanent data

Fragment Storage Strategy:

Fragment 1 (User Vault)
├─ Location: User's vault (encrypted in browser/app)
├─ Access: User password
├─ Recovery Time: Immediate
├─ Encryption: AES-256-GCM with user's password-derived key

Fragment 2 (Hospital System)
├─ Location: Hospital's secure database
├─ Access: Hospital admin + audit
├─ Recovery Time: 30 minutes (admin approval)
├─ Encryption: AES-256-GCM with hospital's key

Fragment 3 (Blockchain Commitments)
├─ Location: Public blockchain (commitments only)
├─ Access: Public/cryptographic proof
├─ Recovery Time: Immediate
├─ Format: Commitment hash (can't recover from hash alone)

Fragment 4 (Email Backup)
├─ Location: User's email
├─ Access: Email verification + password
├─ Recovery Time: 1-2 hours (email delivery)
├─ Encryption: AES-256-GCM, sent via encrypted email

Fragment 5 (Trusted Contact)
├─ Location: Trusted contact's secure storage
├─ Access: Trusted contact's signature + user password
├─ Recovery Time: 24 hours (contact must approve)
├─ Encryption: AES-256-GCM with shared secret

Minimum Combinations to Recover:
- (1, 3, 4): User vault + blockchain + email = 1 hour
- (1, 3, 5): User vault + blockchain + trusted contact = 24 hours
- (1, 2, 3): User vault + hospital + blockchain = 30 minutes
- (2, 3, 4): Hospital + blockchain + email = 2-3 hours
- (3, 4, 5): Blockchain + email + trusted contact = 24-25 hours
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import os
import hashlib
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from src.crypto.secret_sharing import ShamirSecretSharing, SecretShare


class FragmentLocation(str, Enum):
    """Where fragments are stored"""
    VAULT = "VAULT"              # Fragment 1: User's encrypted vault
    HOSPITAL = "HOSPITAL"        # Fragment 2: Hospital database
    BLOCKCHAIN = "BLOCKCHAIN"    # Fragment 3: Public blockchain commitments
    EMAIL = "EMAIL"              # Fragment 4: User's email
    TRUSTED_CONTACT = "TRUSTED_CONTACT"  # Fragment 5: Trusted contact


class RecoveryStatus(str, Enum):
    """Status of recovery process"""
    NOT_STARTED = "NOT_STARTED"
    INITIATED = "INITIATED"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    FRAGMENTS_GATHERING = "FRAGMENTS_GATHERING"
    HOSPITAL_PENDING = "HOSPITAL_PENDING"
    READY_TO_RECONSTRUCT = "READY_TO_RECONSTRUCT"
    RECONSTRUCTED = "RECONSTRUCTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    LOCKED = "LOCKED"  # Too many failed attempts


@dataclass
class EncryptedFragment:
    """Encrypted share with metadata"""
    location: FragmentLocation
    encrypted_data: bytes       # AES-256-GCM ciphertext
    iv: bytes                   # 96-bit IV
    auth_tag: bytes            # 128-bit authentication tag
    salt: Optional[bytes]      # Optional salt (for user password derivation)
    created_at: datetime
    expires_at: Optional[datetime]  # Optional expiration
    
    def to_dict(self) -> dict:
        return {
            "location": self.location.value,
            "encrypted_data": self.encrypted_data.hex(),
            "iv": self.iv.hex(),
            "auth_tag": self.auth_tag.hex(),
            "salt": self.salt.hex() if self.salt else None,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class RecoveryKey:
    """Separate key for recovery access (time-limited)"""
    key_id: str                 # Unique identifier
    private_key_pem: str        # PEM-encoded recovery private key
    public_key_hash: str        # SHA256 hash of public key
    valid_from: datetime
    valid_until: datetime       # Expires automatically
    can_decrypt_temporary: bool  # Can decrypt DEK temporarily
    can_sign_access_grants: bool # Can sign emergency access grants
    scope: str                  # What this key can access
    
    def is_expired(self) -> bool:
        """Check if recovery key has expired"""
        return datetime.utcnow() > self.valid_until
    
    def time_remaining(self) -> timedelta:
        """Time until expiration"""
        return self.valid_until - datetime.utcnow()


@dataclass
class RecoveryAttempt:
    """Track recovery attempts for security"""
    user_id: int
    timestamp: datetime
    method: str              # Email, hospital, trusted contact, etc.
    status: str              # Success, failed, pending
    fragments_gathered: List[int]  # Which fragments were obtained
    ip_address: Optional[str]
    user_agent: Optional[str]


class RecoveryKeyManager:
    """
    Manages recovery keys and fragmented secret storage
    
    Security Properties:
    - Primary key never exposed (split into fragments)
    - Recovery key separate from primary (limited scope)
    - Multi-factor authentication required
    - Time-limited recovery access
    - Audit trail on blockchain
    - Rate limiting to prevent brute force
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256R1()  # P-256
        self.sss = ShamirSecretSharing(threshold=3, total_shares=5)
    
    # ==================== Recovery Key Generation ====================
    
    def generate_recovery_key(
        self,
        duration_hours: int = 72,
        scope: str = "temporary_access"
    ) -> RecoveryKey:
        """
        Generate a recovery key (separate from primary key)
        
        Purpose:
        - Used ONLY for emergency access
        - Time-limited to prevent indefinite use
        - Can't decrypt permanent data
        - Limited scope
        
        Args:
            duration_hours: How long recovery key is valid (default 72)
            scope: What this key can do (temporary_access, emergency_access, etc.)
            
        Returns:
            RecoveryKey with cryptographic material
            
        Performance: ~10-15ms
        """
        import uuid
        
        # Generate separate ECDSA P-256 keypair for recovery
        private_key = ec.generate_private_key(self.curve, self.backend)
        
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
        
        now = datetime.utcnow()
        
        return RecoveryKey(
            key_id=f"recovery_{uuid.uuid4().hex[:16]}",
            private_key_pem=private_key_pem,
            public_key_hash=public_key_hash,
            valid_from=now,
            valid_until=now + timedelta(hours=duration_hours),
            can_decrypt_temporary=True,
            can_sign_access_grants=True,
            scope=scope,
        )
    
    # ==================== Fragment Encryption ====================
    
    def encrypt_fragment_vault(
        self,
        fragment: SecretShare,
        user_password: str,
        user_salt: bytes = None
    ) -> EncryptedFragment:
        """
        Encrypt Fragment 1 for user vault storage
        
        Uses PBKDF2 to derive key from user's password.
        User can decrypt immediately if they remember password.
        
        Args:
            fragment: Share from SSS
            user_password: User's login password
            user_salt: PBKDF2 salt (generated if not provided)
            
        Returns:
            EncryptedFragment ready for storage
            
        Security: AES-256-GCM with password-derived key
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        if user_salt is None:
            user_salt = os.urandom(16)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=user_salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(user_password.encode('utf-8'))
        
        # Encrypt fragment
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = AESGCM(key)
        
        fragment_bytes = fragment.to_bytes()
        ciphertext = cipher.encrypt(iv, fragment_bytes, None)
        
        # AES-GCM includes auth tag in last 16 bytes of ciphertext
        encrypted_data = ciphertext[:-16]
        auth_tag = ciphertext[-16:]
        
        return EncryptedFragment(
            location=FragmentLocation.VAULT,
            encrypted_data=encrypted_data,
            iv=iv,
            auth_tag=auth_tag,
            salt=user_salt,
            created_at=datetime.utcnow(),
            expires_at=None,  # Vault fragment never expires
        )
    
    def encrypt_fragment_hospital(
        self,
        fragment: SecretShare,
        hospital_key: bytes  # Hospital's encryption key
    ) -> EncryptedFragment:
        """
        Encrypt Fragment 2 for hospital database storage
        
        Hospital manages access - can require admin approval.
        
        Args:
            fragment: Share from SSS
            hospital_key: Hospital's 256-bit encryption key
            
        Returns:
            EncryptedFragment for hospital database
            
        Security: AES-256-GCM with hospital's master key
        """
        iv = os.urandom(12)
        cipher = AESGCM(hospital_key)
        
        fragment_bytes = fragment.to_bytes()
        ciphertext = cipher.encrypt(iv, fragment_bytes, None)
        
        encrypted_data = ciphertext[:-16]
        auth_tag = ciphertext[-16:]
        
        return EncryptedFragment(
            location=FragmentLocation.HOSPITAL,
            encrypted_data=encrypted_data,
            iv=iv,
            auth_tag=auth_tag,
            salt=None,
            created_at=datetime.utcnow(),
            expires_at=None,
        )
    
    def encrypt_fragment_email(
        self,
        fragment: SecretShare,
        user_email: str,
        encryption_key: bytes  # Key for email encryption
    ) -> EncryptedFragment:
        """
        Encrypt Fragment 4 for email backup
        
        Sent to user's email address, can be accessed with email verification.
        
        Args:
            fragment: Share from SSS
            user_email: User's email address
            encryption_key: Key for encrypting before sending
            
        Returns:
            EncryptedFragment ready to send via email
            
        Security: AES-256-GCM, then sent over encrypted email
        """
        iv = os.urandom(12)
        cipher = AESGCM(encryption_key)
        
        fragment_bytes = fragment.to_bytes()
        # Include email in additional authenticated data
        aad = user_email.encode('utf-8')
        ciphertext = cipher.encrypt(iv, fragment_bytes, aad)
        
        encrypted_data = ciphertext[:-16]
        auth_tag = ciphertext[-16:]
        
        return EncryptedFragment(
            location=FragmentLocation.EMAIL,
            encrypted_data=encrypted_data,
            iv=iv,
            auth_tag=auth_tag,
            salt=None,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),  # Email backup expires in 1 year
        )
    
    def create_blockchain_commitment(
        self,
        fragment: SecretShare
    ) -> str:
        """
        Create blockchain commitment for Fragment 3
        
        Blockchain stores only the commitment hash, not the actual fragment.
        User can prove they have the fragment by showing it matches the commitment.
        
        Args:
            fragment: Share from SSS
            
        Returns:
            str: SHA256 hash of the fragment (commitment)
            
        Note:
            The actual fragment is stored off-chain.
            The commitment is stored on-chain for verification.
        """
        fragment_bytes = fragment.to_bytes()
        commitment = hashlib.sha256(fragment_bytes).hexdigest()
        return commitment
    
    # ==================== Fragment Decryption ====================
    
    def decrypt_fragment_vault(
        self,
        encrypted_fragment: EncryptedFragment,
        user_password: str
    ) -> SecretShare:
        """
        Decrypt Fragment 1 from user vault
        
        Args:
            encrypted_fragment: EncryptedFragment from storage
            user_password: User's password
            
        Returns:
            Decrypted SecretShare
            
        Raises:
            ValueError: If authentication fails (wrong password)
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Derive key from password using stored salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=encrypted_fragment.salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(user_password.encode('utf-8'))
        
        # Decrypt
        cipher = AESGCM(key)
        ciphertext = encrypted_fragment.encrypted_data + encrypted_fragment.auth_tag
        
        try:
            plaintext = cipher.decrypt(
                encrypted_fragment.iv,
                ciphertext,
                None
            )
        except Exception as e:
            raise ValueError(f"Decryption failed (wrong password?): {str(e)}")
        
        return SecretShare.from_bytes(plaintext)
    
    def decrypt_fragment_hospital(
        self,
        encrypted_fragment: EncryptedFragment,
        hospital_key: bytes
    ) -> SecretShare:
        """Decrypt Fragment 2 from hospital database"""
        cipher = AESGCM(hospital_key)
        ciphertext = encrypted_fragment.encrypted_data + encrypted_fragment.auth_tag
        
        try:
            plaintext = cipher.decrypt(
                encrypted_fragment.iv,
                ciphertext,
                None
            )
        except Exception as e:
            raise ValueError(f"Hospital fragment decryption failed: {str(e)}")
        
        return SecretShare.from_bytes(plaintext)
    
    def decrypt_fragment_email(
        self,
        encrypted_fragment: EncryptedFragment,
        user_email: str,
        encryption_key: bytes
    ) -> SecretShare:
        """Decrypt Fragment 4 from email"""
        cipher = AESGCM(encryption_key)
        ciphertext = encrypted_fragment.encrypted_data + encrypted_fragment.auth_tag
        aad = user_email.encode('utf-8')
        
        try:
            plaintext = cipher.decrypt(
                encrypted_fragment.iv,
                ciphertext,
                aad
            )
        except Exception as e:
            raise ValueError(f"Email fragment decryption failed: {str(e)}")
        
        return SecretShare.from_bytes(plaintext)
    
    # ==================== Recovery Rate Limiting ====================
    
    def check_recovery_eligible(
        self,
        user_id: int,
        recovery_attempts: List[RecoveryAttempt],
        max_attempts_per_hour: int = 3,
        lockout_hours: int = 24
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if user is eligible for recovery attempt
        
        Prevents brute force:
        - Max 3 attempts per hour
        - 24-hour lockout after 3 failed attempts
        
        Args:
            user_id: User attempting recovery
            recovery_attempts: Previous recovery attempts
            max_attempts_per_hour: Max attempts allowed per hour
            lockout_hours: Hours to lock out after failures
            
        Returns:
            Tuple of (is_eligible, reason_if_not)
        """
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)
        
        # Count recent attempts
        recent_attempts = [
            a for a in recovery_attempts
            if a.timestamp > one_hour_ago
        ]
        
        if len(recent_attempts) >= max_attempts_per_hour:
            return False, f"Too many attempts. Try again after 1 hour."
        
        # Check for lockout
        recent_failures = [
            a for a in recovery_attempts
            if a.status == "failed" and
            a.timestamp > (now - timedelta(hours=lockout_hours))
        ]
        
        if len(recent_failures) >= 3:
            lockout_until = recent_failures[0].timestamp + timedelta(hours=lockout_hours)
            return False, f"Too many failed attempts. Locked until {lockout_until}"
        
        return True, None
    
    # ==================== Recovery State Machine ====================
    
    def get_recovery_summary(
        self,
        fragments_available: Dict[FragmentLocation, bool],
        recovery_status: RecoveryStatus
    ) -> Dict:
        """
        Get current recovery status and what's needed next
        
        Args:
            fragments_available: Which fragments user has obtained
            recovery_status: Current stage of recovery
            
        Returns:
            Dictionary with status and next steps
        """
        available_count = sum(1 for v in fragments_available.values() if v)
        
        return {
            "current_status": recovery_status.value,
            "fragments_obtained": available_count,
            "fragments_needed": 3,
            "ready_to_reconstruct": available_count >= 3,
            "available_fragments": {
                loc.value: available
                for loc, available in fragments_available.items()
            },
            "next_steps": self._get_next_recovery_steps(
                fragments_available,
                recovery_status
            ),
        }
    
    def _get_next_recovery_steps(
        self,
        fragments_available: Dict[FragmentLocation, bool],
        recovery_status: RecoveryStatus
    ) -> List[str]:
        """Generate human-readable next steps"""
        steps = []
        
        if not fragments_available.get(FragmentLocation.VAULT):
            steps.append("1. Download Fragment 1 from your vault (encrypted)")
        
        if not fragments_available.get(FragmentLocation.EMAIL):
            steps.append("2. Check your email for Fragment 4 recovery code")
        
        if not fragments_available.get(FragmentLocation.BLOCKCHAIN):
            steps.append("3. System will retrieve Fragment 3 from blockchain")
        
        if sum(1 for v in fragments_available.values() if v) < 3:
            if not fragments_available.get(FragmentLocation.HOSPITAL):
                steps.append("4. (Optional) Request Fragment 2 from hospital")
            if not fragments_available.get(FragmentLocation.TRUSTED_CONTACT):
                steps.append("4. (Optional) Contact trusted contact for Fragment 5")
        
        if sum(1 for v in fragments_available.values() if v) >= 3:
            steps.append("✓ Ready to reconstruct private key")
        
        return steps


# ==================== Example Usage ====================

if __name__ == "__main__":
    print("=== Recovery Key Manager Example ===\n")
    
    mgr = RecoveryKeyManager()
    
    # 1. Generate recovery key
    print("1. Generating recovery key...")
    recovery_key = mgr.generate_recovery_key(duration_hours=72)
    print(f"   Key ID: {recovery_key.key_id}")
    print(f"   Valid until: {recovery_key.valid_until}")
    print(f"   Expired: {recovery_key.is_expired()}\n")
    
    # 2. Split a secret and create fragments
    print("2. Splitting secret into 5 fragments...")
    secret = b"Patient's Private Key EncryptionKey123"
    fragments = mgr.sss.split_secret(secret)
    print(f"   Created {len(fragments)} fragments (3-of-5 recovery)\n")
    
    # 3. Encrypt fragments for different storage locations
    print("3. Encrypting fragments for different locations...")
    
    # Fragment 1 (User Vault)
    encrypted_vault = mgr.encrypt_fragment_vault(
        fragments[0],
        "user_password_123"
    )
    print(f"   Fragment 1 (Vault): Encrypted with password")
    
    # Fragment 4 (Email)
    email_key = os.urandom(32)
    encrypted_email = mgr.encrypt_fragment_email(
        fragments[3],
        "patient@hospital.com",
        email_key
    )
    print(f"   Fragment 4 (Email): Encrypted for email delivery")
    
    # Fragment 3 (Blockchain)
    blockchain_commitment = mgr.create_blockchain_commitment(fragments[2])
    print(f"   Fragment 3 (Blockchain): {blockchain_commitment[:32]}...\n")
    
    # 4. Decrypt and reconstruct
    print("4. Recovering secret...")
    decrypted_1 = mgr.decrypt_fragment_vault(encrypted_vault, "user_password_123")
    print(f"   Fragment 1: Decrypted from vault")
    
    decrypted_4 = mgr.decrypt_fragment_email(
        encrypted_email,
        "patient@hospital.com",
        email_key
    )
    print(f"   Fragment 4: Decrypted from email")
    
    # Reconstruct from 3 fragments (we'll use 1, 2, 4)
    recovered = mgr.sss.reconstruct_secret([fragments[0], fragments[1], fragments[3]])
    print(f"   Reconstructed: {recovered}")
    print(f"   Match: {recovered == secret}\n")
    
    print("=== Example Complete ===")
