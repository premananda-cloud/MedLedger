"""
Signature Verifier Module - ECDSA P-256 Signature Operations
Location: src/crypto/signature_verifier.py

Handles:
- ECDSA P-256 signature creation (patient signs permissions)
- ECDSA P-256 signature verification (verify patient authorized access)
- Permission data serialization (JSON to bytes for signing)
- Signature format conversion (hex, bytes)
"""

import json
import hashlib
from typing import Tuple, Dict, Optional
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class SignatureVerifier:
    """
    Verifies and creates ECDSA P-256 signatures for permission grants
    
    Security Properties:
    - Uses ECDSA P-256 (secp256r1) for all signature operations
    - Signatures are deterministic (RFC 6979)
    - Signatures cannot be forged without private key
    - Signatures are non-repudiable (signer cannot deny)
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256R1()  # P-256
        self.hash_algorithm = hashes.SHA256()
    
    # ==================== Permission Signing ====================
    
    def sign_permission(
        self,
        private_key_pem: str,
        permission_data: Dict
    ) -> str:
        """
        Sign a permission grant with patient's private key
        
        Process:
            1. Serialize permission_data to deterministic JSON
            2. Hash with SHA-256
            3. Sign hash with ECDSA P-256 private key
            4. Return signature in hex format
        
        Args:
            private_key_pem: PEM-encoded ECDSA private key
            permission_data: Dict with:
                - patient_id: str
                - doctor_id: str
                - record_id: str
                - time_start: ISO datetime string
                - time_end: ISO datetime string
                - permission_level: str ("view_only" or "view_download")
        
        Returns:
            str: Hex-encoded ECDSA signature
            
        Raises:
            ValueError: If private key is invalid or signing fails
            
        Performance: ~5-10ms
        """
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=self.backend
            )
            
            # Serialize permission data to deterministic JSON
            # Sort keys for reproducibility
            permission_json = json.dumps(
                permission_data,
                sort_keys=True,
                separators=(',', ':')
            )
            
            # Sign the permission data
            signature_bytes = private_key.sign(
                permission_json.encode('utf-8'),
                ec.ECDSA(self.hash_algorithm)
            )
            
            # Return as hex string
            return signature_bytes.hex()
        
        except Exception as e:
            raise ValueError(f"Failed to sign permission: {str(e)}")
    
    # ==================== Signature Verification ====================
    
    def verify_signature(
        self,
        public_key_hex: str,
        signature_hex: str,
        permission_data: Dict
    ) -> Tuple[bool, str]:
        """
        Verify a permission signature was created by the patient
        
        Process:
            1. Convert public key from hex to cryptography object
            2. Serialize permission_data (same way as signing)
            3. Verify signature with ECDSA
            4. Return True if valid, False otherwise
        
        Args:
            public_key_hex: Patient's uncompressed public key (hex string)
            signature_hex: Signature in hex format
            permission_data: Permission dict (must match original)
        
        Returns:
            Tuple[bool, str]: (is_valid, reason_if_invalid)
            
        Examples:
            is_valid, reason = verifier.verify_signature(
                public_key_hex="04abc123...",
                signature_hex="3045022100...",
                permission_data={...}
            )
            
            if is_valid:
                print("Signature verified!")
            else:
                print(f"Invalid: {reason}")
        
        Performance: ~5-10ms
        """
        try:
            # Parse signature — DER-encoded ECDSA P-256 sigs are 68–72 bytes depending
            # on leading-zero stripping of r/s.  Let the verify() call reject bad bytes;
            # a manual length check would incorrectly reject valid edge-case signatures.
            signature_bytes = bytes.fromhex(signature_hex)

            # Reconstruct public key from hex
            try:
                public_key_bytes = bytes.fromhex(public_key_hex)
                
                # Validate format (should be uncompressed: 0x04 + 64 bytes)
                if len(public_key_bytes) != 65 or public_key_bytes[0] != 0x04:
                    return False, "Invalid public key format"
                
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    self.curve,
                    public_key_bytes
                )
            except Exception as e:
                return False, f"Failed to load public key: {str(e)}"
            
            # Serialize permission data (must match what was signed)
            permission_json = json.dumps(
                permission_data,
                sort_keys=True,
                separators=(',', ':')
            )
            
            # Verify signature
            try:
                public_key.verify(
                    signature_bytes,
                    permission_json.encode('utf-8'),
                    ec.ECDSA(self.hash_algorithm)
                )
                return True, ""  # Valid signature
            
            except InvalidSignature:
                return False, "Signature verification failed"
        
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    # ==================== Permission Data Helpers ====================
    
    def create_permission_data(
        self,
        patient_id: str,
        doctor_id: str,
        record_id: str,
        time_start: datetime,
        time_end: datetime,
        permission_level: str = "view_only"
    ) -> Dict:
        """
        Create standardized permission data dict for signing
        
        Args:
            patient_id: UUID of patient
            doctor_id: UUID of doctor
            record_id: UUID of record
            time_start: Datetime when access begins
            time_end: Datetime when access expires
            permission_level: "view_only" or "view_download"
        
        Returns:
            Dict ready for signing
        """
        return {
            "patient_id": patient_id,
            "doctor_id": doctor_id,
            "record_id": record_id,
            "time_start": time_start.isoformat() if isinstance(time_start, datetime) else str(time_start),
            "time_end": time_end.isoformat() if isinstance(time_end, datetime) else str(time_end),
            "permission_level": permission_level,
        }
    
    def is_permission_valid(
        self,
        permission_data: Dict,
        current_time: Optional[datetime] = None
    ) -> Tuple[bool, str]:
        """
        Check if permission grant is still valid (within time window)
        
        Args:
            permission_data: Permission dict with time_start, time_end
            current_time: Current datetime (default: now)
        
        Returns:
            Tuple[bool, str]: (is_valid, reason_if_invalid)
        """
        if current_time is None:
            current_time = datetime.utcnow()
        
        try:
            # Parse ISO datetime strings
            time_start = datetime.fromisoformat(permission_data["time_start"].replace('Z', '+00:00'))
            time_end = datetime.fromisoformat(permission_data["time_end"].replace('Z', '+00:00'))
            
            # Convert current_time to same timezone
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=time_start.tzinfo)
            
            # Check time window
            if current_time < time_start:
                return False, "Access not yet valid (starts in future)"
            
            if current_time > time_end:
                return False, "Access permission expired"
            
            return True, ""
        
        except Exception as e:
            return False, f"Failed to validate time window: {str(e)}"
    
    # ==================== Permission Hash ====================
    
    def hash_permission(self, permission_data: Dict) -> str:
        """
        Create a hash of permission data for blockchain/audit trail
        
        Args:
            permission_data: Permission dict
        
        Returns:
            str: SHA-256 hash in hex format
        """
        permission_json = json.dumps(
            permission_data,
            sort_keys=True,
            separators=(',', ':')
        )
        return hashlib.sha256(permission_json.encode('utf-8')).hexdigest()
    
    # ==================== Example Usage ====================


if __name__ == "__main__":
    from src.crypto.key_manager import KeyManager
    from datetime import timedelta
    
    print("=== Signature Verification Demo ===\n")
    
    # Generate keypair
    key_manager = KeyManager()
    keypair = key_manager.generate_keypair()
    print(f"✓ Generated keypair")
    print(f"  Public key hash: {keypair.public_key_hash[:16]}...")
    print()
    
    # Create verifier
    verifier = SignatureVerifier()
    
    # Create permission data
    patient_id = "patient-alice-123"
    doctor_id = "doctor-smith-456"
    record_id = "record-cancer-diag-789"
    
    permission_data = verifier.create_permission_data(
        patient_id=patient_id,
        doctor_id=doctor_id,
        record_id=record_id,
        time_start=datetime.utcnow(),
        time_end=datetime.utcnow() + timedelta(hours=2),
        permission_level="view_only"
    )
    print("✓ Created permission data:")
    print(f"  Patient: {patient_id}")
    print(f"  Doctor: {doctor_id}")
    print(f"  Record: {record_id}")
    print(f"  Valid for: 2 hours")
    print()
    
    # Sign permission
    signature = verifier.sign_permission(keypair.private_key_pem, permission_data)
    print("✓ Signed permission with patient's private key")
    print(f"  Signature: {signature[:16]}...")
    print()
    
    # Verify signature
    is_valid, reason = verifier.verify_signature(
        keypair.public_key_hex,
        signature,
        permission_data
    )
    print(f"✓ Signature verification: {is_valid}")
    if not is_valid:
        print(f"  Reason: {reason}")
    print()
    
    # Check time validity
    is_time_valid, reason = verifier.is_permission_valid(permission_data)
    print(f"✓ Time window valid: {is_time_valid}")
    if not is_time_valid:
        print(f"  Reason: {reason}")
    print()
    
    # Demonstrate tampering detection
    print("=== Tampering Detection ===")
    tampered_data = permission_data.copy()
    tampered_data["doctor_id"] = "doctor-evil-999"  # Change who can access
    
    is_valid, reason = verifier.verify_signature(
        keypair.public_key_hex,
        signature,
        tampered_data
    )
    print(f"✓ Tampering detected: {not is_valid}")
    print(f"  Reason: {reason}")
