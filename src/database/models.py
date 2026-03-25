"""
Database Models - SQLAlchemy ORM definitions
Location: src/database/models.py

Defines:
- User model (stores public key, password hash, metadata)
- AuditLog model (immutable event tracking)
- MedicalRecordBlock model (on-chain metadata)
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, Text, Enum, Index, UniqueConstraint, event,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
import enum

# NOTE: engine/DATABASE_URL live exclusively in src/database/connection.py.
# Do NOT import or re-create them here — that caused the duplicate-Base bug.
Base = declarative_base()


class UserRole(str, enum.Enum):
    """User role enumeration"""
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    ADMIN = "ADMIN"


class AuditAction(str, enum.Enum):
    """Audit log action types"""
    USER_REGISTERED = "USER_REGISTERED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    RECORD_CREATED = "RECORD_CREATED"
    RECORD_ACCESSED = "RECORD_ACCESSED"
    PERMISSION_GRANTED = "PERMISSION_GRANTED"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"


class User(Base):
    """
    User model - Stores authentication and key information
    
    Security Design:
    - public_key_hash: Unique identifier for public key (SHA256)
    - public_key_hex: Full public key for cryptographic operations
    - password_hash: Password hashed with PBKDF2 (NOT for key encryption)
    - private_key_NEVER_stored: See comment below
    - key_salt/key_iv: For optional password-protected backup recovery
    """
    
    __tablename__ = "users"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True)
    
    # User Identification
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255))
    
    # Role-Based Access Control
    role = Column(Enum(UserRole), nullable=False, index=True, default=UserRole.PATIENT)
    
    # Cryptographic Keys
    # NOTE: Private key is NEVER stored in database!
    # It's generated once, given to user, and never touches the server again.
    public_key_hex = Column(String(130), nullable=False)
    public_key_compressed = Column(String(66), nullable=False)
    public_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    
    # Authentication (separate from private key system)
    password_hash = Column(String(255), nullable=False)
    
    # Optional: Key Recovery (if user wants password-protected backup)
    # These allow recovery of the private key IF the user saved an encrypted backup
    key_salt = Column(String(64))           # PBKDF2 salt (hex)
    key_iv = Column(String(32))             # AES-GCM IV (hex)
    encrypted_private_key_backup = Column(Text)  # AES-256-GCM encrypted private key (hex)
    key_backup_auth_tag = Column(String(32))     # Authentication tag (hex)
    has_encrypted_backup = Column(Boolean, default=False)
    
    # Account Status
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)  # Email verified
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user", foreign_keys="[AuditLog.user_id]")
    medical_records = relationship("MedicalRecordBlock", back_populates="patient", foreign_keys="MedicalRecordBlock.patient_id")
    provider_records = relationship("MedicalRecordBlock", back_populates="provider", foreign_keys="MedicalRecordBlock.provider_id")
    
    # Constraints
    __table_args__ = (
        Index('idx_email_active', 'email', 'is_active'),
        Index('idx_role_active', 'role', 'is_active'),
        UniqueConstraint('public_key_hash', name='uq_public_key_hash'),
    )
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"


class AuditLog(Base):
    """
    Audit Log model - Immutable event logging for compliance
    
    Design:
    - Tracks all significant events (login, access, modifications)
    - Hash chain (each event references previous) prevents tampering
    - Eventually moved to blockchain for immutability
    - Used for forensic analysis and compliance reporting
    """
    
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Event Reference
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action = Column(Enum(AuditAction), nullable=False, index=True)
    
    # Optional Resource Reference
    record_id = Column(String(64), index=True)  # Medical record ID if applicable
    related_user_id = Column(Integer, ForeignKey("users.id"))  # Target user for permission grants
    
    # Event Details
    description = Column(Text)
    extra_data = Column(Text)  # JSON string with additional context
    
    # Cryptographic Hash Chain
    event_hash = Column(String(64), unique=True, index=True)  # SHA256(event_data)
    previous_event_hash = Column(String(64), index=True)      # Forensic chain
    
    # Request Context (for forensic analysis)
    request_ip = Column(String(50))
    user_agent = Column(String(500))
    
    # Blockchain Reference (Phase 2)
    blockchain_block_hash = Column(String(64), index=True)    # When committed to chain
    is_on_chain = Column(Boolean, default=False, index=True)
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs", foreign_keys="[AuditLog.user_id]")
    
    __table_args__ = (
        Index('idx_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_action_timestamp', 'action', 'timestamp'),
        Index('idx_record_timestamp', 'record_id', 'timestamp'),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, user_id={self.user_id}, action={self.action}, timestamp={self.timestamp})>"


# ── AuditLog immutability guard ───────────────────────────────────────────────
# These SQLAlchemy ORM events fire BEFORE any UPDATE or DELETE reaches the DB.
# They raise immediately, so no audit row can ever be mutated through the ORM.
# A raw SQL DELETE/UPDATE against the DB still requires DB-level controls
# (e.g. a PostgreSQL row-security policy or a dedicated audit DB role with
# INSERT-only privileges), which should be added before production deployment.

@event.listens_for(AuditLog, "before_update")
def _block_audit_update(mapper, connection, target):
    raise RuntimeError(
        "AuditLog rows are immutable — UPDATE is not permitted. "
        f"Attempted on id={target.id}"
    )


@event.listens_for(AuditLog, "before_delete")
def _block_audit_delete(mapper, connection, target):
    raise RuntimeError(
        "AuditLog rows are immutable — DELETE is not permitted. "
        f"Attempted on id={target.id}"
    )


class MedicalRecordBlock(Base):
    """
    Medical Record Metadata Block - Stores on-chain metadata about medical records
    
    Design:
    - Encrypted records stored off-chain (IPFS, local storage)
    - Only metadata and hashes stored on-chain
    - DEK (Data Encryption Key) encrypted with patient's public key
    - Patient can decrypt their data with their private key
    - Access control metadata stored for permission checks
    
    Flow:
    1. Doctor encrypts medical record with AES-256-GCM
    2. Doctor encrypts DEK (Data Encryption Key) with patient's public key
    3. Doctor creates MedicalRecordBlock with:
       - contentHash: SHA256 of plaintext record (proves integrity)
       - encrypted_dek: DEK encrypted with patient's public key (patient-centric)
       - storage_location: Where encrypted record is stored
    4. Block submitted to blockchain for immutability
    5. Patient can retrieve record only if they have private key
    """
    
    __tablename__ = "medical_record_blocks"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Record Identification
    record_id = Column(String(64), unique=True, nullable=False, index=True)  # SHA256 hash
    
    # Participants
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # Who created it
    
    # Content Integrity
    content_hash = Column(String(64), nullable=False, index=True)  # SHA256 of plaintext
    content_type = Column(String(100))  # MIME type (e.g., "application/pdf")
    
    # Encryption Details
    encryption_algorithm = Column(String(50), default="AES-256-GCM")
    dek_encryption_algorithm = Column(String(50), default="ECIES-P256")
    
    # Data Encryption Key (DEK) - encrypted with patient's public key
    encrypted_dek_hex = Column(Text, nullable=False)  # ECIES ciphertext
    dek_salt = Column(String(64))                      # For key derivation
    
    # Storage Location (Off-Chain)
    storage_protocol = Column(String(50))  # "IPFS", "LOCAL", "S3", etc.
    storage_cid = Column(String(255))      # IPFS content hash or path
    storage_key_id = Column(String(255))   # Reference to encryption key
    
    # Blockchain Reference (On-Chain Metadata)
    block_hash = Column(String(64), index=True)       # SHA256 of this block
    merkle_root = Column(String(64))                   # Merkle root of transaction batch
    consensus_round = Column(Integer)                  # PBFT consensus round
    validator_signatures = Column(Text)                # JSON array of validator signatures
    
    # Access Control
    access_policy_hash = Column(String(64))  # Hash of access policy
    
    # Status
    is_immutable = Column(Boolean, default=False, index=True)  # Committed to blockchain
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    patient = relationship("User", back_populates="medical_records", 
                          foreign_keys="[MedicalRecordBlock.patient_id]")
    provider = relationship("User", back_populates="provider_records", 
                           foreign_keys="[MedicalRecordBlock.provider_id]")
    
    __table_args__ = (
        Index('idx_patient_records', 'patient_id', 'created_at'),
        Index('idx_content_hash', 'content_hash'),
        UniqueConstraint('record_id', name='uq_record_id'),
    )
    
    def __repr__(self) -> str:
        return f"<MedicalRecordBlock(id={self.id}, record_id={self.record_id[:8]}, patient_id={self.patient_id})>"


class AccessPermission(Base):
    """
    Access Permission model - Stores granular access control policies
    
    Design (Phase 2):
    - Patient grants access to specific records
    - Time-slot based access (valid_from to valid_until)
    - Grantee public key identifies who can access
    - Patient signature proves authorization
    - Can include conditions (geographic, purpose, read-only)
    
    Each permission requires:
    1. Patient signature (proof they authorized it)
    2. Grantee public key hash (identifies who can access)
    3. Valid time window
    4. Specific record(s) or all records
    """
    
    __tablename__ = "access_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Permission Identification
    permission_id = Column(String(64), unique=True, nullable=False, index=True)
    
    # Participants
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    grantee_public_key_hash = Column(String(64), nullable=False, index=True)
    
    # Resource
    record_id = Column(String(64), index=True)  # Specific record, or NULL for all
    
    # Permissions
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)
    can_audit = Column(Boolean, default=False)
    can_delegate = Column(Boolean, default=False)
    
    # Time-Slot Based Access
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    
    # Conditions (extensible JSON)
    conditions = Column(Text)  # JSON: {geographic, purpose, etc.}
    
    # Doctor's DEK bundle (ECIES-wrapped DEK for the doctor's public key)
    # Populated by the frontend during grant: patient decrypts the record DEK
    # with their private key, then re-encrypts it with the doctor's public key.
    # Cleared on revocation so the doctor can no longer read the file.
    doctor_encrypted_dek = Column(Text, nullable=True)

    # Authorization Proof
    patient_signature = Column(Text, nullable=False)  # ECDSA signature from patient
    signature_timestamp = Column(DateTime)
    
    # Status
    is_active = Column(Boolean, default=True, index=True)
    is_revoked = Column(Boolean, default=False)
    revocation_reason = Column(String(255))
    
    # Blockchain Reference
    block_hash = Column(String(64), index=True)  # When committed to chain
    is_on_chain = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    revoked_at = Column(DateTime)
    
    __table_args__ = (
        Index('idx_patient_permissions', 'patient_id', 'is_active'),
        Index('idx_grantee_permissions', 'grantee_public_key_hash', 'is_active'),
        Index('idx_valid_window', 'valid_from', 'valid_until'),
    )


# ==================== Database Initialization ====================

def create_all_tables(engine):
    """Create all tables defined on Base. Called on startup and by database/__init__.py."""
    Base.metadata.create_all(bind=engine)


def drop_all_tables(engine):
    """Drop all tables from the database (use with caution!)"""
    Base.metadata.drop_all(bind=engine)