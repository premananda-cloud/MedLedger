"""
Registration Service  (rewritten)
Location: src/services/registration.py

What changed from the old version
──────────────────────────────────
OLD: expected the client to supply public_key_hex / public_key_compressed /
     public_key_hash in the request body (full SSI production model).

NEW: takes only  email + password + optional metadata.
     The server calls KeyManager.generate_keypair() automatically.
     The private_key_pem is returned ONCE in RegisterResult and never
     stored anywhere — the caller must save it immediately.

     Controlled by config.json → "crypto" → "keygen_on_server": true
     (dev/test default).  Flip to false for the production SSI path where
     the client generates and supplies public keys.

Key format contract (matches the established crypto layer)
──────────────────────────────────────────────────────────
  KeyPair.public_key_hex        → uncompressed, 65 bytes hex, "04…"
                                  → what ecies_encrypt() and verify_signature() expect
  KeyPair.public_key_hash       → SHA-256 of the raw 65-byte key bytes, hex
                                  → DB lookup key / identity anchor
  KeyPair.public_key_compressed → 33 bytes hex, "02/03…"
                                  → stored for display; not used in crypto ops
  KeyPair.private_key_pem       → PEM string, returned to caller, NEVER stored

Password hashing
────────────────
  PBKDF2-HMAC-SHA256, 100 000 iterations, random 32-byte salt.
  Stored as:  sha256$<iterations>$<salt_hex>$<hash_hex>
  Verified with hmac.compare_digest (constant-time).
"""

import logging
import os
import hmac as hmac_lib
from datetime import datetime, timedelta
from typing import Optional

import jwt  # PyJWT

from src.config import cfg
from src.database.store import get_store
from src.crypto.key_manager import KeyManager

logger = logging.getLogger(__name__)

_key_manager = KeyManager()   # stateless — safe to share


# ── Exceptions ────────────────────────────────────────────────────────────────

class RegistrationError(Exception):
    pass

class UserAlreadyExistsError(RegistrationError):
    pass

class AuthenticationError(RegistrationError):
    pass


# ── Result objects ────────────────────────────────────────────────────────────

class RegisterResult:
    __slots__ = [
        "user_id", "email", "username", "full_name", "role",
        "public_key_hex", "public_key_compressed", "public_key_hash",
        "private_key_pem",   # returned ONCE — caller must save immediately
        "access_token",
        "created_at",
    ]
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}


class LoginResult:
    __slots__ = [
        "user_id", "email", "username", "full_name", "role",
        "public_key_hash", "public_key_compressed",
        "access_token", "last_login",
    ]
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}


# ── Service ───────────────────────────────────────────────────────────────────

class RegistrationService:
    """
    Handles user registration and login.
    Storage backend is determined by config.json — no DB driver imported here.
    """

    def __init__(self):
        self.store = get_store()

    # ══════════════════════════════════════════════════════════════════════════
    # REGISTER
    # ══════════════════════════════════════════════════════════════════════════

    def register(
        self,
        email: str,
        password: str,
        username: str,
        full_name: str = "",
        role: str = "PATIENT",
        # --- production SSI path (only used when keygen_on_server = false) ---
        public_key_hex: Optional[str] = None,
        public_key_compressed: Optional[str] = None,
        public_key_hash: Optional[str] = None,
    ) -> RegisterResult:
        """
        Register a new user.

        Dev/test  (keygen_on_server=true):  pass email, password, username.
                                            Server generates the keypair.
        Production (keygen_on_server=false): client must also supply
                                            public_key_hex, public_key_compressed,
                                            public_key_hash.

        Returns RegisterResult — private_key_pem is in it; save it now.
        Raises UserAlreadyExistsError or RegistrationError.
        """
        email    = email.strip().lower()
        username = username.strip()

        # ── Validation ────────────────────────────────────────────────────────
        if not email or "@" not in email:
            raise RegistrationError("Invalid email address")
        if not password or len(password) < 8:
            raise RegistrationError("Password must be at least 8 characters")
        if not username or len(username) < 3:
            raise RegistrationError("Username must be at least 3 characters")

        # ── Keypair ───────────────────────────────────────────────────────────
        if cfg.keygen_on_server:
            keypair        = _key_manager.generate_keypair()
            priv_pem       = keypair.private_key_pem
            pub_hex        = keypair.public_key_hex          # "04…" uncompressed, 130 hex chars
            pub_compressed = keypair.public_key_compressed   # "02/03…", 66 hex chars
            pub_hash       = keypair.public_key_hash         # SHA-256 of raw key bytes, 64 hex chars
        else:
            if not (public_key_hex and public_key_compressed and public_key_hash):
                raise RegistrationError(
                    "keygen_on_server is false — supply public_key_hex, "
                    "public_key_compressed, and public_key_hash"
                )
            if not public_key_hex.startswith("04") or len(public_key_hex) != 130:
                raise RegistrationError(
                    "public_key_hex must be an uncompressed P-256 key: "
                    "65 bytes hex-encoded starting with '04' (130 chars total)"
                )
            priv_pem       = "client-managed"
            pub_hex        = public_key_hex
            pub_compressed = public_key_compressed
            pub_hash       = public_key_hash

        # ── Hash password ─────────────────────────────────────────────────────
        pw_hash = _hash_password(password)

        # ── Persist ───────────────────────────────────────────────────────────
        try:
            user = self.store.create_user(
                email=email,
                username=username,
                full_name=full_name or username,
                role=role.upper(),
                password_hash=pw_hash,
                public_key_hex=pub_hex,
                public_key_compressed=pub_compressed,
                public_key_hash=pub_hash,
            )
        except ValueError as e:
            raise UserAlreadyExistsError(str(e))
        except Exception as e:
            raise RegistrationError(f"Storage error: {e}")

        self.store.append_audit(
            user_id=user["id"],
            action="USER_REGISTERED",
            description=f"User '{username}' registered as {role.upper()}",
        )

        token = _issue_jwt(user["id"], email)
        logger.info("Registered user id=%s email=%s role=%s", user["id"], email, role)

        return RegisterResult(
            user_id=user["id"],
            email=email,
            username=username,
            full_name=user["full_name"],
            role=user["role"],
            public_key_hex=pub_hex,
            public_key_compressed=pub_compressed,
            public_key_hash=pub_hash,
            private_key_pem=priv_pem,
            access_token=token,
            created_at=user["created_at"],
        )

    # ══════════════════════════════════════════════════════════════════════════
    # LOGIN
    # ══════════════════════════════════════════════════════════════════════════

    def login(self, email: str, password: str) -> LoginResult:
        """
        Authenticate with email + password.
        Returns LoginResult with JWT and the user's public key material.
        Raises AuthenticationError on bad credentials or inactive account.
        """
        email = email.strip().lower()
        user  = self.store.get_by_email(email)

        # Same error for "not found" and "wrong password" — don't leak email list
        if not user:
            self._log_failed(email, "user not found")
            raise AuthenticationError("Invalid email or password")

        if not user.get("is_active", True):
            self._log_failed(email, "account disabled")
            raise AuthenticationError("Account is disabled")

        if not _verify_password(password, user["password_hash"]):
            self._log_failed(email, "wrong password")
            raise AuthenticationError("Invalid email or password")

        self.store.touch_last_login(user["id"])
        self.store.append_audit(
            user_id=user["id"],
            action="LOGIN_SUCCESS",
            description=f"Login: {email}",
        )
        token = _issue_jwt(user["id"], email)
        logger.info("Login ok user id=%s", user["id"])

        return LoginResult(
            user_id=user["id"],
            email=email,
            username=user["username"],
            full_name=user["full_name"],
            role=user["role"],
            public_key_hash=user["public_key_hash"],
            public_key_compressed=user["public_key_compressed"],
            access_token=token,
            last_login=user.get("last_login"),
        )

    # ══════════════════════════════════════════════════════════════════════════
    # JWT VERIFICATION  (used by auth middleware / route deps)
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def verify_token(token: str) -> dict:
        """Decode and verify a JWT.  Returns payload dict.
           Raises AuthenticationError on any failure."""
        try:
            return jwt.decode(token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm])
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC KEY LOOKUPS  (used by other services / crypto modules)
    # ══════════════════════════════════════════════════════════════════════════

    def get_public_key_hex(self, email: str) -> str:
        """
        Return uncompressed public_key_hex for a user by email.
        This is the string ecies_encrypt() and verify_signature() expect.
        Raises RegistrationError if not found.
        """
        user = self.store.get_by_email(email)
        if not user:
            raise RegistrationError(f"User not found: {email}")
        return user["public_key_hex"]

    def get_public_key_hex_by_hash(self, public_key_hash: str) -> str:
        """
        Return uncompressed public_key_hex looked up by its SHA-256 hash.
        Used by permission / record services that store the hash as identity.
        Raises RegistrationError if not found.
        """
        user = self.store.get_by_public_key_hash(public_key_hash)
        if not user:
            raise RegistrationError(f"No user for public_key_hash: {public_key_hash}")
        return user["public_key_hex"]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _log_failed(self, email: str, reason: str):
        self.store.append_audit(
            user_id=0,   # sentinel for anonymous / unauthenticated events
            action="LOGIN_FAILED",
            description=f"Failed login for {email}: {reason}",
        )


# ── Password helpers ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256, 100 000 iterations, 32-byte random salt.
    Format:  sha256$<iterations>$<salt_hex>$<hash_hex>"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    iterations = 100_000
    salt       = os.urandom(32)
    kdf        = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=iterations, backend=default_backend(),
    )
    h = kdf.derive(password.encode("utf-8"))
    return f"sha256${iterations}${salt.hex()}${h.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Constant-time PBKDF2 verification."""
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != "sha256":
            return False
        _, iterations, salt_hex, hash_hex = parts
        salt        = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=salt, iterations=int(iterations), backend=default_backend(),
        )
        computed = kdf.derive(password.encode("utf-8"))
        return hmac_lib.compare_digest(computed, stored_hash)
    except Exception:
        return False


def _issue_jwt(user_id: int, email: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub":   str(user_id),
        "email": email,
        "iat":   now,
        "exp":   now + timedelta(hours=cfg.jwt_expiration_hours),
    }
    return jwt.encode(payload, cfg.jwt_secret, algorithm=cfg.jwt_algorithm)
