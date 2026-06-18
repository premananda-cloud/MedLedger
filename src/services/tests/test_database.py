# tests/test_database.py

import asyncio
import pytest
import hashlib
import secrets
import json
from unittest.mock import AsyncMock, MagicMock, patch, ANY
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

import asyncpg

# Import the module to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database import Database, get_db, close_db, _db_instance


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def db():
    """Create a Database instance with mocked pool"""
    database = Database()
    database.pool = AsyncMock(spec=asyncpg.Pool)
    return database


@pytest.fixture
def mock_connection():
    """Mock database connection"""
    conn = AsyncMock(spec=asyncpg.Connection)
    conn.transaction = MagicMock()
    conn.transaction.return_value.__aenter__ = AsyncMock()
    conn.transaction.return_value.__aexit__ = AsyncMock()
    return conn


@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        'user_id_hex': hashlib.sha256(b'test_signing_key').hexdigest(),
        'username': 'testuser',
        'email': 'test@example.com',
        'full_name': 'Test User',
        'role': 'PATIENT',
        'password_hash': 'hashed_password_123',
        'pwhash_salt': secrets.token_hex(32),
        'signing_public_key': 'test_signing_key',
        'exchange_public_key': 'test_exchange_key',
        'server_salt': secrets.token_hex(32),
        'is_verified': False,
        'is_active': True
    }


@pytest.fixture
def sample_user_row():
    """Sample user row as returned by database"""
    return {
        'user_id_hex': 'abc123def456',
        'username': 'testuser',
        'email': 'test@example.com',
        'full_name': 'Test User',
        'role': 'PATIENT',
        'password_hash': 'hashed_password_123',
        'pwhash_salt': 'salt_abc',
        'signing_public_key': 'test_signing_key',
        'exchange_public_key': 'test_exchange_key',
        'server_salt': 'server_salt_xyz',
        'is_verified': False,
        'is_active': True,
        'account_deleted': False,
        'created_at': datetime.utcnow(),
        'last_login_at': None
    }


# =============================================================
# INITIALIZATION TESTS
# =============================================================

class TestDatabaseInit:
    """Test Database initialization"""

    def test_init_builds_dsn(self):
        """Test that __init__ builds DSN"""
        db = Database()
        assert db.pool is None
        assert 'postgresql://' in db.dsn
        assert '@' in db.dsn

    @patch('database.os.getenv')
    def test_build_dsn_from_env(self, mock_getenv):
        """Test DSN construction from environment variables"""
        mock_getenv.side_effect = lambda key, default=None: {
            'DB_USER': 'testuser',
            'DB_PASSWORD': 'testpass',
            'DB_HOST': 'testhost',
            'DB_PORT': '5433',
            'DB_NAME': 'testdb'
        }.get(key, default)

        db = Database()
        expected_dsn = 'postgresql://testuser:testpass@testhost:5433/testdb'
        assert db.dsn == expected_dsn

    def test_build_dsn_with_defaults(self):
        """Test DSN with default values"""
        with patch('database.os.getenv', return_value=None):
            db = Database()
            assert 'premananda' in db.dsn
            assert 'localhost' in db.dsn
            assert '5432' in db.dsn
            assert 'medledger_db' in db.dsn


# =============================================================
# CONNECTION MANAGEMENT TESTS
# =============================================================

class TestConnectionManagement:
    """Test connection pool management"""

    @pytest.mark.asyncio
    @patch('database.asyncpg.create_pool')
    async def test_connect_creates_pool(self, mock_create_pool, db):
        """Test that connect creates a connection pool"""
        db.pool = None
        mock_pool = AsyncMock()
        mock_create_pool.return_value = mock_pool

        result = await db.connect()

        mock_create_pool.assert_called_once_with(
            dsn=db.dsn,
            min_size=5,
            max_size=20,
            command_timeout=60,
            max_inactive_connection_lifetime=300,
            init=asyncpg.Bytes
        )
        assert result == mock_pool
        assert db.pool == mock_pool

    @pytest.mark.asyncio
    async def test_connect_when_already_connected(self, db):
        """Test connect when pool already exists"""
        existing_pool = db.pool
        result = await db.connect()
        assert result == existing_pool

    @pytest.mark.asyncio
    async def test_close_pool(self, db):
        """Test closing the connection pool"""
        await db.close()
        db.pool.close.assert_called_once()
        assert db.pool is None

    @pytest.mark.asyncio
    async def test_close_when_no_pool(self):
        """Test close when pool doesn't exist"""
        db = Database()
        await db.close()  # Should not raise exception

    @pytest.mark.asyncio
    async def test_get_pool_connects_if_needed(self, db):
        """Test get_pool connects if pool is None"""
        db.pool = None

        with patch.object(db, 'connect', new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = AsyncMock()
            await db.get_pool()
            mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_pool_returns_existing_pool(self, db):
        """Test get_pool returns existing pool"""
        result = await db.get_pool()
        assert result == db.pool


# =============================================================
# USER OPERATIONS TESTS
# =============================================================

class TestUserOperations:
    """Test user-related database operations"""

    @pytest.mark.asyncio
    async def test_create_user(self, db, mock_connection, sample_user_data):
        """Test creating a new user"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection

        expected_row = {
            'user_id_hex': sample_user_data['user_id_hex'],
            'username': 'testuser',
            'email': 'test@example.com',
            'full_name': 'Test User',
            'role': 'PATIENT',
            'is_verified': False,
            'is_active': True,
            'created_at': datetime.utcnow()
        }
        mock_connection.fetchrow.return_value = expected_row

        result = await db.create_user(sample_user_data)

        assert result == expected_row
        mock_connection.fetchrow.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_generates_user_id(self, db, mock_connection):
        """Test that user_id_hex is generated from signing key"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection

        user_data = {
            'username': 'testuser',
            'signing_public_key': 'test_signing_key'
        }
        expected_id = hashlib.sha256(b'test_signing_key').hexdigest()

        mock_connection.fetchrow.return_value = {'user_id_hex': expected_id}

        result = await db.create_user(user_data)
        assert result['user_id_hex'] == expected_id

    @pytest.mark.asyncio
    async def test_get_user_by_username(self, db, mock_connection, sample_user_row):
        """Test getting user by username"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = sample_user_row

        result = await db.get_user_by_username('testuser')

        assert result == sample_user_row
        mock_connection.fetchrow.assert_called_once()
        # Verify case-insensitive query
        call_args = mock_connection.fetchrow.call_args[0][1]
        assert call_args == 'testuser'

    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, db, mock_connection):
        """Test getting non-existent user by username"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.get_user_by_username('nonexistent')

        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, db, mock_connection, sample_user_row):
        """Test getting user by email"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = sample_user_row

        result = await db.get_user_by_email('test@example.com')

        assert result == sample_user_row

    @pytest.mark.asyncio
    async def test_get_user_by_id(self, db, mock_connection, sample_user_row):
        """Test getting user by ID"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = sample_user_row

        result = await db.get_user_by_id('abc123def456')

        assert result == sample_user_row

    @pytest.mark.asyncio
    async def test_update_user(self, db, mock_connection):
        """Test updating user fields"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 1"

        updates = {'email': 'newemail@example.com', 'is_active': False}
        result = await db.update_user('abc123', updates)

        assert result is True
        mock_connection.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_no_valid_fields(self, db, mock_connection):
        """Test update with no valid fields"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection

        result = await db.update_user('abc123', {'invalid_field': 'value'})

        assert result is False
        mock_connection.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_user_no_rows_affected(self, db, mock_connection):
        """Test update when no rows affected"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 0"

        result = await db.update_user('abc123', {'email': 'new@email.com'})

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_user(self, db, mock_connection):
        """Test soft deleting a user"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 1"

        result = await db.delete_user('abc123')

        assert result is True
        mock_connection.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_username_exists(self, db, mock_connection):
        """Test checking if username exists"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {'?column?': 1}

        result = await db.username_exists('testuser')

        assert result is True

    @pytest.mark.asyncio
    async def test_username_not_exists(self, db, mock_connection):
        """Test checking if username doesn't exist"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.username_exists('nonexistent')

        assert result is False

    @pytest.mark.asyncio
    async def test_email_exists(self, db, mock_connection):
        """Test checking if email exists"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {'?column?': 1}

        result = await db.email_exists('test@example.com')

        assert result is True


# =============================================================
# VAULT OPERATIONS TESTS
# =============================================================

class TestVaultOperations:
    """Test vault-related database operations"""

    @pytest.fixture
    def sample_vault_record(self):
        return {
            'record_id': 'rec123',
            'owner_key_hash': 'key_hash_abc',
            'owner_user_id_hex': 'user123',
            'owner_public_key_hex': 'pub_key_xyz',
            'filename': 'test_file.pdf',
            'mime_type': 'application/pdf',
            'size_bytes': 1024,
            'iv_hex': 'iv_abc123',
            'tags': ['medical', 'confidential']
        }

    @pytest.mark.asyncio
    async def test_create_vault_record(self, db, mock_connection, sample_vault_record):
        """Test creating a vault record"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        expected_row = {
            'record_id': 'rec123',
            'owner_key_hash': 'key_hash_abc',
            'owner_user_id_hex': 'user123',
            'filename': 'test_file.pdf',
            'mime_type': 'application/pdf',
            'size_bytes': 1024,
            'created_at': datetime.utcnow()
        }
        mock_connection.fetchrow.return_value = expected_row

        result = await db.create_vault_record(sample_vault_record)

        assert result == expected_row

    @pytest.mark.asyncio
    async def test_get_vault_records_by_user(self, db, mock_connection):
        """Test getting vault records by user"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_records = [
            {'record_id': 'rec1', 'filename': 'file1.pdf'},
            {'record_id': 'rec2', 'filename': 'file2.pdf'}
        ]
        mock_connection.fetch.return_value = mock_records

        result = await db.get_vault_records_by_user('user123')

        assert len(result) == 2
        assert result[0]['record_id'] == 'rec1'

    @pytest.mark.asyncio
    async def test_get_vault_record(self, db, mock_connection):
        """Test getting a specific vault record"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'record_id': 'rec123',
            'filename': 'test_file.pdf'
        }

        result = await db.get_vault_record('rec123')

        assert result is not None
        assert result['record_id'] == 'rec123'

    @pytest.mark.asyncio
    async def test_get_vault_record_not_found(self, db, mock_connection):
        """Test getting non-existent vault record"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.get_vault_record('nonexistent')

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_vault_record(self, db, mock_connection):
        """Test deleting a vault record"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "DELETE 1"

        result = await db.delete_vault_record('rec123')

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_vault_record_not_found(self, db, mock_connection):
        """Test deleting non-existent vault record"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "DELETE 0"

        result = await db.delete_vault_record('nonexistent')

        assert result is False


# =============================================================
# CIPHERTEXT OPERATIONS TESTS
# =============================================================

class TestCiphertextOperations:
    """Test ciphertext-related operations"""

    @pytest.mark.asyncio
    async def test_store_ciphertext(self, db, mock_connection):
        """Test storing ciphertext"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection

        result = await db.store_ciphertext(
            'rec123',
            b'encrypted_data',
            {'key': 'dek_value'}
        )

        assert result is True
        mock_connection.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ciphertext(self, db, mock_connection):
        """Test getting ciphertext"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'ciphertext': memoryview(b'encrypted_data'),
            'dek_bundle': json.dumps({'key': 'dek_value'})
        }

        result = await db.get_ciphertext('rec123')

        assert result is not None
        assert result['ciphertext'] == b'encrypted_data'
        assert result['dek_bundle'] == {'key': 'dek_value'}

    @pytest.mark.asyncio
    async def test_get_ciphertext_not_found(self, db, mock_connection):
        """Test getting non-existent ciphertext"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.get_ciphertext('nonexistent')

        assert result is None


# =============================================================
# SHARES OPERATIONS TESTS
# =============================================================

class TestSharesOperations:
    """Test shares-related operations"""

    @pytest.fixture
    def sample_share_data(self):
        return {
            'share_id': 'share123',
            'short_code': 'ABC123',
            'owner_user_id_hex': 'owner123',
            'grantee_user_id_hex': 'grantee456',
            'ciphertext': b'encrypted_share',
            'dek_bundle': json.dumps({'key': 'dek'}),
            'nonce': 'nonce123',
            'filename': 'shared_file.pdf',
            'mime_type': 'application/pdf',
            'size_bytes': 2048,
            'file_hash': 'hash_abc',
            'signature': 'sig_xyz',
            'payload_canon': 'canon_data',
            'expires_at': datetime.utcnow() + timedelta(days=7),
            'delete_on_download': True
        }

    @pytest.mark.asyncio
    async def test_create_share(self, db, mock_connection, sample_share_data):
        """Test creating a share"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'share_id': 'share123',
            'short_code': 'ABC123',
            'filename': 'shared_file.pdf',
            'created_at': datetime.utcnow(),
            'expires_at': sample_share_data['expires_at']
        }

        result = await db.create_share(sample_share_data)

        assert result is not None
        assert result['share_id'] == 'share123'

    @pytest.mark.asyncio
    async def test_get_share_by_id(self, db, mock_connection):
        """Test getting share by ID"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'share_id': 'share123',
            'filename': 'shared_file.pdf'
        }

        result = await db.get_share_by_id('share123')

        assert result is not None
        assert result['share_id'] == 'share123'

    @pytest.mark.asyncio
    async def test_get_share_by_code(self, db, mock_connection):
        """Test getting share by short code"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'share_id': 'share123',
            'short_code': 'ABC123'
        }

        result = await db.get_share_by_code('ABC123')

        assert result is not None
        assert result['short_code'] == 'ABC123'

    @pytest.mark.asyncio
    async def test_get_shares_by_owner(self, db, mock_connection):
        """Test getting shares by owner"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_shares = [
            {'share_id': 'share1', 'filename': 'file1.pdf'},
            {'share_id': 'share2', 'filename': 'file2.pdf'}
        ]
        mock_connection.fetch.return_value = mock_shares

        result = await db.get_shares_by_owner('owner123')

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_shares_by_owner_with_status(self, db, mock_connection):
        """Test getting shares by owner with status filter"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetch.return_value = []

        result = await db.get_shares_by_owner('owner123', status='active')

        assert result == []

    @pytest.mark.asyncio
    async def test_get_shares_by_grantee(self, db, mock_connection):
        """Test getting shares by grantee"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetch.return_value = []

        result = await db.get_shares_by_grantee('grantee456')

        assert result == []

    @pytest.mark.asyncio
    async def test_mark_share_retrieved(self, db, mock_connection):
        """Test marking share as retrieved"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 1"

        result = await db.mark_share_retrieved('share123')

        assert result is True

    @pytest.mark.asyncio
    async def test_mark_share_retrieved_no_update(self, db, mock_connection):
        """Test marking already retrieved share"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 0"

        result = await db.mark_share_retrieved('share123')

        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_share(self, db, mock_connection):
        """Test revoking a share"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 1"

        result = await db.revoke_share('share123')

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_share(self, db, mock_connection):
        """Test hard deleting a share"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "DELETE 1"

        result = await db.delete_share('share123')

        assert result is True


# =============================================================
# GRANTS OPERATIONS TESTS
# =============================================================

class TestGrantsOperations:
    """Test grants-related operations"""

    @pytest.fixture
    def sample_grant_data(self):
        return {
            'grant_id': 'grant123',
            'record_id': 'rec123',
            'grantor_key_hash': 'grantor_hash',
            'grantee_key_hash': 'grantee_hash',
            'grantee_user_id_hex': 'user456',
            'grantee_public_key_hex': 'pub_key_456',
            'permission_level': 'read',
            'time_start': datetime.utcnow(),
            'time_end': datetime.utcnow() + timedelta(days=30),
            'dek_bundle_grantee': {'key': 'dek_value'},
            'signature_hex': 'sig_abc123'
        }

    @pytest.mark.asyncio
    async def test_create_grant(self, db, mock_connection, sample_grant_data):
        """Test creating a grant"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'grant_id': 'grant123',
            'record_id': 'rec123',
            'permission_level': 'read',
            'time_start': sample_grant_data['time_start'],
            'time_end': sample_grant_data['time_end']
        }

        result = await db.create_grant(sample_grant_data)

        assert result is not None
        assert result['grant_id'] == 'grant123'

    @pytest.mark.asyncio
    async def test_get_grants_for_record(self, db, mock_connection):
        """Test getting grants for a record"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_grants = [
            {'grant_id': 'grant1', 'permission_level': 'read'},
            {'grant_id': 'grant2', 'permission_level': 'write'}
        ]
        mock_connection.fetch.return_value = mock_grants

        result = await db.get_grants_for_record('rec123')

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_revoke_grant(self, db, mock_connection):
        """Test revoking a grant"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 1"

        result = await db.revoke_grant('grant123')

        assert result is True

    @pytest.mark.asyncio
    async def test_revoke_grant_not_found(self, db, mock_connection):
        """Test revoking non-existent grant"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 0"

        result = await db.revoke_grant('nonexistent')

        assert result is False


# =============================================================
# AUDIT LOGGING TESTS
# =============================================================

class TestAuditLogging:
    """Test audit logging operations"""

    @pytest.mark.asyncio
    async def test_log_audit(self, db, mock_connection):
        """Test logging an audit event"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {'id': 1}

        audit_data = {
            'actor_user_id_hex': 'user123',
            'action': 'LOGIN',
            'share_id': None,
            'detail': {'ip': '127.0.0.1'},
            'ip_address': '127.0.0.1',
            'user_agent': 'test-agent'
        }

        result = await db.log_audit(audit_data)

        assert result == 1

    @pytest.mark.asyncio
    async def test_get_audit_logs_by_user(self, db, mock_connection):
        """Test getting audit logs for a user"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_logs = [
            {'event_id': 'evt1', 'action': 'LOGIN'},
            {'event_id': 'evt2', 'action': 'LOGOUT'}
        ]
        mock_connection.fetch.return_value = mock_logs

        result = await db.get_audit_logs_by_user('user123')

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_audit_logs_by_user_with_limit(self, db, mock_connection):
        """Test getting audit logs with custom limit"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetch.return_value = []

        result = await db.get_audit_logs_by_user('user123', limit=50)

        assert result == []


# =============================================================
# RATE LIMITING TESTS
# =============================================================

class TestRateLimiting:
    """Test rate limiting operations"""

    @pytest.mark.asyncio
    async def test_record_attempt(self, db, mock_connection):
        """Test recording a rate limit attempt"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'attempts': 1,
            'first_attempt': datetime.utcnow(),
            'last_attempt': datetime.utcnow(),
            'blocked_until': None
        }

        result = await db.record_attempt('key_hash_123', 'login')

        assert result is not None
        assert result['attempts'] == 1

    @pytest.mark.asyncio
    async def test_block_rate_limit(self, db, mock_connection):
        """Test blocking a rate-limited key"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection

        await db.block_rate_limit('key_hash_123', 'login', duration_minutes=30)

        mock_connection.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_rate_limit_status(self, db, mock_connection):
        """Test getting rate limit status"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'attempts': 5,
            'first_attempt': datetime.utcnow(),
            'last_attempt': datetime.utcnow(),
            'blocked_until': datetime.utcnow() + timedelta(minutes=15)
        }

        result = await db.get_rate_limit_status('key_hash_123', 'login')

        assert result is not None
        assert result['attempts'] == 5

    @pytest.mark.asyncio
    async def test_get_rate_limit_status_not_found(self, db, mock_connection):
        """Test getting rate limit status for non-existent key"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.get_rate_limit_status('nonexistent', 'login')

        assert result is None


# =============================================================
# TOKEN REVOCATION TESTS
# =============================================================

class TestTokenRevocation:
    """Test token revocation operations"""

    @pytest.mark.asyncio
    async def test_revoke_token(self, db, mock_connection):
        """Test revoking a JWT token"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        expires_at = datetime.utcnow() + timedelta(hours=1)

        await db.revoke_token('token_jti_123', 'user123', expires_at)

        mock_connection.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_token_revoked_true(self, db, mock_connection):
        """Test checking if token is revoked (true)"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {'?column?': 1}

        result = await db.is_token_revoked('token_jti_123')

        assert result is True

    @pytest.mark.asyncio
    async def test_is_token_revoked_false(self, db, mock_connection):
        """Test checking if token is revoked (false)"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.is_token_revoked('token_jti_123')

        assert result is False


# =============================================================
# POW CHALLENGES TESTS
# =============================================================

class TestPowChallenges:
    """Test Proof of Work challenges operations"""

    @pytest.mark.asyncio
    async def test_create_pow_challenge(self, db, mock_connection):
        """Test creating a PoW challenge"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'challenge_id': 'challenge123',
            'difficulty': 4,
            'expires_at': datetime.utcnow() + timedelta(minutes=5)
        }

        challenge_data = {
            'challenge_id': 'challenge123',
            'nonce_prefix': 'abc',
            'difficulty': 4,
            'target_hash': '0000abc'
        }

        result = await db.create_pow_challenge(challenge_data)

        assert result is not None
        assert result['challenge_id'] == 'challenge123'

    @pytest.mark.asyncio
    async def test_get_pow_challenge(self, db, mock_connection):
        """Test getting a PoW challenge"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = {
            'challenge_id': 'challenge123',
            'nonce_prefix': 'abc',
            'difficulty': 4,
            'target_hash': '0000abc',
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=5),
            'solved_at': None
        }

        result = await db.get_pow_challenge('challenge123')

        assert result is not None
        assert result['challenge_id'] == 'challenge123'

    @pytest.mark.asyncio
    async def test_get_pow_challenge_expired(self, db, mock_connection):
        """Test getting expired PoW challenge"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.fetchrow.return_value = None

        result = await db.get_pow_challenge('expired_challenge')

        assert result is None

    @pytest.mark.asyncio
    async def test_mark_pow_solved(self, db, mock_connection):
        """Test marking PoW challenge as solved"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 1"

        result = await db.mark_pow_solved('challenge123', 'nonce_solution', '127.0.0.1')

        assert result is True

    @pytest.mark.asyncio
    async def test_mark_pow_solved_not_found(self, db, mock_connection):
        """Test marking non-existent PoW challenge as solved"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_connection.execute.return_value = "UPDATE 0"

        result = await db.mark_pow_solved('nonexistent', 'nonce_solution', '127.0.0.1')

        assert result is False


# =============================================================
# REFRESH TOKENS TESTS
# =============================================================

class TestRefreshTokens:
    """Test refresh token operations"""

    @pytest.mark.asyncio
    async def test_store_refresh_token(self, db, mock_connection):
        """Test storing a refresh token"""
        db.pool.acquire.return_value.__aenter__.return_value = mock_connection
        expires_at = datetime.utcnow() + timedelta(days=7)

        result = await db.store_refresh_token(
            'token_hash_123', 'user123', 'family_abc', expires_at
        )

        assert result is True
        mock_connection.execute.assert_c
