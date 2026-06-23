"""
database/exceptions.py — Custom exceptions for the database layer.

All repository methods raise these instead of leaking SQLAlchemy
internals or raw psycopg errors to the caller.
"""


class DatabaseError(Exception):
    """Base exception for all database layer errors."""


class RecordNotFoundError(DatabaseError):
    """
    Raised when an update/delete targets a row that does not exist.
    Get methods return None instead of raising this.
    """


class DuplicateError(DatabaseError):
    """
    Raised when a unique constraint is violated.
    Includes a 'field' attribute indicating which field conflicted.
    """
    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field   # e.g. "email", "username", "token_hash"


class IntegrityError(DatabaseError):
    """
    Raised for any other database integrity violation
    (foreign key, check constraint, etc.) not covered by DuplicateError.
    """
