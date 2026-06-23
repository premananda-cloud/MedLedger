"""
database/ — Data access layer for MedLedger.

Layer contract:
  ✓ Pure data operations — reads and writes only
  ✓ Receives AsyncSession in __init__, owns nothing else
  ✓ Raises only exceptions defined in database/exceptions.py
  ✗ No business logic
  ✗ No validation
  ✗ No auth decisions
  ✗ No imports from auth/ or services/

from database import DatabaseRepository
from database.exceptions import (
    DatabaseError,
    RecordNotFoundError,
    DuplicateError,
    IntegrityError,
)
"""

from .repository import DatabaseRepository
from .exceptions import (
    DatabaseError,
    RecordNotFoundError,
    DuplicateError,
    IntegrityError,
)

__all__ = [
    "DatabaseRepository",
    "DatabaseError",
    "RecordNotFoundError",
    "DuplicateError",
    "IntegrityError",
]
