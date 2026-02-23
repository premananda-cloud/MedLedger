"""
Database Connection Module
Location: src/database/connection.py

Supports both SQLite (testing) and PostgreSQL (production).
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

# Get database URL from environment, default to SQLite for local dev/testing
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./medledger.db")

# SQLite doesn't support pool_size/max_overflow - handle both backends
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},  # Required for SQLite + FastAPI
        echo=False
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        echo=False
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency - yields a DB session, closes on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables. Call on app startup."""
    from src.database.models import Base
    Base.metadata.create_all(bind=engine)


def drop_db():
    """Drop all tables. Only for dev/testing."""
    from src.database.models import Base
    Base.metadata.drop_all(bind=engine)


def check_db_connection() -> bool:
    """Returns True if DB is reachable."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False
