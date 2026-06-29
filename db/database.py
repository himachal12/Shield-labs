"""
db/database.py

Sets up the SQLAlchemy database engine and session factory.

Think of it like this:
- Engine = the connection to the database file
- Session = a temporary workspace where you make changes
           (like a shopping cart — you add items, then checkout/commit)
- Base = the parent class all our database models inherit from
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from core.config import settings

# ─────────────────────────────────────────────
# DATABASE URL
# ─────────────────────────────────────────────

# SQLite stores everything in a single file.
# "sqlite:///shieldlabs.db" means:
# - sqlite:// = use SQLite
# - ///shieldlabs.db = file named shieldlabs.db in current directory
DATABASE_URL = "sqlite:///shieldlabs.db"


# ─────────────────────────────────────────────
# ENGINE
# ─────────────────────────────────────────────

# The engine is the actual connection to the database.
# connect_args={"check_same_thread": False} is required for SQLite
# when used with FastAPI because FastAPI handles multiple requests
# on different threads, and SQLite needs this flag to allow that.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=settings.debug  # If DEBUG=True, prints every SQL query (great for learning)
)


# ─────────────────────────────────────────────
# SESSION FACTORY
# ─────────────────────────────────────────────

# SessionLocal is a factory — calling SessionLocal() creates a new session.
# autocommit=False → we manually commit changes (safer, gives us control)
# autoflush=False  → don't auto-send changes to DB until we commit
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)


# ─────────────────────────────────────────────
# BASE CLASS
# ─────────────────────────────────────────────

# All our database models (tables) will inherit from this Base class.
# SQLAlchemy uses it to track all models and create tables.
class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────
# DEPENDENCY — Used by FastAPI
# ─────────────────────────────────────────────

def get_db():
    """
    FastAPI dependency that provides a database session.

    This is a generator function (uses yield instead of return).
    FastAPI calls this automatically for every request that needs DB access.

    The try/finally pattern guarantees the session is always closed
    even if an error occurs during the request. This prevents
    connection leaks.

    Usage in FastAPI:
        @app.get("/scans")
        def get_scans(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db        # Hand the session to the route handler
    finally:
        db.close()      # Always close, no matter what