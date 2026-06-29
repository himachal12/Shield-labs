"""
Dependencies for FastAPI routes
Shared functions used by multiple endpoints
"""

from sqlalchemy.orm import Session
from app.database import get_db
from typing import Generator

def get_database() -> Generator[Session, None, None]:
    """
    Get database session for routes
    
    Usage in route:
    @app.get("/endpoint")
    async def my_route(db: Session = Depends(get_database)):
        ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()