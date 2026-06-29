"""
main.py

ShieldLabs FastAPI application entry point.

This file:
1. Creates the FastAPI app
2. Sets up the database tables
3. Registers all routes
4. Configures logging
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from db.database import engine, Base
from db import models  # Must import to register models with Base
from api.routes import scans

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

# Configure logging so every module's logs show up cleanly
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("shieldlabs.main")

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

# Create all tables on startup if they don't exist
# Safe to run every time — won't overwrite existing tables
Base.metadata.create_all(bind=engine)
logger.info("Database tables verified.")

# ─────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────

app = FastAPI(
    title="ShieldLabs API",
    description="AI-Powered Security Scanner for Nepal Startups",
    version="1.0.0",
    docs_url="/docs",      # Swagger UI at http://localhost:8000/docs
    redoc_url="/redoc"     # ReDoc UI at http://localhost:8000/redoc
)

# ─────────────────────────────────────────────
# CORS MIDDLEWARE
# ─────────────────────────────────────────────

# CORS = Cross-Origin Resource Sharing
# Without this, your React frontend (on port 3000) cannot
# talk to this API (on port 8000) — browser blocks it
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # In production, list specific domains
    allow_credentials=True,
    allow_methods=["*"],       # Allow GET, POST, DELETE, etc.
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

# Register the scans router with /api/v1 prefix
# All scan endpoints will be at /api/v1/scans/...
app.include_router(scans.router, prefix="/api/v1")


# ─────────────────────────────────────────────
# ROOT ENDPOINT
# ─────────────────────────────────────────────

@app.get("/")
def root():
    """Root endpoint — confirms API is alive."""
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }