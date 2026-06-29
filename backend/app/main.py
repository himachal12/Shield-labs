"""ShieldLabs FastAPI application."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.config import settings
from app.models.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("shieldlabs.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("%s v%s started", settings.app_name, settings.app_version)
    yield
    logger.info("%s stopped", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    description="AI-powered security scanner and vulnerability remediation engine",
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {"name": settings.app_name, "version": settings.app_version, "status": "running", "docs": "/docs"}


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "debug": settings.debug,
        "services": {"api": "operational", "database": "operational", "ollama": "not_checked", "groq": "configured" if settings.groq_api_key else "not_configured"},
    }


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"error": "Internal server error", "detail": str(exc) if settings.debug else "An error occurred"})
