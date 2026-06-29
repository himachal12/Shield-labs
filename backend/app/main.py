"""
ShieldLabs Main Application
FastAPI entry point for the security scanning platform
"""

import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import API routes
from app.api.routes import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Get config from .env
APP_NAME = os.getenv("APP_NAME", "ShieldLabs")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
DEBUG = os.getenv("DEBUG", "True") == "True"

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for FastAPI
    Runs on startup and shutdown
    """
    # On startup
    logger.info(f"🛡️  {APP_NAME} v{APP_VERSION} starting up...")
    logger.info(f"🔧 Debug mode: {DEBUG}")
    logger.info(f"🧠 Ollama API: {os.getenv('OLLAMA_BASE_URL')}")
    logger.info(f"🚀 Groq API: {'Configured' if os.getenv('GROQ_API_KEY') else 'NOT CONFIGURED'}")
    
    yield  # App runs here
    
    # On shutdown
    logger.info(f"🛑 {APP_NAME} shutting down...")

# Create FastAPI app
app = FastAPI(
    title=APP_NAME,
    description="AI-powered security scanner and vulnerability remediation engine",
    version=APP_VERSION,
    debug=DEBUG,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routes
app.include_router(router)

# Health check endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": f"Welcome to {APP_NAME}",
        "version": APP_VERSION,
        "status": "running"
    }

@app.get("/api/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "debug": DEBUG,
        "services": {
            "api": "operational",
            "database": "operational",
            "ollama": "not_checked_yet",
            "groq": "not_checked_yet"
        }
    }

# Error handlers
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle all exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return {
        "error": "Internal server error",
        "detail": str(exc) if DEBUG else "An error occurred"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )