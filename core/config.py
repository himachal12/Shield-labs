"""
core/config.py

This module loads all environment variables from the .env file
and makes them available as a single config object.

Why do this? Instead of calling os.getenv() everywhere in your code,
you import this config object once and access settings cleanly.
"""

from pydantic_settings import BaseSettings  # Pydantic's settings management
from functools import lru_cache             # Caches the config so it's only loaded once


class Settings(BaseSettings):
    """
    Settings class — each attribute maps to a variable in your .env file.
    Pydantic automatically reads the .env file and fills these in.
    If a required variable is missing, it raises a clear error immediately.
    """

    # App
    app_name: str = "ShieldLabs"
    debug: bool = True

    # Groq
    groq_api_key: str
    groq_model: str = "llama3-70b-8192"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "codellama:7b"

    class Config:
        # Tells Pydantic where to find the .env file
        env_file = ".env"
        # Makes variable names case-insensitive
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Returns the Settings object.

    @lru_cache means this function only runs ONCE no matter how many
    times you call it. After the first call, it returns the cached result.
    This is important for performance — you don't want to re-read the
    .env file on every single API request.
    """
    return Settings()


# A single importable instance of settings
settings = get_settings()