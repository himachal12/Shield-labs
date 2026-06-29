"""Application configuration for ShieldLabs."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ShieldLabs"
    app_version: str = "1.0.0"
    debug: bool = True
    database_url: str = "sqlite:///./shieldlabs.db"
    groq_api_key: str = ""
    groq_model: str = "llama3-70b-8192"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
