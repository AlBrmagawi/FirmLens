from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FL_", env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://firmwarelens@db/firmwarelens"
    data_dir: Path = Path("/data")
    data_volume: str = "firmwarelens_data"
    intelligence_volume: str = "firmwarelens_intelligence"
    sandbox_image: str = "firmwarelens-sandbox:0.1.0"
    origin: str = "http://localhost:8080"
    upload_limit: int = 134217728
    job_timeout: int = 600
    max_attempts: int = 2
    lease_seconds: int = 90
    secure_cookie: bool = False
    ai_provider: Literal["disabled", "openai", "ollama"] = "disabled"
    cloud_ai_enabled: bool = False
    ai_model: str = ""
    openai_api_key: str = ""
    ollama_url: str = "http://host.docker.internal:11434"
    ai_timeout: int = 60
    ai_daily_requests: int = 50
    ai_context_chars: int = 24000


@lru_cache
def settings() -> Settings:
    return Settings()
