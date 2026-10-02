"""Central configuration. Everything comes from environment variables (.env supported)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_url: str
    embedding_provider: str
    embedding_model: str
    llm_api_key: str
    llm_model: str
    llm_base_url: str


def get_settings() -> Settings:
    """Read settings at call time so tests can override environment variables."""
    return Settings(
        database_url=os.getenv("DATABASE_URL", ""),
        api_url=os.getenv("API_URL", "http://localhost:8000").rstrip("/"),
        embedding_provider=os.getenv("EMBEDDING_PROVIDER", "hash").strip().lower(),
        embedding_model=os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2").strip(),
        llm_api_key=os.getenv("LLM_API_KEY", "").strip(),
        llm_model=os.getenv("LLM_MODEL", "").strip(),
        llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
    )
