"""Shared fixtures.

Tests that need PostgreSQL use a SEPARATE database (TEST_DATABASE_URL) and are
skipped with a clear reason if it is not reachable. Parser/normalizer tests run
without any database.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
DEFAULT_TEST_URL = "postgresql+psycopg2://secuser:secpass@localhost:5432/security_test_db"

# Point the application at the test database BEFORE any app module creates an engine.
TEST_URL = os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_URL)
os.environ["DATABASE_URL"] = TEST_URL
# Tests must be deterministic and offline: never call a real LLM or download a model.
os.environ["LLM_API_KEY"] = ""
os.environ["LLM_MODEL"] = ""
os.environ["EMBEDDING_PROVIDER"] = "hash"


@pytest.fixture(scope="session")
def _database():
    from database import DatabaseConfigError, init_db, reset_engine_cache

    reset_engine_cache()
    try:
        init_db()
    except DatabaseConfigError as exc:
        pytest.skip(f"PostgreSQL test database not available: {exc}")


@pytest.fixture
def db(_database):
    """Clean session: both tables are emptied before each test."""
    from sqlalchemy import text

    from database import new_session

    session = new_session()
    session.execute(text("TRUNCATE findings, knowledge_chunks RESTART IDENTITY"))
    session.commit()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def normalized_findings():
    """The 9 findings produced from the real scanner reports in tests/fixtures."""
    from normalizer import normalize

    semgrep = normalize("semgrep", json.loads((FIXTURES / "semgrep_report.json").read_text()), REPO_ROOT)
    gitleaks = normalize("gitleaks", json.loads((FIXTURES / "gitleaks_report.json").read_text()), REPO_ROOT)
    return semgrep + gitleaks
