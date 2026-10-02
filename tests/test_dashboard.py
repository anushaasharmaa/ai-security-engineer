"""Runs dashboard/app.py headlessly (streamlit.testing) against the real API app + test database."""
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from rag.ingestion import ingest

APP = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


@pytest.fixture
def run_dashboard(client, monkeypatch):
    """Route the dashboard's httpx.get calls into the FastAPI test client."""
    def fake_get(url, params=None, timeout=None):
        path = "/" + url.split("/", 3)[3]
        return client.get(path, params=params)

    monkeypatch.setattr(httpx, "get", fake_get)

    def _run():
        st.cache_data.clear()
        return AppTest.from_file(APP, default_timeout=30).run()
    return _run


def _text(app) -> str:
    return "\n".join(str(e.value) for e in list(app.markdown) + list(app.caption))


def test_dashboard_shows_summary_table_and_detail(run_dashboard, client, db, normalized_findings):
    ingest(db)
    client.post("/findings", json=[f.model_dump(mode="json") for f in normalized_findings])

    app = run_dashboard()
    assert not app.exception and not app.error

    metrics = {m.label: m.value for m in app.metric}
    assert metrics == {"Total findings": "9", "Critical": "2", "High": "5", "Medium": "1", "Low": "1"}

    table = app.dataframe[0].value
    assert list(table.columns) == ["Scanner", "Severity", "Finding Type", "File", "Line", "Status"]
    assert len(table) == 9
    assert table.iloc[0]["Severity"] == "CRITICAL"

    # First (most severe) finding is selected by default: command injection.
    text = _text(app)
    for heading in ("What is the vulnerability?", "Why is it dangerous?",
                    "Relevant CWE / OWASP information", "Recommended secure coding practice",
                    "Description", "Evidence", "Retrieved security context (RAG)"):
        assert heading in text
    assert "CWE-78" in text
    assert "Generated WITHOUT an LLM" in text            # honest label for the fallback
    assert "os.system" in app.code[0].value
    assert len(app.expander) == 4                         # retrieved chunks
    assert "exact CWE match" in app.expander[0].label


def test_selecting_another_finding_updates_the_detail(run_dashboard, client, db, normalized_findings):
    ingest(db)
    client.post("/findings", json=[f.model_dump(mode="json") for f in normalized_findings])
    app = run_dashboard()

    selectbox = app.selectbox(key="selected_finding")
    secret_index = next(i for i, option in enumerate(selectbox.options) if "Gitleaks" in option)
    app = selectbox.select_index(secret_index).run()

    assert not app.exception and not app.error
    assert "CWE-798" in _text(app)
    assert app.code[0].value == "[secret redacted by Gitleaks]"
    assert "Hardcoded Credentials" in app.expander[0].label


def test_severity_filter(run_dashboard, client, db, normalized_findings):
    ingest(db)
    client.post("/findings", json=[f.model_dump(mode="json") for f in normalized_findings])
    app = run_dashboard()
    app = app.sidebar.multiselect[0].set_value(["CRITICAL"]).run()
    assert len(app.dataframe[0].value) == 2
    assert app.metric[0].value == "9"                     # summary stays global


def test_empty_database_shows_guidance(run_dashboard):
    app = run_dashboard()
    assert not app.exception
    assert app.metric[0].value == "0"
    assert "No findings stored yet" in app.info[0].value


def test_api_down_shows_clear_error(monkeypatch):
    def refuse(url, params=None, timeout=None):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", refuse)
    st.cache_data.clear()
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert "Cannot reach the API" in app.error[0].value
    assert "uvicorn backend.main:app" in app.error[0].value
