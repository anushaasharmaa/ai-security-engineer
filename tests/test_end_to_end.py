"""
Complete midterm flow with the REAL scanners:

    scan test-repo -> parse -> normalize -> POST /findings -> PostgreSQL
    -> GET /findings -> RAG retrieval -> explanation

Skipped (with a reason) if Semgrep or Gitleaks is not installed.
"""
import shutil
from pathlib import Path

import pytest

from normalizer.__main__ import normalize_reports
from rag.ingestion import ingest
from scanners.run_scans import run_all

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every vulnerability planted in test-repo/ : (file, finding type, CWE, scanner)
PLANTED = {
    ("test-repo/app.py", "SQL Injection", "CWE-89", "Semgrep"),
    ("test-repo/app.py", "Command Injection", "CWE-78", "Semgrep"),
    ("test-repo/app.py", "Code Injection", "CWE-95", "Semgrep"),
    ("test-repo/app.py", "Insecure Deserialization", "CWE-502", "Semgrep"),
    ("test-repo/app.py", "Cross-Site Scripting", "CWE-79", "Semgrep"),
    ("test-repo/app.py", "Weak Cryptography", "CWE-327", "Semgrep"),
    ("test-repo/config.py", "Hardcoded Secret", "CWE-798", "Gitleaks"),
}

pytestmark = pytest.mark.skipif(
    not (shutil.which("semgrep") and shutil.which("gitleaks")),
    reason="Semgrep and/or Gitleaks not installed; end-to-end scan test skipped",
)


def test_full_pipeline(client, db, tmp_path, monkeypatch):
    monkeypatch.chdir(REPO_ROOT)

    # 1-4. Scanners run and write JSON reports
    reports = run_all(Path("test-repo"), tmp_path)
    assert reports["semgrep"].exists() and reports["gitleaks"].exists()

    # 5-6. Parse + normalize
    findings = normalize_reports(reports, REPO_ROOT)
    assert {(f.file_path, f.finding_type, f.cwe, f.scanner) for f in findings} == PLANTED
    assert len(findings) == 9      # 2x SQL injection, 2x command injection, 5 others
    assert not any("safe_examples.py" in f.file_path for f in findings), "false positive on secure code"
    assert not any("FAKE_API_KEY" in (f.evidence or "") for f in findings), "secret value leaked into evidence"

    # 7-8. Store in PostgreSQL through the API, read back
    posted = client.post("/findings", json=[f.model_dump(mode="json") for f in findings])
    assert posted.status_code == 201 and posted.json()["created"] == 9
    stored = client.get("/findings").json()
    assert {f["id"] for f in stored} == {f.id for f in findings}
    assert client.get("/summary").json() == {"total": 9, "critical": 2, "high": 5, "medium": 1, "low": 1}

    # 9-10. RAG context + explanation for every finding
    ingest(db)
    for finding in stored:
        analysis = client.get(f"/findings/{finding['id']}/analysis").json()
        context = analysis["retrieved_context"]
        assert context, f"no context for {finding['finding_type']}"
        assert {c["cwe"] for c in context} == {finding["cwe"]}
        assert all(analysis["explanation"].values())
        assert analysis["generated_by"] == "fallback"   # tests never call a real LLM

    # Re-running the scan on unchanged code creates no duplicates
    again = normalize_reports(run_all(Path("test-repo"), tmp_path), REPO_ROOT)
    assert client.post("/findings", json=[f.model_dump(mode="json") for f in again]).json()["created"] == 0
