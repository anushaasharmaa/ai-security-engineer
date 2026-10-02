import json
from pathlib import Path

import pytest

from normalizer import NormalizationError, SemgrepParser, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_report.json"
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def report():
    return json.loads(FIXTURE.read_text())


def test_parses_every_result_from_real_report(report):
    findings = SemgrepParser().parse(report, REPO_ROOT)
    assert len(findings) == len(report["results"]) == 8
    assert {f.scanner for f in findings} == {"Semgrep"}


def test_detects_expected_vulnerability_classes(report):
    by_type = {f.finding_type: f for f in SemgrepParser().parse(report, REPO_ROOT)}
    assert by_type["SQL Injection"].cwe == "CWE-89"
    assert by_type["Command Injection"].cwe == "CWE-78"
    assert by_type["Command Injection"].severity is Severity.CRITICAL
    assert by_type["Cross-Site Scripting"].cwe == "CWE-79"
    assert by_type["Weak Cryptography"].severity is Severity.LOW


def test_evidence_is_read_from_source_when_semgrep_withholds_it(report):
    # Semgrep writes "requires login" into extra.lines for anonymous users.
    assert report["results"][0]["extra"]["lines"] == "requires login"
    finding = SemgrepParser().parse(report, REPO_ROOT)[0]
    assert "cursor.execute" in finding.evidence
    assert "requires login" not in finding.evidence


def test_evidence_is_none_when_source_unavailable(report):
    finding = SemgrepParser().parse(report, source_root=None)[0]
    assert finding.evidence is None


def test_legacy_severities_and_list_cwe_are_mapped():
    report = {"results": [{
        "check_id": "python.lang.security.some-rule",
        "path": "a.py", "start": {"line": 3}, "end": {"line": 3},
        "extra": {"severity": "ERROR", "message": "msg", "lines": "x = 1",
                  "metadata": {"cwe": ["CWE-22: Path Traversal"]}},
    }]}
    finding = SemgrepParser().parse(report)[0]
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-22"
    assert finding.finding_type == "Some Rule"   # derived from the rule id
    assert finding.evidence == "x = 1"


def test_malformed_result_is_skipped_not_fatal(report):
    report["results"].append({"check_id": "broken"})  # no path / start
    assert len(SemgrepParser().parse(report, REPO_ROOT)) == 8


def test_wrong_top_level_structure_raises():
    with pytest.raises(NormalizationError):
        SemgrepParser().parse([])
    with pytest.raises(NormalizationError):
        SemgrepParser().parse({"no_results": True})


def test_empty_report_gives_no_findings():
    assert SemgrepParser().parse({"results": []}) == []
