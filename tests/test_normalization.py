import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from normalizer import (NormalizationError, NormalizedFinding, ScannerParser,
                        available_scanners, normalize, register_parser)
from normalizer.__main__ import main as normalizer_cli
from normalizer.base import _PARSERS

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parent.parent
REQUIRED_FIELDS = {"id", "scanner", "finding_type", "severity", "title", "description",
                   "file_path", "line_number", "evidence", "rule_id", "cwe", "status", "timestamp"}


def _all_findings():
    semgrep = normalize("semgrep", json.loads((FIXTURES / "semgrep_report.json").read_text()), REPO_ROOT)
    gitleaks = normalize("gitleaks", json.loads((FIXTURES / "gitleaks_report.json").read_text()), REPO_ROOT)
    return semgrep + gitleaks


def test_both_scanners_produce_the_same_schema():
    findings = _all_findings()
    assert len(findings) == 9
    for finding in findings:
        assert isinstance(finding, NormalizedFinding)
        assert set(finding.model_dump()) == REQUIRED_FIELDS
        assert finding.status.value == "OPEN"
        assert finding.timestamp.tzinfo is not None


def test_ids_are_unique_and_deterministic():
    first, second = _all_findings(), _all_findings()
    assert len({f.id for f in first}) == len(first)
    assert [f.id for f in first] == [f.id for f in second]


def test_unknown_scanner_is_a_clear_error():
    with pytest.raises(NormalizationError, match="No parser registered"):
        normalize("trivy", {})


def test_registry_is_extensible():
    """A future scanner only needs a parser class + register_parser()."""
    class FakeTrivyParser(ScannerParser):
        key = "faketrivy"
        scanner_name = "FakeTrivy"

        def parse(self, report, source_root=None):
            return [NormalizedFinding(id="t1", scanner=self.scanner_name, finding_type="Vulnerable Dependency",
                                      severity="high", title=report["title"])]

    register_parser(FakeTrivyParser())
    try:
        assert "faketrivy" in available_scanners()
        finding = normalize("faketrivy", {"title": "CVE in package"})[0]
        assert finding.severity.value == "HIGH"   # lower-case input is normalized
    finally:
        _PARSERS.pop("faketrivy")


def test_schema_rejects_invalid_values():
    base = dict(id="x", scanner="Semgrep", finding_type="t", title="t")
    with pytest.raises(ValidationError):
        NormalizedFinding(**base, severity="URGENT")
    with pytest.raises(ValidationError):
        NormalizedFinding(**base, severity="HIGH", cwe="89")
    with pytest.raises(ValidationError):
        NormalizedFinding(**base, severity="HIGH", status="FIXED")


def test_cli_writes_normalized_json(tmp_path):
    out = tmp_path / "normalized.json"
    code = normalizer_cli(["--semgrep", str(FIXTURES / "semgrep_report.json"),
                           "--gitleaks", str(FIXTURES / "gitleaks_report.json"),
                           "--source-root", str(REPO_ROOT), "--output", str(out)])
    assert code == 0
    data = json.loads(out.read_text())
    assert len(data) == 9
    assert {d["scanner"] for d in data} == {"Semgrep", "Gitleaks"}


def test_cli_reports_missing_and_invalid_files(tmp_path, capsys):
    assert normalizer_cli(["--semgrep", str(tmp_path / "missing.json")]) == 1
    assert "not found" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert normalizer_cli(["--semgrep", str(bad)]) == 1
    assert "not valid JSON" in capsys.readouterr().err
