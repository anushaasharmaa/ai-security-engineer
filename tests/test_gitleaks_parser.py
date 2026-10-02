import json
from pathlib import Path

import pytest

from normalizer import GitleaksParser, NormalizationError, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "gitleaks_report.json"


@pytest.fixture
def report():
    return json.loads(FIXTURE.read_text())


def test_parses_real_report(report):
    findings = GitleaksParser().parse(report)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "Gitleaks"
    assert finding.finding_type == "Hardcoded Secret"
    assert finding.cwe == "CWE-798"
    assert finding.severity is Severity.HIGH
    assert finding.file_path == "test-repo/config.py"
    assert finding.rule_id == "demo-fake-api-key"
    assert finding.line_number == 9


def test_redacted_report_never_exposes_secret(report):
    finding = GitleaksParser().parse(report)[0]
    assert finding.evidence == "[secret redacted by Gitleaks]"


def test_unredacted_report_is_masked_by_parser():
    leak = {"RuleID": "generic-api-key", "File": "a.py", "StartLine": 2,
            "Match": 'token = "abcd1234efgh5678"', "Secret": "abcd1234efgh5678"}
    finding = GitleaksParser().parse([leak])[0]
    assert "abcd1234efgh5678" not in finding.evidence
    assert finding.evidence.startswith('token = "abcd****')


def test_id_is_same_for_redacted_and_unredacted_reports():
    base = {"RuleID": "r", "File": "a.py", "StartLine": 2}
    redacted = GitleaksParser().parse([{**base, "Match": "REDACTED", "Secret": "REDACTED"}])[0]
    plain = GitleaksParser().parse([{**base, "Match": "k=secretvalue", "Secret": "secretvalue"}])[0]
    assert redacted.id == plain.id


def test_private_key_rules_are_critical():
    leak = {"RuleID": "private-key", "File": "id_rsa", "StartLine": 1, "Match": "REDACTED"}
    assert GitleaksParser().parse([leak])[0].severity is Severity.CRITICAL


def test_empty_and_null_reports():
    assert GitleaksParser().parse([]) == []
    assert GitleaksParser().parse(None) == []


def test_wrong_structure_raises():
    with pytest.raises(NormalizationError):
        GitleaksParser().parse({"results": []})


def test_malformed_entry_is_skipped(report):
    report.append({"RuleID": "x"})  # no File / StartLine
    assert len(GitleaksParser().parse(report)) == 1
