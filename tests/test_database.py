from sqlalchemy import inspect, text

from backend.services import finding_service
from database import Finding, get_engine
from normalizer.schema import NormalizedFinding, Severity


def test_tables_and_pgvector_exist(db):
    tables = set(inspect(get_engine()).get_table_names())
    assert {"findings", "knowledge_chunks"} <= tables
    assert db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")).scalar() == 1


def test_findings_table_matches_normalized_schema(db):
    columns = {c["name"] for c in inspect(get_engine()).get_columns("findings")}
    assert columns == set(NormalizedFinding.model_fields)


def test_insert_and_retrieve_roundtrip(db, normalized_findings):
    created = finding_service.create_findings(db, normalized_findings)
    assert len(created) == 9

    original = normalized_findings[0]
    stored = finding_service.get_finding(db, original.id)
    assert isinstance(stored, Finding)
    for field in ("scanner", "finding_type", "title", "description", "file_path",
                  "line_number", "evidence", "rule_id", "cwe"):
        assert getattr(stored, field) == getattr(original, field)
    assert stored.severity == original.severity.value
    assert stored.status == "OPEN"
    assert stored.timestamp == original.timestamp


def test_reinserting_is_idempotent(db, normalized_findings):
    assert len(finding_service.create_findings(db, normalized_findings)) == 9
    assert finding_service.create_findings(db, normalized_findings) == []
    assert finding_service.get_summary(db)["total"] == 9


def test_list_is_ordered_by_severity_and_filterable(db, normalized_findings):
    finding_service.create_findings(db, normalized_findings)
    severities = [f.severity for f in finding_service.list_findings(db)]
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    assert severities == sorted(severities, key=rank.get)
    assert len(finding_service.list_findings(db, severity=Severity.CRITICAL)) == 2
    assert len(finding_service.list_findings(db, scanner="gitleaks")) == 1


def test_summary_counts(db, normalized_findings):
    assert finding_service.get_summary(db) == {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    finding_service.create_findings(db, normalized_findings)
    assert finding_service.get_summary(db) == {"total": 9, "critical": 2, "high": 5, "medium": 1, "low": 1}


def test_missing_finding_returns_none(db):
    assert finding_service.get_finding(db, "does-not-exist") is None
