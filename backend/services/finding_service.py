"""Database operations for findings. No HTTP or scanner knowledge in here."""
from __future__ import annotations

from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from database.models import Finding
from normalizer.schema import NormalizedFinding, Severity

_SEVERITY_RANK = case(
    {s.value: rank for rank, s in enumerate(Severity)},  # CRITICAL=0 ... LOW=3
    value=Finding.severity,
    else_=99,
)


def create_findings(db: Session, findings: list[NormalizedFinding]) -> list[str]:
    """Insert findings, ignoring IDs that already exist.

    Finding IDs are deterministic, so re-running the pipeline on unchanged code
    creates nothing new and keeps the original first-seen timestamp and status.
    Returns the IDs that were actually inserted.
    """
    if not findings:
        return []
    unique = {f.id: f for f in findings}  # duplicates inside one request
    rows = [f.model_dump(mode="python") for f in unique.values()]
    for row in rows:
        row["severity"] = row["severity"].value
        row["status"] = row["status"].value
    stmt = insert(Finding).values(rows).on_conflict_do_nothing(index_elements=[Finding.id]).returning(Finding.id)
    created = list(db.execute(stmt).scalars())
    db.commit()
    return created


def list_findings(db: Session, *, severity: Severity | None = None, scanner: str | None = None,
                  limit: int = 200, offset: int = 0) -> list[Finding]:
    stmt = select(Finding)
    if severity:
        stmt = stmt.where(Finding.severity == severity.value)
    if scanner:
        stmt = stmt.where(func.lower(Finding.scanner) == scanner.lower())
    stmt = stmt.order_by(_SEVERITY_RANK, Finding.file_path, Finding.line_number).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars())


def get_finding(db: Session, finding_id: str) -> Finding | None:
    return db.get(Finding, finding_id)


def get_summary(db: Session) -> dict[str, int]:
    counts = dict(db.execute(select(Finding.severity, func.count()).group_by(Finding.severity)).all())
    summary = {s.value.lower(): int(counts.get(s.value, 0)) for s in Severity}
    summary["total"] = sum(summary.values())
    return summary
