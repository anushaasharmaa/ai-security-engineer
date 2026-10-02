"""The single normalized finding schema shared by every scanner, the API and the DB."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    # The midterm pipeline only ever produces OPEN. The other values exist so the
    # final phase (triage / remediation) does not need a schema change.
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NormalizedFinding(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    scanner: str = Field(min_length=1, max_length=50)
    finding_type: str = Field(min_length=1, max_length=100)
    severity: Severity
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=0)
    evidence: str | None = None
    rule_id: str | None = None
    cwe: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("severity", mode="before")
    @classmethod
    def _upper_severity(cls, value):
        return value.upper() if isinstance(value, str) else value

    @field_validator("cwe")
    @classmethod
    def _cwe_format(cls, value):
        if value is None or value == "":
            return None
        value = value.strip().upper()
        if not value.startswith("CWE-") or not value[4:].isdigit():
            raise ValueError("cwe must look like 'CWE-89'")
        return value


def make_finding_id(scanner: str, rule_id: str | None, file_path: str | None,
                    line_number: int | None, evidence: str | None) -> str:
    """Deterministic ID: the same finding in the same place always gets the same ID,
    so re-running the pipeline does not create duplicates."""
    raw = "|".join(str(part or "") for part in (scanner, rule_id, file_path, line_number, evidence))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
