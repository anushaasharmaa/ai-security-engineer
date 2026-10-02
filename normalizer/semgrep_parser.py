"""Semgrep JSON (`semgrep scan --json`) -> NormalizedFinding."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from normalizer.base import NormalizationError, ScannerParser
from normalizer.schema import NormalizedFinding, Severity, make_finding_id

log = logging.getLogger(__name__)

# Semgrep has two severity vocabularies: legacy (ERROR/WARNING/INFO) and the
# newer CRITICAL/HIGH/MEDIUM/LOW. Both are accepted.
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_MAX_EVIDENCE_LINES = 10
_MAX_EVIDENCE_CHARS = 1000
# Semgrep puts this placeholder in `extra.lines` when the user is not logged in.
_WITHHELD = {"requires login", ""}


def _extract_cwe(metadata: dict) -> str | None:
    raw = metadata.get("cwe")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not isinstance(raw, str):
        return None
    match = _CWE_RE.search(raw)
    return match.group(0).upper() if match else None


def _finding_type(metadata: dict, rule_id: str) -> str:
    if isinstance(metadata.get("finding_type"), str) and metadata["finding_type"].strip():
        return metadata["finding_type"].strip()
    # Fallback for third-party rules: "python.lang.security.sql-injection" -> "Sql Injection"
    return rule_id.split(".")[-1].replace("-", " ").replace("_", " ").title()


def _read_source_lines(source_root: Path | None, path: str, start: int, end: int) -> str | None:
    if source_root is None:
        return None
    try:
        lines = (source_root / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    end = min(max(end, start), start + _MAX_EVIDENCE_LINES - 1)
    snippet = "\n".join(lines[start - 1:end]).strip()
    return snippet or None


class SemgrepParser(ScannerParser):
    key = "semgrep"
    scanner_name = "Semgrep"

    def parse(self, report: Any, source_root: Path | None = None) -> list[NormalizedFinding]:
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            raise NormalizationError("Semgrep report must be a JSON object with a 'results' list")

        findings: list[NormalizedFinding] = []
        for index, result in enumerate(report["results"]):
            try:
                findings.append(self._parse_result(result, source_root))
            except (KeyError, TypeError, ValueError) as exc:
                # One malformed entry should not discard the rest of the report.
                log.warning("Skipping malformed Semgrep result #%d: %s", index, exc)
        return findings

    def _parse_result(self, result: dict, source_root: Path | None) -> NormalizedFinding:
        rule_id = result["check_id"]
        path = result["path"]
        start_line = int(result["start"]["line"])
        end_line = int(result.get("end", {}).get("line", start_line))
        extra = result.get("extra", {})
        metadata = extra.get("metadata") or {}

        evidence = extra.get("lines")
        if not isinstance(evidence, str) or evidence.strip() in _WITHHELD:
            evidence = _read_source_lines(source_root, path, start_line, end_line)
        if evidence:
            evidence = evidence.strip()[:_MAX_EVIDENCE_CHARS]

        severity = _SEVERITY_MAP.get(str(extra.get("severity", "")).upper())
        if severity is None:
            log.warning("Unknown Semgrep severity %r for %s; using MEDIUM", extra.get("severity"), rule_id)
            severity = Severity.MEDIUM

        finding_type = _finding_type(metadata, rule_id)
        return NormalizedFinding(
            id=make_finding_id(self.scanner_name, rule_id, path, start_line, evidence),
            scanner=self.scanner_name,
            finding_type=finding_type,
            severity=severity,
            title=f"Potential {finding_type}",
            description=" ".join(str(extra.get("message", "")).split()),
            file_path=path,
            line_number=start_line,
            evidence=evidence,
            rule_id=rule_id,
            cwe=_extract_cwe(metadata),
        )
