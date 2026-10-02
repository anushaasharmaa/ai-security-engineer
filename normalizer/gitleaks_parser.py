"""Gitleaks JSON (`--report-format json`) -> NormalizedFinding."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from normalizer.base import NormalizationError, ScannerParser
from normalizer.schema import NormalizedFinding, Severity, make_finding_id

log = logging.getLogger(__name__)

# Gitleaks reports no severity, so we assign one. Any hardcoded secret is HIGH;
# rule IDs that indicate keys granting broad access are CRITICAL.
_CRITICAL_RULE_HINTS = ("private-key", "aws-", "gcp-", "azure-", "github-pat", "github-fine-grained")
_HARDCODED_CREDENTIALS_CWE = "CWE-798"
_REDACTED = "REDACTED"


def _severity_for(rule_id: str) -> Severity:
    rule = rule_id.lower()
    return Severity.CRITICAL if any(hint in rule for hint in _CRITICAL_RULE_HINTS) else Severity.HIGH


def _safe_evidence(match: str | None, secret: str | None) -> str:
    """Never let a secret value travel further down the pipeline.

    The pipeline runs Gitleaks with --redact, but reports produced without it
    are masked here as a second line of defence.
    """
    if not match or match == _REDACTED:
        return "[secret redacted by Gitleaks]"
    if secret and secret != _REDACTED and secret in match:
        return match.replace(secret, secret[:4] + "****[masked]")
    return match


class GitleaksParser(ScannerParser):
    key = "gitleaks"
    scanner_name = "Gitleaks"

    def parse(self, report: Any, source_root: Path | None = None) -> list[NormalizedFinding]:
        if report is None:  # Gitleaks may write `null` when nothing was found
            return []
        if not isinstance(report, list):
            raise NormalizationError("Gitleaks report must be a JSON array")

        findings: list[NormalizedFinding] = []
        for index, leak in enumerate(report):
            try:
                findings.append(self._parse_leak(leak))
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Skipping malformed Gitleaks result #%d: %s", index, exc)
        return findings

    def _parse_leak(self, leak: dict) -> NormalizedFinding:
        rule_id = leak["RuleID"]
        path = leak["File"]
        line = int(leak["StartLine"])
        evidence = _safe_evidence(leak.get("Match"), leak.get("Secret"))
        description = leak.get("Description") or f"Secret matching Gitleaks rule '{rule_id}'"

        return NormalizedFinding(
            # Evidence is excluded from the ID so redacted and unredacted reports
            # of the same leak map to the same finding.
            id=make_finding_id(self.scanner_name, rule_id, path, line, None),
            scanner=self.scanner_name,
            finding_type="Hardcoded Secret",
            severity=_severity_for(rule_id),
            title=f"Hardcoded secret detected ({rule_id})",
            description=(
                f"{description}. A credential committed to source control is exposed to "
                "everyone with repository access and remains in git history."
            ),
            file_path=path,
            line_number=line,
            evidence=evidence,
            rule_id=rule_id,
            cwe=_HARDCODED_CREDENTIALS_CWE,
        )
