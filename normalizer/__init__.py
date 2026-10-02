"""Finding normalization: scanner-specific JSON -> one common schema."""
from normalizer.base import (
    NormalizationError,
    ScannerParser,
    available_scanners,
    get_parser,
    normalize,
    register_parser,
)
from normalizer.gitleaks_parser import GitleaksParser
from normalizer.schema import FindingStatus, NormalizedFinding, Severity, make_finding_id
from normalizer.semgrep_parser import SemgrepParser

register_parser(SemgrepParser())
register_parser(GitleaksParser())

__all__ = [
    "FindingStatus", "GitleaksParser", "NormalizationError", "NormalizedFinding",
    "ScannerParser", "SemgrepParser", "Severity", "available_scanners", "get_parser",
    "make_finding_id", "normalize", "register_parser",
]
