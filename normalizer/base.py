"""Parser interface and registry.

To add a scanner in the final phase (e.g. Trivy, Checkov):
    1. Subclass ScannerParser in a new module.
    2. Call register_parser(MyParser()).
Nothing else in the pipeline needs to change.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from normalizer.schema import NormalizedFinding


class NormalizationError(ValueError):
    """The scanner report does not have the structure the parser expects."""


class ScannerParser(ABC):
    #: key used on the command line and in the registry, e.g. "semgrep"
    key: str
    #: value stored in NormalizedFinding.scanner, e.g. "Semgrep"
    scanner_name: str

    @abstractmethod
    def parse(self, report: Any, source_root: Path | None = None) -> list[NormalizedFinding]:
        """Convert one raw scanner report into normalized findings."""


_PARSERS: dict[str, ScannerParser] = {}


def register_parser(parser: ScannerParser) -> None:
    _PARSERS[parser.key] = parser


def get_parser(key: str) -> ScannerParser:
    try:
        return _PARSERS[key.lower()]
    except KeyError:
        raise NormalizationError(
            f"No parser registered for scanner '{key}'. Available: {sorted(_PARSERS)}"
        ) from None


def available_scanners() -> list[str]:
    return sorted(_PARSERS)


def normalize(scanner: str, report: Any, source_root: Path | None = None) -> list[NormalizedFinding]:
    return get_parser(scanner).parse(report, source_root)
