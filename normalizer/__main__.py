"""
Normalize raw scanner reports into one JSON file.

    python -m normalizer --semgrep reports/semgrep.json --gitleaks reports/gitleaks.json \
        --source-root . --output reports/normalized-findings.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from normalizer import NormalizationError, NormalizedFinding, available_scanners, normalize


def normalize_reports(reports: dict[str, Path], source_root: Path) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for scanner, path in reports.items():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise NormalizationError(f"{scanner} report not found: {path}") from None
        except json.JSONDecodeError as exc:
            raise NormalizationError(f"{scanner} report {path} is not valid JSON: {exc}") from None
        findings.extend(normalize(scanner, raw, source_root))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize scanner reports.")
    for scanner in available_scanners():
        parser.add_argument(f"--{scanner}", type=Path, help=f"path to the raw {scanner} JSON report")
    parser.add_argument("--source-root", type=Path, default=Path("."),
                        help="directory the scanners were run from (used to read evidence lines)")
    parser.add_argument("--output", type=Path, default=Path("reports/normalized-findings.json"))
    args = parser.parse_args(argv)

    reports = {s: getattr(args, s) for s in available_scanners() if getattr(args, s)}
    if not reports:
        parser.error("provide at least one report, e.g. --semgrep reports/semgrep.json")

    try:
        findings = normalize_reports(reports, args.source_root)
    except NormalizationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8"
    )
    print(f"Normalized {len(findings)} finding(s) from {', '.join(reports)} -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
