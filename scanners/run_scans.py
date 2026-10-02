"""
Run Semgrep and Gitleaks against a target directory and write raw JSON reports.

    python -m scanners.run_scans --target test-repo --out reports

The same two commands are used by .github/workflows/security.yml, so local runs
and CI produce identical report formats.

Trivy / Checkov are planned for the final phase and are intentionally absent.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEMGREP_RULES = REPO_ROOT / "scanners" / "semgrep" / "rules"
GITLEAKS_CONFIG = REPO_ROOT / "scanners" / "gitleaks" / "gitleaks.toml"


class ScannerError(RuntimeError):
    """A scanner is missing or failed to run (not: 'the scanner found issues')."""


def _require(binary: str, install_hint: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise ScannerError(f"'{binary}' was not found on PATH. {install_hint}")
    return path


def _run(cmd: list[str], name: str, report: Path) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # Both tools are invoked so that "findings present" still exits 0.
    # Any non-zero exit therefore means the scan itself failed.
    if proc.returncode != 0:
        raise ScannerError(
            f"{name} failed (exit {proc.returncode}).\n{proc.stderr.strip() or proc.stdout.strip()}"
        )
    if not report.exists():
        raise ScannerError(f"{name} finished but did not write {report}")


def run_semgrep(target: Path, out_dir: Path) -> Path:
    semgrep = _require("semgrep", "Install it with: pipx install semgrep")
    report = out_dir / "semgrep.json"
    _run(
        [
            semgrep, "scan",
            "--config", str(SEMGREP_RULES),
            "--json", "--output", str(report),
            "--metrics=off", "--disable-version-check", "--quiet",
            str(target),
        ],
        "Semgrep",
        report,
    )
    return report


def run_gitleaks(target: Path, out_dir: Path) -> Path:
    gitleaks = _require(
        "gitleaks", "Install it from https://github.com/gitleaks/gitleaks/releases (v8.19+)"
    )
    report = out_dir / "gitleaks.json"
    _run(
        [
            gitleaks, "dir", str(target),
            "--config", str(GITLEAKS_CONFIG),
            "--report-format", "json", "--report-path", str(report),
            "--redact",          # never write secret values into reports
            "--no-banner",
            "--exit-code", "0",  # findings are data, not a scan failure
        ],
        "Gitleaks",
        report,
    )
    return report


def run_all(target: Path, out_dir: Path) -> dict[str, Path]:
    if not target.is_dir():
        raise ScannerError(f"Scan target '{target}' is not a directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "semgrep": run_semgrep(target, out_dir),
        "gitleaks": run_gitleaks(target, out_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Semgrep and Gitleaks.")
    parser.add_argument("--target", default="test-repo", help="directory to scan")
    parser.add_argument("--out", default="reports", help="directory for JSON reports")
    args = parser.parse_args(argv)
    try:
        reports = run_all(Path(args.target), Path(args.out))
    except ScannerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    for name, path in reports.items():
        print(f"{name}: wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
