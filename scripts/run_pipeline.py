"""
Run the whole midterm pipeline locally, without GitHub Actions:

    scan (Semgrep + Gitleaks) -> normalize -> POST to the API -> print summary

    python -m scripts.run_pipeline                 # scan test-repo/
    python -m scripts.run_pipeline --skip-scan     # reuse reports/*.json, e.g. artifacts downloaded from CI

Requires the API to be running (uvicorn backend.main:app).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

from normalizer import NormalizationError
from normalizer.__main__ import normalize_reports
from scanners.run_scans import ScannerError, run_all

load_dotenv()


def post_findings(api_url: str, findings: list[dict]) -> dict:
    try:
        health = httpx.get(f"{api_url}/health", timeout=10)
        health.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"API is not reachable/healthy at {api_url} ({type(exc).__name__}). "
            "Start it with: uvicorn backend.main:app"
        ) from exc
    if health.json().get("knowledge_chunks") == 0:
        print("WARNING: knowledge base is empty. Run: python -m rag.ingestion", file=sys.stderr)

    if not findings:
        return {"received": 0, "created": 0, "duplicates": 0}
    response = httpx.post(f"{api_url}/findings", json=findings, timeout=30)
    if response.status_code != 201:
        raise RuntimeError(f"POST /findings failed with {response.status_code}: {response.text[:300]}")
    return response.json()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan -> normalize -> store.")
    parser.add_argument("--target", default="test-repo", help="directory to scan")
    parser.add_argument("--reports", default="reports", help="directory for raw and normalized reports")
    parser.add_argument("--api-url", default=os.getenv("API_URL", "http://localhost:8000"))
    parser.add_argument("--skip-scan", action="store_true", help="reuse existing semgrep.json / gitleaks.json")
    args = parser.parse_args(argv)
    reports_dir, api_url = Path(args.reports), args.api_url.rstrip("/")

    try:
        if args.skip_scan:
            reports = {name: reports_dir / f"{name}.json" for name in ("semgrep", "gitleaks")}
            print(f"[1/3] Scan skipped, using existing reports in {reports_dir}/")
        else:
            print(f"[1/3] Scanning {args.target}/ with Semgrep and Gitleaks ...")
            reports = run_all(Path(args.target), reports_dir)

        print("[2/3] Normalizing findings ...")
        findings = normalize_reports(reports, Path("."))
        payload = [f.model_dump(mode="json") for f in findings]
        normalized_path = reports_dir / "normalized-findings.json"
        normalized_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        by_scanner: dict[str, int] = {}
        for finding in findings:
            by_scanner[finding.scanner] = by_scanner.get(finding.scanner, 0) + 1
        print(f"      {len(findings)} finding(s) {by_scanner} -> {normalized_path}")

        print(f"[3/3] Sending findings to {api_url}/findings ...")
        result = post_findings(api_url, payload)
        print(f"      received={result['received']} created={result['created']} duplicates={result['duplicates']}")
        print(f"Summary: {httpx.get(f'{api_url}/summary', timeout=10).json()}")
    except (ScannerError, NormalizationError, RuntimeError, httpx.HTTPError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Done. Open the dashboard: streamlit run dashboard/app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
