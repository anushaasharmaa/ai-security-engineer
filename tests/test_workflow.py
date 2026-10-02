"""Static checks on the GitHub Actions workflow (it cannot be executed locally)."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"


@pytest.fixture(scope="module")
def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def test_triggers_on_push_and_pull_request(workflow):
    triggers = workflow.get("on") or workflow.get(True)   # YAML parses the key `on` as boolean True
    assert {"push", "pull_request"} <= set(triggers)


def test_scan_job_runs_both_scanners_and_publishes_json(workflow):
    steps = workflow["jobs"]["scan"]["steps"]
    script = "\n".join(step.get("run", "") for step in steps)
    assert "semgrep scan" in script and "--json" in script
    assert "gitleaks dir" in script and "--report-format json" in script and "--redact" in script
    assert "python -m normalizer" in script
    assert any("upload-artifact" in step.get("uses", "") for step in steps)


def test_workflow_references_files_that_exist(workflow):
    script = "\n".join(step.get("run", "") for step in workflow["jobs"]["scan"]["steps"])
    for path in ("scanners/semgrep/rules", "scanners/gitleaks/gitleaks.toml"):
        assert path in script and (REPO_ROOT / path).exists()
    assert (REPO_ROOT / workflow["env"]["SCAN_TARGET"]).is_dir()


def test_workflow_has_least_privilege_permissions(workflow):
    assert workflow["permissions"] == {"contents": "read"}
