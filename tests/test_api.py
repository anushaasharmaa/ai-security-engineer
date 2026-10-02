def _payload(findings):
    return [f.model_dump(mode="json") for f in findings]


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database"] == "ok"


def test_post_list_then_get(client, normalized_findings):
    response = client.post("/findings", json=_payload(normalized_findings))
    assert response.status_code == 201
    assert response.json()["received"] == 9
    assert response.json()["created"] == 9
    assert response.json()["duplicates"] == 0

    listed = client.get("/findings").json()
    assert len(listed) == 9
    assert listed[0]["severity"] == "CRITICAL"   # most severe first
    assert {"id", "scanner", "finding_type", "severity", "title", "description", "file_path",
            "line_number", "evidence", "rule_id", "cwe", "status", "timestamp"} == set(listed[0])


def test_post_single_object(client, normalized_findings):
    response = client.post("/findings", json=normalized_findings[0].model_dump(mode="json"))
    assert response.status_code == 201
    assert response.json()["created"] == 1


def test_post_twice_reports_duplicates(client, normalized_findings):
    client.post("/findings", json=_payload(normalized_findings))
    again = client.post("/findings", json=_payload(normalized_findings)).json()
    assert again["created"] == 0 and again["duplicates"] == 9
    assert client.get("/summary").json()["total"] == 9


def test_get_by_id_and_404(client, normalized_findings):
    client.post("/findings", json=_payload(normalized_findings))
    target = normalized_findings[0]
    found = client.get(f"/findings/{target.id}")
    assert found.status_code == 200
    assert found.json()["rule_id"] == target.rule_id
    missing = client.get("/findings/nope")
    assert missing.status_code == 404
    assert "not found" in missing.json()["detail"]


def test_filters(client, normalized_findings):
    client.post("/findings", json=_payload(normalized_findings))
    assert len(client.get("/findings", params={"severity": "HIGH"}).json()) == 5
    assert len(client.get("/findings", params={"scanner": "Gitleaks"}).json()) == 1
    assert client.get("/findings", params={"severity": "BOGUS"}).status_code == 422


def test_summary(client, normalized_findings):
    assert client.get("/summary").json() == {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    client.post("/findings", json=_payload(normalized_findings))
    assert client.get("/summary").json() == {"total": 9, "critical": 2, "high": 5, "medium": 1, "low": 1}


def test_invalid_payload_is_rejected(client):
    bad = {"id": "x", "scanner": "Semgrep", "finding_type": "t", "title": "t", "severity": "URGENT"}
    assert client.post("/findings", json=bad).status_code == 422
    assert client.post("/findings", json={"scanner": "Semgrep"}).status_code == 422
    assert client.get("/summary").json()["total"] == 0
