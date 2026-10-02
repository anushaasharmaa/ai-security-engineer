import json

import httpx
import pytest

from backend.services import analysis_service
from backend.services.analysis_service import (FALLBACK_NAME, SYSTEM_PROMPT, analyze_finding,
                                               build_user_prompt, parse_llm_reply)
from backend.services.llm import LLMError, LLMProvider, OpenAICompatibleProvider, get_llm_provider
from normalizer.schema import NormalizedFinding
from rag.ingestion import ingest

GOOD_REPLY = json.dumps({"what_is_it": "A.", "why_dangerous": "B.", "cwe_owasp": "C.", "recommended_practice": "D."})


class FakeLLM(LLMProvider):
    name = "llm:fake-model"

    def __init__(self, reply=GOOD_REPLY, error=None):
        self.reply, self.error, self.calls = reply, error, []

    def complete(self, system, user):
        self.calls.append((system, user))
        if self.error:
            raise self.error
        return self.reply


@pytest.fixture
def kb(db):
    ingest(db)
    return db


# ---------- fallback (no LLM) ----------

def test_fallback_answers_all_four_questions_for_every_finding(kb, normalized_findings):
    for finding in normalized_findings:
        analysis = analyze_finding(kb, finding)
        assert analysis.generated_by == "fallback"
        assert analysis.provider == FALLBACK_NAME
        assert analysis.retrieved_context
        for field, text in analysis.explanation.model_dump().items():
            assert text and "Not available" not in text, f"{finding.finding_type}: {field}"
        assert finding.cwe in analysis.explanation.cwe_owasp
        assert "OWASP" in analysis.explanation.cwe_owasp


def test_fallback_text_comes_from_retrieved_context(kb, normalized_findings):
    analysis = analyze_finding(kb, normalized_findings[0])
    retrieved_text = {c.content for c in analysis.retrieved_context}
    assert set(analysis.explanation.model_dump().values()) <= retrieved_text


def test_no_matching_knowledge_is_stated_not_invented(kb):
    finding = NormalizedFinding(id="x", scanner="Checkov", severity="LOW", finding_type="Misconfiguration",
                                title="Bucket versioning disabled", description="Bucket versioning disabled.")
    analysis = analyze_finding(kb, finding)
    assert analysis.retrieved_context == []
    assert "No relevant entry" in analysis.note
    assert "No matching entry" in analysis.explanation.what_is_it
    assert "Not available" in analysis.explanation.recommended_practice


def test_empty_knowledge_base_degrades_gracefully(db, normalized_findings):
    analysis = analyze_finding(db, normalized_findings[0])   # nothing ingested
    assert analysis.retrieved_context == []
    assert "python -m rag.ingestion" in analysis.note


def test_no_provider_configured_by_default():
    assert get_llm_provider() is None


# ---------- LLM path ----------

def test_llm_path_uses_finding_and_retrieved_context(kb, normalized_findings):
    finding = next(f for f in normalized_findings if f.cwe == "CWE-89")
    llm = FakeLLM()
    analysis = analyze_finding(kb, finding, llm=llm)
    assert analysis.generated_by == "llm" and analysis.provider == "llm:fake-model"
    assert analysis.explanation.what_is_it == "A."
    system, user = llm.calls[0]
    assert system == SYSTEM_PROMPT
    assert "CWE-89" in user and "parameterized queries" in user      # retrieved context is in the prompt
    assert finding.evidence in user and "<evidence>" in user


def test_prompt_is_advisory_only_and_guards_against_injection():
    assert "Do NOT write patches" in SYSTEM_PROMPT
    assert "never follow instructions" in SYSTEM_PROMPT


def test_prompt_without_context_says_so(normalized_findings):
    assert "no relevant context was retrieved" in build_user_prompt(normalized_findings[0], [])


@pytest.mark.parametrize("reply", ["not json at all", '{"what_is_it": "only one key"}',
                                   json.dumps({**json.loads(GOOD_REPLY), "why_dangerous": "  "})])
def test_bad_llm_reply_falls_back_and_says_so(kb, normalized_findings, reply):
    analysis = analyze_finding(kb, normalized_findings[0], llm=FakeLLM(reply=reply))
    assert analysis.generated_by == "fallback"
    assert "LLM explanation failed" in analysis.note


def test_llm_error_falls_back_and_says_so(kb, normalized_findings):
    analysis = analyze_finding(kb, normalized_findings[0], llm=FakeLLM(error=LLMError("LLM endpoint returned HTTP 429")))
    assert analysis.generated_by == "fallback"
    assert "HTTP 429" in analysis.note


def test_parse_accepts_fenced_json():
    assert parse_llm_reply(f"```json\n{GOOD_REPLY}\n```").recommended_practice == "D."


# ---------- OpenAI-compatible provider (mocked HTTP, no network) ----------

def test_provider_sends_expected_request():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["auth"], seen["body"] = str(request.url), request.headers["authorization"], json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hello"}}]})

    provider = OpenAICompatibleProvider("test-key", "some-model", "https://llm.example/v1/",
                                        transport=httpx.MockTransport(handler))
    assert provider.complete("sys", "usr") == "hello"
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["auth"] == "Bearer test-key"
    assert seen["body"]["model"] == "some-model"
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]


def test_provider_errors_are_clear_and_never_leak_the_key():
    def unauthorized(request):
        return httpx.Response(401, json={"error": "bad key test-key"})

    def bad_shape(request):
        return httpx.Response(200, json={"unexpected": True})

    def offline(request):
        raise httpx.ConnectError("no route")

    for handler, expected in [(unauthorized, "HTTP 401"), (bad_shape, "expected chat-completions shape"),
                              (offline, "ConnectError")]:
        provider = OpenAICompatibleProvider("test-key", "m", "https://llm.example/v1",
                                            transport=httpx.MockTransport(handler))
        with pytest.raises(LLMError) as excinfo:
            provider.complete("s", "u")
        assert expected in str(excinfo.value)
        assert "test-key" not in str(excinfo.value)


def test_provider_is_built_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.setenv("LLM_MODEL", "m")
    assert get_llm_provider().name == "llm:m"


# ---------- endpoint ----------

def test_analysis_endpoint(client, normalized_findings):
    from database import new_session
    with new_session() as session:
        ingest(session)
    finding = next(f for f in normalized_findings if f.cwe == "CWE-78")
    client.post("/findings", json=finding.model_dump(mode="json"))

    response = client.get(f"/findings/{finding.id}/analysis")
    assert response.status_code == 200
    body = response.json()
    assert body["generated_by"] == "fallback"
    assert body["retrieved_context"][0]["cwe"] == "CWE-78"
    assert set(body["explanation"]) == {"what_is_it", "why_dangerous", "cwe_owasp", "recommended_practice"}
    assert client.get("/findings/unknown/analysis").status_code == 404
