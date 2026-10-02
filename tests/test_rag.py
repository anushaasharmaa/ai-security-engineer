import math
from pathlib import Path

import pytest

from database import EMBEDDING_DIM, KnowledgeChunk
from normalizer.schema import NormalizedFinding
from rag.embeddings import EmbeddingError, HashingEmbedder, _build, get_embedder
from rag.ingestion import KNOWLEDGE_DIR, chunk_document, ingest, load_chunks
from rag.retrieval import RetrievalError, build_query, retrieve_for_finding, retrieve_for_text

REQUIRED_TOPICS = {"CWE-89", "CWE-79", "CWE-798", "CWE-78"}


# ---------- embeddings (no database) ----------

def test_hashing_embedder_is_deterministic_and_normalized():
    embedder = HashingEmbedder()
    first, second = embedder.embed_one("SQL injection in login query"), embedder.embed_one("SQL injection in login query")
    assert first == second
    assert len(first) == EMBEDDING_DIM
    assert math.isclose(sum(v * v for v in first), 1.0, rel_tol=1e-9)


def test_similar_text_scores_higher_than_unrelated_text():
    embedder = HashingEmbedder()
    query, related, unrelated = embedder.embed([
        "SQL query built with string concatenation",
        "Use parameterized queries instead of building the SQL string by concatenation",
        "Encode output for its context and set a Content Security Policy",
    ])
    dot = lambda a, b: sum(x * y for x, y in zip(a, b))
    assert dot(query, related) > dot(query, unrelated)


def test_empty_text_gives_zero_vector():
    assert HashingEmbedder().embed_one("") == [0.0] * EMBEDDING_DIM


def test_default_provider_is_hash_and_unknown_provider_fails():
    assert isinstance(get_embedder(), HashingEmbedder)
    with pytest.raises(EmbeddingError, match="Unknown EMBEDDING_PROVIDER"):
        _build("word2vec", "x")


# ---------- chunking (no database) ----------

def test_knowledge_base_covers_required_topics():
    chunks = load_chunks()
    assert REQUIRED_TOPICS <= {c.cwe for c in chunks}
    assert all(c.content and c.section and c.title and c.source for c in chunks)


def test_each_document_is_chunked_by_section():
    chunks = chunk_document(KNOWLEDGE_DIR / "cwe-89-sql-injection.md")
    assert [c.section for c in chunks] == ["What it is", "Why it is dangerous",
                                           "CWE and OWASP mapping", "Secure coding practice"]
    assert {c.cwe for c in chunks} == {"CWE-89"}
    assert not any("##" in c.content for c in chunks)


def test_files_without_front_matter_are_skipped():
    assert chunk_document(KNOWLEDGE_DIR / "README.md") == []


def test_long_sections_are_split(tmp_path: Path):
    doc = tmp_path / "long.md"
    doc.write_text("---\ntitle: Long\ncwe: CWE-1\n---\n\n## Section\n" + ("A sentence about security. " * 200))
    chunks = chunk_document(doc)
    assert len(chunks) > 1
    assert all(len(c.content) <= 1200 for c in chunks)


# ---------- ingestion + retrieval (PostgreSQL / pgvector) ----------

@pytest.fixture
def kb(db):
    count = ingest(db)
    return db, count


def test_ingestion_stores_chunks_with_vectors_and_is_idempotent(kb):
    db, count = kb
    assert count == len(load_chunks()) == db.query(KnowledgeChunk).count()
    row = db.query(KnowledgeChunk).first()
    assert len(row.embedding) == EMBEDDING_DIM
    assert row.embedder == HashingEmbedder.name
    assert ingest(db) == count                      # second run replaces, never duplicates
    assert db.query(KnowledgeChunk).count() == count


def test_every_real_finding_retrieves_its_own_cwe_document(kb, normalized_findings):
    db, _ = kb
    for finding in normalized_findings:
        results = retrieve_for_finding(db, finding)
        assert results, f"no context for {finding.finding_type}"
        assert all(r.cwe == finding.cwe and r.match_type == "cwe" for r in results), finding.finding_type
        similarities = [r.similarity for r in results]
        assert similarities == sorted(similarities, reverse=True)


def test_vector_search_alone_finds_the_right_document(kb, normalized_findings):
    """Remove the CWE so only pgvector similarity can find the document."""
    db, _ = kb
    for finding in normalized_findings:
        stripped = finding.model_copy(update={"cwe": None})
        assert "CWE-" not in build_query(stripped)
        results = retrieve_for_finding(db, stripped)
        assert results, f"nothing retrieved for {finding.finding_type}"
        assert results[0].cwe == finding.cwe, f"{finding.finding_type}: got {results[0].cwe}"
        assert results[0].match_type == "semantic"


def test_cwe_missing_from_knowledge_base_falls_back_to_similarity(kb):
    db, _ = kb
    finding = NormalizedFinding(
        id="x", scanner="Semgrep", severity="HIGH", cwe="CWE-564", finding_type="SQL Injection",
        title="Potential SQL Injection",
        description="SQL query is built with string concatenation and passed to execute()")
    results = retrieve_for_finding(db, finding)
    assert results and results[0].cwe == "CWE-89"
    assert {r.match_type for r in results} == {"semantic"}


def test_unrelated_query_returns_nothing(kb):
    db, _ = kb
    assert retrieve_for_text(db, "the weather is nice today") == []


def test_top_k_is_respected(kb, normalized_findings):
    db, _ = kb
    assert len(retrieve_for_finding(db, normalized_findings[0], top_k=2)) == 2


def test_empty_knowledge_base_is_a_clear_error(db):
    with pytest.raises(RetrievalError, match="python -m rag.ingestion"):
        retrieve_for_text(db, "sql injection")


def test_embedder_mismatch_is_detected(kb):
    db, _ = kb

    class OtherEmbedder(HashingEmbedder):
        name = "some-other-embedder"

    with pytest.raises(RetrievalError, match="Re-run"):
        retrieve_for_text(db, "sql injection", embedder=OtherEmbedder())
