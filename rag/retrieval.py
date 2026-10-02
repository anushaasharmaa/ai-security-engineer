"""
Finding -> relevant security knowledge.

Retrieval strategy (deliberately simple):
    1. Identify the weakness: use the finding's CWE if it has one.
    2. Embed a query built from the finding (type, CWE, title, description).
    3. If the CWE exists in the knowledge base, rank THAT document's chunks by
       cosine similarity (pgvector `<=>`).
    4. Fill any remaining slots with a similarity search over the whole
       knowledge base, keeping only chunks above the embedder's threshold.
       This is the only path for findings without a CWE or with a CWE that is
       not in the knowledge base.

Each result says which path produced it (`match_type`), so the dashboard never
presents a weak semantic guess as if it were an exact CWE match.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database import KnowledgeChunk
from rag.embeddings import Embedder, get_embedder

DEFAULT_TOP_K = 4


class RetrievalError(RuntimeError):
    pass


class RetrievedChunk(BaseModel):
    doc_id: str
    title: str
    section: str
    cwe: str | None
    owasp: str | None
    source: str | None
    content: str
    similarity: float
    match_type: str  # "cwe" (exact CWE match) or "semantic" (vector similarity only)


def build_query(finding: Any) -> str:
    """Text that represents the finding. Evidence (raw code) is left out on
    purpose: it adds noise, and it is untrusted input."""
    parts = [getattr(finding, name, None) for name in ("finding_type", "cwe", "title", "description")]
    return " ".join(str(p) for p in parts if p)


def _check_store(db: Session, embedder: Embedder) -> None:
    stored = db.execute(select(KnowledgeChunk.embedder, func.count()).group_by(KnowledgeChunk.embedder)).all()
    if not stored:
        raise RetrievalError("The knowledge base is empty. Run: python -m rag.ingestion")
    names = {name for name, _ in stored}
    if names != {embedder.name}:
        raise RetrievalError(
            f"Knowledge base was embedded with {sorted(names)} but the current embedder is "
            f"'{embedder.name}'. Re-run: python -m rag.ingestion"
        )


def _search(db: Session, vector: list[float], limit: int, *, cwe: str | None = None,
            exclude_ids: set[int] | None = None) -> list[tuple[KnowledgeChunk, float]]:
    distance = KnowledgeChunk.embedding.cosine_distance(vector).label("distance")
    stmt = select(KnowledgeChunk, distance)
    if cwe:
        stmt = stmt.where(KnowledgeChunk.cwe == cwe)
    if exclude_ids:
        stmt = stmt.where(KnowledgeChunk.id.notin_(exclude_ids))
    rows = db.execute(stmt.order_by(distance).limit(limit)).all()
    return [(chunk, 1.0 - float(dist)) for chunk, dist in rows]


def _to_result(chunk: KnowledgeChunk, similarity: float, match_type: str) -> RetrievedChunk:
    return RetrievedChunk(doc_id=chunk.doc_id, title=chunk.title, section=chunk.section, cwe=chunk.cwe,
                          owasp=chunk.owasp, source=chunk.source, content=chunk.content,
                          similarity=round(similarity, 4), match_type=match_type)


def retrieve_for_text(db: Session, query: str, *, cwe: str | None = None, top_k: int = DEFAULT_TOP_K,
                      embedder: Embedder | None = None) -> list[RetrievedChunk]:
    embedder = embedder or get_embedder()
    _check_store(db, embedder)
    vector = embedder.embed_one(query)

    results: list[RetrievedChunk] = []
    seen: set[int] = set()
    if cwe:
        for chunk, similarity in _search(db, vector, top_k, cwe=cwe.upper()):
            results.append(_to_result(chunk, similarity, "cwe"))
            seen.add(chunk.id)
    if len(results) < top_k:
        for chunk, similarity in _search(db, vector, top_k - len(results), exclude_ids=seen):
            if similarity >= embedder.min_similarity:
                results.append(_to_result(chunk, similarity, "semantic"))
    return results


def retrieve_for_finding(db: Session, finding: Any, *, top_k: int = DEFAULT_TOP_K,
                         embedder: Embedder | None = None) -> list[RetrievedChunk]:
    return retrieve_for_text(db, build_query(finding), cwe=getattr(finding, "cwe", None),
                             top_k=top_k, embedder=embedder)
