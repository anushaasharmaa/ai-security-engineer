"""
Knowledge base -> chunks -> embeddings -> pgvector.

    python -m rag.ingestion

Idempotent: the knowledge_chunks table is replaced on every run.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from database import DatabaseConfigError, KnowledgeChunk, init_db, new_session
from rag.embeddings import Embedder, EmbeddingError, get_embedder

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge_base"
MAX_CHUNK_CHARS = 1200
_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass
class Chunk:
    doc_id: str
    title: str
    section: str
    cwe: str | None
    owasp: str | None
    source: str | None
    content: str

    def text_for_embedding(self) -> str:
        # Title, CWE and section are embedded with the body so that each chunk
        # is understandable (and retrievable) on its own.
        return f"{self.title} {self.cwe or ''} {self.section}. {self.content}"


def parse_document(path: Path) -> tuple[dict[str, str], str] | None:
    """Return (metadata, body). Files without front matter (e.g. README) are skipped."""
    text = path.read_text(encoding="utf-8")
    match = _FRONT_MATTER_RE.match(text)
    if not match:
        return None
    metadata = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip().lower()] = value.strip()
    if "title" not in metadata:
        raise ValueError(f"{path.name}: front matter needs a 'title'")
    return metadata, text[match.end():]


def _split_long(text: str, limit: int) -> list[str]:
    """Pack paragraphs (then sentences) into pieces of at most `limit` characters."""
    if len(text) <= limit:
        return [text]
    units = [p.strip() for p in text.split("\n\n") if p.strip()]
    if len(units) == 1:
        units = re.split(r"(?<=[.!?])\s+", text)
    pieces, current = [], ""
    for unit in units:
        if current and len(current) + len(unit) + 1 > limit:
            pieces.append(current)
            current = unit
        else:
            current = f"{current} {unit}".strip()
    if current:
        pieces.append(current)
    return pieces


def chunk_document(path: Path) -> list[Chunk]:
    parsed = parse_document(path)
    if parsed is None:
        return []
    metadata, body = parsed
    chunks: list[Chunk] = []
    # One chunk per "## section" (split further only if a section is very long).
    for block in re.split(r"^##\s+", body, flags=re.MULTILINE):
        block = block.strip()
        if not block:
            continue
        heading, _, content = block.partition("\n")
        content = " ".join(content.split())
        if not content:
            continue
        for piece in _split_long(content, MAX_CHUNK_CHARS):
            chunks.append(Chunk(
                doc_id=path.stem, title=metadata["title"], section=heading.strip(),
                cwe=(metadata.get("cwe") or "").upper() or None,
                owasp=metadata.get("owasp") or None, source=metadata.get("source") or None,
                content=piece,
            ))
    return chunks


def load_chunks(directory: Path = KNOWLEDGE_DIR) -> list[Chunk]:
    if not directory.is_dir():
        raise FileNotFoundError(f"Knowledge base directory not found: {directory}")
    chunks: list[Chunk] = []
    for path in sorted(directory.glob("*.md")):
        chunks.extend(chunk_document(path))
    return chunks


def ingest(db: Session, directory: Path = KNOWLEDGE_DIR, embedder: Embedder | None = None) -> int:
    """Replace the stored knowledge base with the documents in `directory`."""
    embedder = embedder or get_embedder()
    chunks = load_chunks(directory)
    if not chunks:
        raise ValueError(f"No knowledge documents with front matter found in {directory}")
    vectors = embedder.embed([c.text_for_embedding() for c in chunks])
    db.execute(delete(KnowledgeChunk))
    db.add_all(
        KnowledgeChunk(doc_id=c.doc_id, title=c.title, section=c.section, cwe=c.cwe, owasp=c.owasp,
                       source=c.source, content=c.content, embedder=embedder.name, embedding=v)
        for c, v in zip(chunks, vectors)
    )
    db.commit()
    return len(chunks)


def main() -> int:
    try:
        init_db()
        embedder = get_embedder()
        with new_session() as db:
            count = ingest(db, embedder=embedder)
    except (DatabaseConfigError, EmbeddingError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    docs = len({c.doc_id for c in load_chunks()})
    print(f"Ingested {count} chunks from {docs} documents using embedder '{embedder.name}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
