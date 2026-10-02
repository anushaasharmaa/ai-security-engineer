"""SQLAlchemy ORM models. Columns of `findings` mirror normalizer.schema.NormalizedFinding."""
from __future__ import annotations

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Fixed vector size. Both embedders in rag/embeddings.py produce this dimension
# (it is the output size of all-MiniLM-L6-v2), so switching provider needs no migration.
EMBEDDING_DIM = 384


class Base(DeclarativeBase):
    pass


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scanner: Mapped[str] = mapped_column(String(50), index=True)
    finding_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class KnowledgeChunk(Base):
    """One chunk of a security knowledge document plus its embedding (RAG store)."""
    __tablename__ = "knowledge_chunks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    doc_id: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(255))
    section: Mapped[str] = mapped_column(String(255), default="")
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    owasp: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text)
    embedder: Mapped[str] = mapped_column(String(100))
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIM))


Index("ix_knowledge_chunks_doc_section", KnowledgeChunk.doc_id, KnowledgeChunk.section)
