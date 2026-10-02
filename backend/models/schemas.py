"""Pydantic request/response models for the API."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from normalizer.schema import NormalizedFinding


class FindingIn(NormalizedFinding):
    """Body of POST /findings: exactly the normalized schema."""


class FindingOut(NormalizedFinding):
    model_config = ConfigDict(from_attributes=True)


class IngestResult(BaseModel):
    received: int
    created: int
    duplicates: int
    created_ids: list[str]


class Summary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


class Health(BaseModel):
    status: str
    database: str
    knowledge_chunks: int | None = None
