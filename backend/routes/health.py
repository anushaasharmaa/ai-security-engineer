from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from backend.models import Health
from database import KnowledgeChunk, check_connection, new_session

router = APIRouter(tags=["health"])


@router.get("/health", response_model=Health)
def health():
    if not check_connection():
        return JSONResponse(status_code=503, content={"status": "degraded", "database": "unreachable"})
    with new_session() as db:
        chunks = db.execute(select(func.count()).select_from(KnowledgeChunk)).scalar_one()
    return Health(status="ok", database="ok", knowledge_chunks=chunks)
