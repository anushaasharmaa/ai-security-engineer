from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.services import analysis_service, finding_service
from backend.services.analysis_service import Analysis
from database import get_db

router = APIRouter(prefix="/findings", tags=["analysis"])


@router.get("/{finding_id}/analysis", response_model=Analysis)
def get_analysis(finding_id: str, db: Session = Depends(get_db)):
    """Retrieved security context + advisory explanation for one finding.
    Computed on request (retrieval, then one LLM call or the extractive fallback)."""
    finding = finding_service.get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return analysis_service.analyze_finding(db, finding)
