from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.models import FindingIn, FindingOut, IngestResult
from backend.services import finding_service
from database import get_db
from normalizer.schema import Severity

router = APIRouter(prefix="/findings", tags=["findings"])


@router.post("", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
def post_findings(payload: FindingIn | list[FindingIn], db: Session = Depends(get_db)) -> IngestResult:
    """Store one normalized finding or a list of them. Already-known IDs are ignored."""
    findings = payload if isinstance(payload, list) else [payload]
    created = finding_service.create_findings(db, findings)
    return IngestResult(received=len(findings), created=len(created),
                        duplicates=len(findings) - len(created), created_ids=created)


@router.get("", response_model=list[FindingOut])
def get_findings(
    severity: Severity | None = None,
    scanner: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return finding_service.list_findings(db, severity=severity, scanner=scanner, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = finding_service.get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return finding
