from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.models import Summary
from backend.services import finding_service
from database import get_db

router = APIRouter(tags=["summary"])


@router.get("/summary", response_model=Summary)
def get_summary(db: Session = Depends(get_db)):
    return finding_service.get_summary(db)
