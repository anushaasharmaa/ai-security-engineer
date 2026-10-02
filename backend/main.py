"""FastAPI application.

    uvicorn backend.main:app --reload
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from backend.routes import analysis, findings, health, summary
from database import init_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # raises a clear DatabaseConfigError if PostgreSQL is not reachable
    yield


app = FastAPI(
    title="AI-Powered Security Engineer for CI/CD",
    description="Midterm prototype: stores normalized scanner findings and serves "
                "retrieved security context with an advisory explanation.",
    version="0.5.0-midterm",
    lifespan=lifespan,
)


@app.exception_handler(OperationalError)
async def database_unavailable(request: Request, exc: OperationalError):
    return JSONResponse(status_code=503, content={"detail": "Database is unavailable. Is PostgreSQL running?"})


app.include_router(health.router)
app.include_router(findings.router)
app.include_router(analysis.router)
app.include_router(summary.router)
