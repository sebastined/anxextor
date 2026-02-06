from __future__ import annotations

import logging
import time
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import BatchScanRequest, BatchScanResult, ScanRequest, ScanResult
from .scanner import safe_scan
from .auth import require_api_key
from .rate_limit import RateLimiter
from .config import settings

ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = ROOT_DIR / "frontend"

logging.basicConfig(level=settings.log_level)

app = FastAPI(title="anxextor", version="0.1.0")
logger = logging.getLogger("anxextor")
limiter = RateLimiter(limit_per_minute=settings.rate_limit_per_minute)

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid4()))
    start_time = time.monotonic()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception("Unhandled error", extra={"request_id": request_id})
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )

    duration_ms = int((time.monotonic() - start_time) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-ms"] = str(duration_ms)
    logger.info(
        "Request completed",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    return response


@app.get("/")
async def index() -> FileResponse:
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(index_path)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/api/scan",
    response_model=ScanResult,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        429: {"description": "Too many requests"},
    },
)
async def scan_endpoint(payload: ScanRequest, request: Request) -> ScanResult:
    require_api_key(request)
    limiter.check(request)
    result, error = safe_scan(payload.url)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return result


@app.post(
    "/api/scan/batch",
    response_model=BatchScanResult,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        413: {"description": "Too many targets"},
        429: {"description": "Too many requests"},
    },
)
async def scan_batch_endpoint(payload: BatchScanRequest, request: Request) -> BatchScanResult:
    require_api_key(request)
    limiter.check(request)

    if len(payload.targets) > settings.batch_max_targets:
        raise HTTPException(
            status_code=413,
            detail=f"Too many targets. Max {settings.batch_max_targets}.",
        )

    results = []
    errors = []

    for target in payload.targets:
        result, error = safe_scan(target)
        if error:
            errors.append({"target": target, "error": error})
        elif result:
            results.append(result)

    return BatchScanResult(results=results, errors=errors)
