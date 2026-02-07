from __future__ import annotations

import logging
import time
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import BatchScanRequest, BatchScanResult, ScanRequest, ScanResult
from .scanner import safe_scan
from .auth import require_api_key
from .rate_limit import RateLimiter
from .config import settings

ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = ROOT_DIR / "frontend"

log_level = (settings.log_level or "INFO").strip() or "INFO"
logging.basicConfig(level=log_level)

app = FastAPI(title="anxextor", version="0.1.0")
logger = logging.getLogger("anxextor")
limiter = RateLimiter(limit_per_minute=settings.rate_limit_per_minute)

DEFAULT_CSP = " ".join(
    [
        "default-src 'self';",
        "base-uri 'self';",
        "object-src 'none';",
        "frame-ancestors 'none';",
        "script-src 'self' https://cdn.jsdelivr.net;",
        "style-src 'self' https://fonts.googleapis.com;",
        "font-src 'self' https://fonts.gstatic.com;",
        "img-src 'self' data:;",
        "connect-src 'self';",
    ]
)
DEFAULT_PERMISSIONS_POLICY = (
    "accelerometer=(), autoplay=(), camera=(), geolocation=(), "
    "gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), "
    "usb=(), fullscreen=(self)"
)


def _apply_security_headers(response: Response, is_https: bool) -> None:
    response.headers.setdefault("Content-Security-Policy", DEFAULT_CSP)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", DEFAULT_PERMISSIONS_POLICY)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Embedder-Policy", "unsafe-none")
    response.headers.setdefault("Cache-Control", "no-store")

    if is_https:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )


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
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    is_https = request.url.scheme == "https" or forwarded_proto == "https"
    _apply_security_headers(response, is_https)
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
