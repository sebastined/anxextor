from __future__ import annotations

import logging
import time
from pathlib import Path
from uuid import uuid4
import asyncio

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import BatchScanRequest, BatchScanResult, FeedbackRequest, ScanRequest, ScanResult
from .scanner import safe_scan
from .auth import require_api_key
from .rate_limit import RateLimiter
from .config import settings
from .visitors import track_visit
from .feedback import get_feedback_summary, record_feedback
from .pdf_generator import generate_pdf_report

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
        "script-src 'self' https://cdn.jsdelivr.net https://fpjscdn.net;",
        "style-src 'self' https://fonts.googleapis.com;",
        "font-src 'self' https://fonts.gstatic.com;",
        "img-src 'self' data:;",
        "connect-src 'self' https://api.fpjs.io https://eu.api.fpjs.io https://ap.api.fpjs.io https://fpjscdn.net https://cdn.jsdelivr.net;",
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

    fingerprint_id = request.headers.get("x-fingerprint-id", "").strip()
    client_ip = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
        or (request.client.host if request.client else "")
    )
    skip_paths = {
        "/health",
        "/api/config",
        "/api/visitor",
        "/api/scan",
        "/api/scan/batch",
        "/api/feedback",
    }
    if fingerprint_id and client_ip and request.url.path not in skip_paths:
        asyncio.create_task(asyncio.to_thread(track_visit, fingerprint_id, client_ip))
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


@app.get("/api/config")
async def client_config() -> dict:
    return {
        "fingerprint_public_key": settings.fingerprintjs_public_key,
        "fingerprint_region": settings.fingerprintjs_region,
        "visitor_tracking_enabled": settings.visitor_tracking_enabled,
    }


@app.post("/api/visitor")
async def visitor_snapshot(request: Request) -> dict:
    fingerprint_id = request.headers.get("x-fingerprint-id", "").strip()
    if not fingerprint_id:
        raise HTTPException(status_code=400, detail="Fingerprint is required")
    client_ip = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
        or (request.client.host if request.client else "")
    )
    if not client_ip:
        raise HTTPException(status_code=400, detail="Client IP not found")

    snapshot = await asyncio.to_thread(track_visit, fingerprint_id, client_ip)
    return {"enabled": bool(snapshot), "snapshot": snapshot.to_dict() if snapshot else None}


@app.post("/api/feedback")
async def feedback_submit(payload: FeedbackRequest, request: Request) -> dict:
    fingerprint_id = request.headers.get("x-fingerprint-id", "").strip()
    if not fingerprint_id:
        raise HTTPException(status_code=400, detail="Fingerprint is required")
    client_ip = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
        or (request.client.host if request.client else "")
    )
    if not client_ip:
        raise HTTPException(status_code=400, detail="Client IP not found")

    user_agent = request.headers.get("user-agent")
    success = await asyncio.to_thread(
        record_feedback,
        fingerprint_id,
        client_ip,
        payload.rating,
        user_agent,
        payload.page,
    )
    if not success:
        raise HTTPException(status_code=400, detail="Feedback not recorded")
    summary = await asyncio.to_thread(get_feedback_summary, fingerprint_id, payload.page)
    return {"status": "ok", "summary": summary}


@app.get("/api/feedback/summary")
async def feedback_summary(request: Request, page: str | None = None) -> dict:
    fingerprint_id = request.headers.get("x-fingerprint-id", "").strip()
    if not fingerprint_id:
        raise HTTPException(status_code=400, detail="Fingerprint is required")
    summary = await asyncio.to_thread(get_feedback_summary, fingerprint_id, page)
    return {"summary": summary}


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
    fingerprint_id = request.headers.get("x-fingerprint-id", "").strip()
    client_ip = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
        or (request.client.host if request.client else "")
    )
    if fingerprint_id and client_ip:
        asyncio.create_task(
            asyncio.to_thread(track_visit, fingerprint_id, client_ip, "scan")
        )
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

    fingerprint_id = request.headers.get("x-fingerprint-id", "").strip()
    client_ip = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
        or (request.client.host if request.client else "")
    )
    if fingerprint_id and client_ip:
        asyncio.create_task(
            asyncio.to_thread(track_visit, fingerprint_id, client_ip, "scan")
        )

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


@app.post(
    "/api/export-pdf",
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
    },
)
async def export_pdf_endpoint(payload: ScanResult, request: Request) -> Response:
    require_api_key(request)
    try:
        pdf_bytes = await asyncio.to_thread(generate_pdf_report, payload.model_dump())
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=security-assessment.pdf"},
        )
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        raise HTTPException(status_code=400, detail=f"PDF generation failed: {str(e)}")
