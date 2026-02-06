from __future__ import annotations

from fastapi import HTTPException, Request, status

from .config import settings


def require_api_key(request: Request) -> None:
    if not settings.api_key:
        return

    provided = request.headers.get("x-api-key")
    if not provided or provided != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
        )
