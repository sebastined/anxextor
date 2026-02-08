from __future__ import annotations

from typing import Dict, Optional

from .config import settings


def get_rest_base() -> Optional[str]:
    if not settings.supabase_url or not settings.supabase_service_key:
        return None
    return f"{settings.supabase_url.rstrip('/')}/rest/v1"


def get_rest_headers() -> Optional[Dict[str, str]]:
    if not settings.supabase_service_key:
        return None
    return {
        "apikey": settings.supabase_service_key,
        "authorization": f"Bearer {settings.supabase_service_key}",
        "content-type": "application/json",
    }
