from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Optional

import httpx

from .privacy import encrypt_ip, hash_ip
from .supabase_utils import get_rest_base, get_rest_headers

logger = logging.getLogger("anxextor.feedback")

ALLOWED_RATINGS = {"up", "down"}


def record_feedback(
    fingerprint_id: str,
    ip_value: str,
    rating: str,
    user_agent: Optional[str],
    page: Optional[str],
) -> bool:
    if rating not in ALLOWED_RATINGS:
        return False

    rest_base = get_rest_base()
    headers = get_rest_headers()
    if not rest_base or not headers:
        return False

    now = datetime.now(timezone.utc)
    payload = {
        "fingerprint_id": fingerprint_id,
        "ip_hash": hash_ip(ip_value),
        "ip_encrypted": encrypt_ip(ip_value),
        "rating": rating,
        "user_agent": user_agent,
        "page": page,
        "created_at": now.isoformat(),
    }

    try:
        # Record every vote as a new event
        response = httpx.post(
            f"{rest_base}/feedback_events",
            headers=headers,
            json=payload,
            timeout=5.0,
        )
        return response.status_code in {200, 201}
    except Exception:
        logger.exception("Failed to record feedback")
        return False


def get_feedback_summary(
    fingerprint_id: str,
    page: Optional[str],
) -> Optional[Dict[str, Optional[int]]]:
    rest_base = get_rest_base()
    headers = get_rest_headers()
    if not rest_base or not headers:
        return None

    page_value = page or "/"
    params = {"page": f"eq.{page_value}"}

    def _count(rating: str) -> int:
        try:
            response = httpx.get(
                f"{rest_base}/feedback_events",
                params={**params, "rating": f"eq.{rating}", "select": "id"},
                headers={**headers, "prefer": "count=exact"},
                timeout=5.0,
            )
        except Exception:
            logger.exception("Failed to count feedback")
            return 0

        content_range = response.headers.get("content-range") or ""
        if "/" in content_range:
            total = content_range.split("/")[-1]
            if total.isdigit():
                return int(total)
        return 0

    user_rating = None
    try:
        # Get user's preference from the prefs table
        response = httpx.get(
            f"{rest_base}/feedback_user_prefs",
            params={
                "page": f"eq.{page_value}",
                "fingerprint_id": f"eq.{fingerprint_id}",
                "select": "rating",
                "limit": 1,
            },
            headers=headers,
            timeout=5.0,
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and data:
                user_rating = data[0].get("rating")
    except Exception:
        logger.exception("Failed to fetch user feedback")

    return {
        "up": _count("up"),
        "down": _count("down"),
        "user_rating": user_rating,
    }
