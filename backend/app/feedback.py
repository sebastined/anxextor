from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

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
