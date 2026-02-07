from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx
from cryptography.fernet import Fernet

from .config import settings

logger = logging.getLogger("anxextor.visitors")

WINDOWS = {
    "5m": timedelta(minutes=5),
    "30m": timedelta(minutes=30),
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "1w": timedelta(weeks=1),
    "1mo": timedelta(days=30),
    "1y": timedelta(days=365),
}


@dataclass
class VisitorSnapshot:
    fingerprint_id: str
    ip: str
    country: Optional[str]
    city: Optional[str]
    behind_proxy: Optional[bool]
    visit_count: int
    scan_count: int
    last_visit_at: str
    visit_windows: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "ip": self.ip,
            "country": self.country,
            "city": self.city,
            "behind_proxy": self.behind_proxy,
            "visit_count": self.visit_count,
            "scan_count": self.scan_count,
            "last_visit_at": self.last_visit_at,
            "visit_windows": self.visit_windows,
        }


def _get_rest_base() -> Optional[str]:
    if not settings.supabase_url or not settings.supabase_service_key:
        return None
    return f"{settings.supabase_url.rstrip('/')}/rest/v1"


def _get_rest_headers() -> Optional[Dict[str, str]]:
    if not settings.supabase_service_key:
        return None
    return {
        "apikey": settings.supabase_service_key,
        "authorization": f"Bearer {settings.supabase_service_key}",
        "content-type": "application/json",
    }


def _get_fernet() -> Optional[Fernet]:
    if not settings.ip_encryption_key:
        return None
    try:
        return Fernet(settings.ip_encryption_key)
    except Exception:
        logger.warning("Invalid IP encryption key format")
        return None


def _hash_ip(ip_value: str) -> str:
    salt = settings.ip_hash_salt or ""
    digest = hashlib.sha256(f"{salt}:{ip_value}".encode("utf-8")).hexdigest()
    return digest


def _encrypt_ip(ip_value: str) -> Optional[str]:
    fernet = _get_fernet()
    if not fernet:
        return None
    return fernet.encrypt(ip_value.encode("utf-8")).decode("utf-8")


def _get_ipinfo(ip_value: str) -> Dict[str, Any]:
    if not settings.ipinfo_token:
        return {}
    try:
        response = httpx.get(
            f"https://ipinfo.io/{ip_value}/json",
            params={"token": settings.ipinfo_token},
            timeout=5.0,
        )
        if response.status_code != 200:
            return {}
        return response.json()
    except Exception:
        logger.exception("Failed to fetch ipinfo data")
        return {}


def _privacy_flag(data: Dict[str, Any]) -> Optional[bool]:
    privacy = data.get("privacy")
    if not isinstance(privacy, dict):
        return None
    return any(bool(privacy.get(key)) for key in ("vpn", "proxy", "tor", "hosting"))


def _count_events(
    rest_base: str,
    headers: Dict[str, str],
    fingerprint_id: str,
    event_type: str,
    since: datetime,
) -> int:
    params = {
        "select": "id",
        "fingerprint_id": f"eq.{fingerprint_id}",
        "event_type": f"eq.{event_type}",
        "created_at": f"gte.{since.isoformat()}",
    }
    try:
        response = httpx.get(
            f"{rest_base}/visitor_events",
            params=params,
            headers={**headers, "prefer": "count=exact"},
            timeout=5.0,
        )
    except Exception:
        logger.exception("Failed to count events")
        return 0

    content_range = response.headers.get("content-range") or ""
    if "/" in content_range:
        total = content_range.split("/")[-1]
        if total.isdigit():
            return int(total)
    return 0


def _window_counts(rest_base: str, headers: Dict[str, str], fingerprint_id: str) -> Dict[str, int]:
    now = datetime.now(timezone.utc)
    return {
        label: _count_events(rest_base, headers, fingerprint_id, "visit", now - delta)
        for label, delta in WINDOWS.items()
    }


def track_visit(
    fingerprint_id: str,
    ip_value: str,
    event_type: str = "visit",
) -> Optional[VisitorSnapshot]:
    if not settings.visitor_tracking_enabled:
        return None

    rest_base = _get_rest_base()
    headers = _get_rest_headers()
    if not rest_base or not headers:
        return None

    now = datetime.now(timezone.utc)
    ip_hash = _hash_ip(ip_value)
    encrypted_ip = _encrypt_ip(ip_value)
    ipinfo = _get_ipinfo(ip_value)

    country = ipinfo.get("country")
    city = ipinfo.get("city")
    behind_proxy = _privacy_flag(ipinfo)

    existing = None
    try:
        response = httpx.get(
            f"{rest_base}/visitor_profiles",
            params={
                "select": "visit_count,scan_count",
                "fingerprint_id": f"eq.{fingerprint_id}",
                "limit": 1,
            },
            headers=headers,
            timeout=5.0,
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and data:
                existing = data[0]
    except Exception:
        logger.exception("Failed to read visitor profile")

    visit_count = int(existing.get("visit_count", 0)) if existing else 0
    scan_count = int(existing.get("scan_count", 0)) if existing else 0

    if event_type == "visit":
        visit_count += 1
    elif event_type == "scan":
        scan_count += 1

    profile_payload = {
        "fingerprint_id": fingerprint_id,
        "ip_hash": ip_hash,
        "ip_encrypted": encrypted_ip,
        "last_ip": ip_value,
        "country": country,
        "city": city,
        "behind_proxy": behind_proxy,
        "visit_count": visit_count,
        "scan_count": scan_count,
        "last_visit_at": now.isoformat(),
    }

    try:
        httpx.post(
            f"{rest_base}/visitor_profiles",
            params={"on_conflict": "fingerprint_id"},
            headers={**headers, "prefer": "resolution=merge-duplicates"},
            json=profile_payload,
            timeout=5.0,
        )
    except Exception:
        logger.exception("Failed to upsert visitor profile")

    try:
        httpx.post(
            f"{rest_base}/visitor_events",
            headers=headers,
            json={
                "fingerprint_id": fingerprint_id,
                "event_type": event_type,
                "created_at": now.isoformat(),
            },
            timeout=5.0,
        )
    except Exception:
        logger.exception("Failed to insert visitor event")

    visit_windows = _window_counts(rest_base, headers, fingerprint_id)

    return VisitorSnapshot(
        fingerprint_id=fingerprint_id,
        ip=ip_value,
        country=country,
        city=city,
        behind_proxy=behind_proxy,
        visit_count=visit_count,
        scan_count=scan_count,
        last_visit_at=now.isoformat(),
        visit_windows=visit_windows,
    )
