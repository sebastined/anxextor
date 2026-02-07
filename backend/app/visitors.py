from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx
from cryptography.fernet import Fernet
from supabase import Client, create_client

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


def _get_supabase() -> Optional[Client]:
    if not settings.supabase_url or not settings.supabase_service_key:
        return None
    return create_client(settings.supabase_url, settings.supabase_service_key)


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
    client: Client,
    fingerprint_id: str,
    event_type: str,
    since: datetime,
) -> int:
    response = (
        client.table("visitor_events")
        .select("id", count="exact")
        .eq("fingerprint_id", fingerprint_id)
        .eq("event_type", event_type)
        .gte("created_at", since.isoformat())
        .execute()
    )
    count = getattr(response, "count", None)
    return int(count or 0)


def _window_counts(client: Client, fingerprint_id: str) -> Dict[str, int]:
    now = datetime.now(timezone.utc)
    return {
        label: _count_events(client, fingerprint_id, "visit", now - delta)
        for label, delta in WINDOWS.items()
    }


def track_visit(
    fingerprint_id: str,
    ip_value: str,
    event_type: str = "visit",
) -> Optional[VisitorSnapshot]:
    if not settings.visitor_tracking_enabled:
        return None

    client = _get_supabase()
    if not client:
        return None

    now = datetime.now(timezone.utc)
    ip_hash = _hash_ip(ip_value)
    encrypted_ip = _encrypt_ip(ip_value)
    ipinfo = _get_ipinfo(ip_value)

    country = ipinfo.get("country")
    city = ipinfo.get("city")
    behind_proxy = _privacy_flag(ipinfo)

    existing = (
        client.table("visitor_profiles")
        .select("visit_count, scan_count")
        .eq("fingerprint_id", fingerprint_id)
        .maybe_single()
        .execute()
        .data
    )
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

    client.table("visitor_profiles").upsert(
        profile_payload, on_conflict="fingerprint_id"
    ).execute()

    client.table("visitor_events").insert(
        {
            "fingerprint_id": fingerprint_id,
            "event_type": event_type,
            "created_at": now.isoformat(),
        }
    ).execute()

    visit_windows = _window_counts(client, fingerprint_id)

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
