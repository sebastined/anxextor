from __future__ import annotations

import os

from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Settings:
    api_key: Optional[str]
    rate_limit_per_minute: int
    http_timeout_seconds: float
    http_retries: int
    log_level: str
    batch_max_targets: int
    supabase_url: Optional[str]
    supabase_service_key: Optional[str]
    ipinfo_token: Optional[str]
    fingerprintjs_public_key: Optional[str]
    fingerprintjs_region: Optional[str]
    ip_encryption_key: Optional[str]
    ip_hash_salt: Optional[str]
    visitor_tracking_enabled: bool


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_log_level(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().upper()
    return value if value else default


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


load_dotenv()

settings = Settings(
    api_key=os.getenv("ANXEXTOR_API_KEY"),
    rate_limit_per_minute=_get_int("ANXEXTOR_RATE_LIMIT_PER_MINUTE", 30),
    http_timeout_seconds=_get_float("ANXEXTOR_HTTP_TIMEOUT_SECONDS", 10.0),
    http_retries=_get_int("ANXEXTOR_HTTP_RETRIES", 2),
    log_level=_get_log_level("ANXEXTOR_LOG_LEVEL", "INFO"),
    batch_max_targets=_get_int("ANXEXTOR_BATCH_MAX_TARGETS", 5),
    supabase_url=os.getenv("ANXEXTOR_SUPABASE_URL"),
    supabase_service_key=os.getenv("ANXEXTOR_SUPABASE_SERVICE_KEY"),
    ipinfo_token=os.getenv("ANXEXTOR_IPINFO_TOKEN"),
    fingerprintjs_public_key=os.getenv("ANXEXTOR_FINGERPRINTJS_PUBLIC_KEY"),
    fingerprintjs_region=os.getenv("ANXEXTOR_FINGERPRINTJS_REGION"),
    ip_encryption_key=os.getenv("ANXEXTOR_IP_ENCRYPTION_KEY"),
    ip_hash_salt=os.getenv("ANXEXTOR_IP_HASH_SALT"),
    visitor_tracking_enabled=_get_bool("ANXEXTOR_VISITOR_TRACKING_ENABLED", True),
)
