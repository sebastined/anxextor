from __future__ import annotations

import os
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


settings = Settings(
    api_key=os.getenv("ANXEXTOR_API_KEY"),
    rate_limit_per_minute=_get_int("ANXEXTOR_RATE_LIMIT_PER_MINUTE", 30),
    http_timeout_seconds=_get_float("ANXEXTOR_HTTP_TIMEOUT_SECONDS", 10.0),
    http_retries=_get_int("ANXEXTOR_HTTP_RETRIES", 2),
    log_level=_get_log_level("ANXEXTOR_LOG_LEVEL", "INFO"),
    batch_max_targets=_get_int("ANXEXTOR_BATCH_MAX_TARGETS", 5),
)
