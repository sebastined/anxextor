from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict

from fastapi import HTTPException, Request, status

from .config import settings


@dataclass
class RateLimitState:
    timestamps: Deque[float]


class RateLimiter:
    def __init__(self, window_seconds: int = 60, limit_per_minute: int | None = None) -> None:
        self.window_seconds = window_seconds
        self.limit_per_minute = (
            settings.rate_limit_per_minute if limit_per_minute is None else limit_per_minute
        )
        self._clients: Dict[str, RateLimitState] = defaultdict(
            lambda: RateLimitState(deque())
        )

    def _get_client_key(self, request: Request) -> str:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def check(self, request: Request) -> None:
        limit = self.limit_per_minute
        if limit <= 0:
            return

        now = time.monotonic()
        client_key = self._get_client_key(request)
        state = self._clients[client_key]

        while state.timestamps and now - state.timestamps[0] > self.window_seconds:
            state.timestamps.popleft()

        if len(state.timestamps) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded.",
            )

        state.timestamps.append(now)
