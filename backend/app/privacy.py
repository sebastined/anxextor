from __future__ import annotations

import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet

from .config import settings

logger = logging.getLogger("anxextor.privacy")


def _get_fernet() -> Optional[Fernet]:
    if not settings.ip_encryption_key:
        return None
    try:
        return Fernet(settings.ip_encryption_key)
    except Exception:
        logger.warning("Invalid IP encryption key format")
        return None


def hash_ip(ip_value: str) -> str:
    salt = settings.ip_hash_salt or ""
    digest = hashlib.sha256(f"{salt}:{ip_value}".encode("utf-8")).hexdigest()
    return digest


def encrypt_ip(ip_value: str) -> Optional[str]:
    fernet = _get_fernet()
    if not fernet:
        return None
    return fernet.encrypt(ip_value.encode("utf-8")).decode("utf-8")
