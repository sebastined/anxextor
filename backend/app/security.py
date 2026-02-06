from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse


class TargetValidationError(ValueError):
    pass


def normalize_url(target: str) -> Tuple[str, str, str, Optional[str]]:
    target = target.strip()
    if not target:
        raise TargetValidationError("URL is required.")

    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError("Only http and https URLs are allowed.")

    if not parsed.hostname:
        raise TargetValidationError("URL must include a hostname.")

    hostname = parsed.hostname
    wildcard_base = None
    if hostname.startswith("*."):
        wildcard_base = hostname[2:]
        if not wildcard_base:
            raise TargetValidationError("Wildcard hostname is invalid.")

    return target, hostname, parsed.scheme, wildcard_base


def resolve_ips(hostname: str) -> List[str]:
    ip_addresses = set()
    for result in socket.getaddrinfo(hostname, None):
        ip_addresses.add(result[4][0])
    return sorted(ip_addresses)


def is_public_ip(ip_value: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_value)
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_reserved
    )


def validate_public_target(hostname: str) -> None:
    ip_addresses = resolve_ips(hostname)
    if not ip_addresses:
        raise TargetValidationError("Hostname did not resolve to any IPs.")

    for ip_addr in ip_addresses:
        if not is_public_ip(ip_addr):
            raise TargetValidationError(
                "Target resolves to a non-public IP and is blocked for safety."
            )
