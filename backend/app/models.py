from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(
        ..., description="Target URL or hostname", examples=["https://example.com"]
    )


class BatchScanRequest(BaseModel):
    targets: List[str] = Field(
        ..., description="List of target URLs or hostnames", min_length=1
    )


class ScanFinding(BaseModel):
    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    reference_url: Optional[str] = None


class ScanResult(BaseModel):
    target: str
    final_url: str
    status_code: Optional[int]
    score: int
    grade: str
    findings: List[ScanFinding]
    headers: Dict[str, str]
    tls: Optional[Dict[str, Any]]
    dns: Dict[str, Any]
    timing_ms: int

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "target": "https://example.com",
                    "final_url": "https://example.com/",
                    "status_code": 200,
                    "score": 85,
                    "grade": "B",
                    "findings": [
                        {
                            "id": "missing_csp",
                            "title": "Missing Content-Security-Policy",
                            "severity": "high",
                            "description": "CSP is not present, increasing XSS risk.",
                            "recommendation": "Implement Content-Security-Policy with restrictive directives to prevent XSS attacks. Start with 'default-src \'self\'' and explicitly allow trusted origins.",
                            "cve": "CWE-79",
                            "cvss_score": 6.1,
                            "reference_url": "https://cwe.mitre.org/data/definitions/79.html",
                        }
                    ],
                    "headers": {"content-type": "text/html"},
                    "tls": {
                        "protocol": "TLSv1.3",
                        "cipher": "TLS_AES_128_GCM_SHA256",
                        "days_until_expiry": 120,
                    },
                    "dns": {"spf": True, "dmarc": True, "caa": False, "dnssec": False},
                    "timing_ms": 412,
                }
            ]
        }
    }


class BatchScanError(BaseModel):
    target: str
    error: str


class BatchScanResult(BaseModel):
    results: List[ScanResult]
    errors: List[BatchScanError]


class FeedbackRequest(BaseModel):
    rating: str = Field(..., description="Feedback rating", examples=["up", "down"])
    page: Optional[str] = Field(None, description="Page where feedback was given")
