#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.scanner import safe_scan  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/scan_demo.py <url>")
        return 1

    target = sys.argv[1]
    result, error = safe_scan(target)
    if error:
        print(f"Error: {error}")
        return 1

    print(json.dumps(result.model_dump(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
