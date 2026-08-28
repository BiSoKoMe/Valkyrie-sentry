#!/usr/bin/env python3
"""Native-messaging relay for Valkyrie's browser context extension.

The extension cannot read the loopback token. This host reads the local secret
and forwards structured messages to the engine. It logs nothing and retains no
browser data when the engine is unavailable.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path


MAX_MESSAGE_BYTES = 16 * 1024


def _read() -> dict | None:
    raw = sys.stdin.buffer.read(4)
    if len(raw) != 4:
        return None
    length = struct.unpack("<I", raw)[0]
    if not 0 < length <= MAX_MESSAGE_BYTES:
        return None
    try:
        value = json.loads(sys.stdin.buffer.read(length).decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _write(value: dict) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(payload)) + payload)
    sys.stdout.buffer.flush()


def _forward(endpoint: str, token_path: Path, event: dict) -> bool:
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    request = urllib.request.Request(
        endpoint, data=json.dumps(event).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "X-Valkyrie-Browser-Token": token},
    )
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            return response.status == 202
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="http://127.0.0.1:8080/api/browser/events")
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()
    while (event := _read()) is not None:
        _write({"accepted": _forward(args.endpoint, Path(args.token_file), event)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
