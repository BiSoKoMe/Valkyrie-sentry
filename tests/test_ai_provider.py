#!/usr/bin/env python3
"""Vendor-neutral AI provider layer (valkyrie/edr/ai_provider.py).

Proves the real HTTP request/response handling of each provider dialect
deterministically — by stubbing httpx.post, so no network and no vendor SDK are
involved — plus provider selection and JSON extraction. Exit 0/non-zero.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import valkyrie.edr.ai_provider as ap

_FAILS: list = []
_REPLY = {"assessment": "ok", "confidence": "high", "likely_technique": "T1071",
          "recommended_action": {"action": "monitor_only", "target": "",
                                 "rationale": "watch"},
          "evidence": ["e1"]}


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILS.append(label)


class _Resp:
    def __init__(self, payload):
        self._p, self.status_code = payload, 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class _Capture:
    """Stub for httpx.post that records the request and returns a canned reply."""
    def __init__(self, payload):
        self.payload, self.url, self.headers, self.body = payload, "", {}, {}

    def __call__(self, url, headers=None, json=None, timeout=None):
        self.url, self.headers, self.body = url, headers or {}, json or {}
        return _Resp(self.payload)


def _with_env(**kw):
    """Set env vars for a sub-test; return a restore() thunk."""
    saved = {k: os.environ.get(k) for k in kw}
    for k, v in kw.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def main() -> int:
    print("\n=== AI provider layer (vendor-neutral) ===\n")
    if not ap._HTTPX:
        print("  httpx not installed — network providers are correctly unavailable.")
        _check("offline provider available() is False", not ap.OfflineProvider().available())
        return 0 if not _FAILS else 1

    real_post = ap.httpx.post

    # -- Anthropic dialect --------------------------------------------------
    print("[1] AnthropicProvider — Messages API shape + parse")
    cap = _Capture({"content": [{"type": "text", "text": json.dumps(_REPLY)}]})
    ap.httpx.post = cap
    try:
        p = ap.AnthropicProvider(api_key="test-key", model="claude-x")
        _check("available with key", p.available())
        out = p.analyze("SYS", "USER", {"required": []})
        _check("returns parsed dict", out == _REPLY)
        _check("hits /v1/messages", cap.url.endswith("/v1/messages"))
        _check("sends x-api-key header", cap.headers.get("x-api-key") == "test-key")
        _check("anthropic-version header set", "anthropic-version" in cap.headers)
        _check("system + user in body",
               cap.body.get("system") == "SYS"
               and cap.body["messages"][0]["content"] == "USER")
        _check("model honored", cap.body.get("model") == "claude-x")
    finally:
        ap.httpx.post = real_post

    # -- OpenAI dialect -----------------------------------------------------
    print("\n[2] OpenAIProvider — Chat Completions shape + parse")
    cap = _Capture({"choices": [{"message": {"content": json.dumps(_REPLY)}}]})
    ap.httpx.post = cap
    try:
        p = ap.OpenAIProvider(api_key="sk-test", model="gpt-x")
        out = p.analyze("SYS", "USER", {"required": []})
        _check("returns parsed dict", out == _REPLY)
        _check("hits /chat/completions", cap.url.endswith("/chat/completions"))
        _check("Bearer auth header", cap.headers.get("authorization") == "Bearer sk-test")
        _check("json_object response_format requested",
               cap.body.get("response_format", {}).get("type") == "json_object")
        _check("system+user messages", len(cap.body.get("messages", [])) == 2)
    finally:
        ap.httpx.post = real_post

    # -- Local provider (no key, OpenAI-compatible, on-box) -----------------
    print("\n[3] LocalProvider — available without a key, local base URL")
    lp = ap.LocalProvider()
    _check("available without any key", lp.available())
    _check("defaults to a localhost base URL", "localhost" in lp._base or "127.0.0.1" in lp._base)

    # -- JSON extraction tolerance -----------------------------------------
    print("\n[4] _extract_json tolerates fenced / prose-wrapped replies")
    _check("plain json", ap._extract_json('{"a":1}') == {"a": 1})
    _check("```json fence", ap._extract_json('```json\n{"a":1}\n```') == {"a": 1})
    _check("prose then object", ap._extract_json('Here:\n{"a":1}\nthanks') == {"a": 1})
    _check("garbage -> None", ap._extract_json("not json") is None)

    # -- Selection ----------------------------------------------------------
    print("\n[5] get_provider() selection + auto-detection")
    r = _with_env(VALKYRIE_AI_PROVIDER="openai", VALKYRIE_AI_KEY="k",
                  ANTHROPIC_API_KEY=None, OPENAI_API_KEY=None, VALKYRIE_AI_BASE_URL=None)
    try:
        _check("explicit VALKYRIE_AI_PROVIDER honored", ap.get_provider().name == "openai")
    finally:
        r()
    r = _with_env(VALKYRIE_AI_PROVIDER=None, ANTHROPIC_API_KEY="k",
                  VALKYRIE_AI_KEY=None, OPENAI_API_KEY=None, VALKYRIE_AI_BASE_URL=None)
    try:
        _check("ANTHROPIC_API_KEY auto-detects anthropic (backward compat)",
               ap.get_provider().name == "anthropic")
    finally:
        r()
    r = _with_env(VALKYRIE_AI_PROVIDER=None, ANTHROPIC_API_KEY=None,
                  VALKYRIE_AI_KEY=None, OPENAI_API_KEY=None, VALKYRIE_AI_BASE_URL=None)
    try:
        _check("nothing configured -> offline", ap.get_provider().name == "offline")
        _check("offline never available", not ap.get_provider().available())
    finally:
        r()

    print("\n" + "=" * 48)
    if _FAILS:
        print(f"FAILED: {len(_FAILS)} check(s)")
        for f in _FAILS:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
