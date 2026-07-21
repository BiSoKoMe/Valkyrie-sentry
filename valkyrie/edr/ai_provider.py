"""Vendor-neutral LLM provider interface for the AI investigation assistant.

The investigation engine (``edr/investigate.py``) must never depend on a single
AI vendor. It talks only to the :class:`AIProvider` interface below; which
concrete backend answers is a runtime configuration choice:

    AIProvider (interface)
        ├── AnthropicProvider    (Claude / Anthropic Messages API)
        ├── OpenAIProvider       (OpenAI Chat Completions API)
        ├── LocalProvider        (any OpenAI-compatible local server —
        │                         Ollama, LM Studio, llama.cpp, vLLM …)
        └── OfflineProvider      (no backend; forces the offline analyst)

All network providers speak plain HTTP over ``httpx`` (already a Valkyrie
dependency) — there is **no vendor SDK dependency**. A provider is only
"available" when it has both a transport and whatever credential it needs, so a
missing key or missing ``httpx`` degrades cleanly to the offline analyst.

Selection (all optional; sensible auto-detection when unset):

  * ``VALKYRIE_AI_PROVIDER``  — ``anthropic`` | ``openai`` | ``local`` | ``offline``
  * ``VALKYRIE_AI_MODEL``     — model id (per-provider default otherwise)
  * ``VALKYRIE_AI_KEY``       — API key (generic)
  * ``VALKYRIE_AI_BASE_URL``  — override the endpoint (custom / local servers)

Backward compatible: ``ANTHROPIC_API_KEY`` and ``OPENAI_API_KEY`` are still read
as fall-backs for their respective providers, so existing deployments keep
working unchanged.

Privacy note: every network provider SENDS the compact incident facts to the
configured endpoint. That is why AI investigation is opt-in and off by default
(``config.EDR_AI_INVESTIGATION``). The ``local`` and ``offline`` providers keep
everything on-box.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Optional

try:
    import httpx
    _HTTPX = True
except ImportError:            # transport unavailable -> only OfflineProvider works
    _HTTPX = False

_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

class AIProvider(ABC):
    """A provider-independent LLM backend for evidence-grounded analysis."""

    #: short, stable id reported back as the report's ``analyst`` field.
    name: str = "offline"

    @abstractmethod
    def available(self) -> bool:
        """True only if this provider can actually be called right now."""

    @abstractmethod
    def analyze(self, system: str, user: str, schema: dict) -> Optional[dict]:
        """Return the model's structured JSON reply (a dict), or None.

        ``system``/``user`` are the prompts; ``schema`` is the JSON Schema the
        reply must conform to (providers that support server-side JSON mode use
        it; all providers also validate by parsing). Any failure — no transport,
        network error, unparseable reply — returns None so the caller falls back
        to the offline analyst. Never raises.
        """


def _extract_json(text: str) -> Optional[dict]:
    """Parse a model reply into a dict, tolerating ```json fences / prose."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1] if t.count("```") >= 2 else t.strip("`")
        if t.lstrip().lower().startswith("json"):
            t = t.lstrip()[4:]
    try:
        obj = json.loads(t)
    except (ValueError, TypeError):
        # last resort: the outermost {...} span
        i, j = t.find("{"), t.rfind("}")
        if i >= 0 and j > i:
            try:
                obj = json.loads(t[i:j + 1])
            except (ValueError, TypeError):
                return None
        else:
            return None
    return obj if isinstance(obj, dict) else None


# ---------------------------------------------------------------------------
# Offline (default when nothing is configured)
# ---------------------------------------------------------------------------

class OfflineProvider(AIProvider):
    name = "offline"

    def available(self) -> bool:
        return False

    def analyze(self, system: str, user: str, schema: dict) -> Optional[dict]:
        return None


# ---------------------------------------------------------------------------
# Anthropic (Claude) — Messages API over HTTP
# ---------------------------------------------------------------------------

class AnthropicProvider(AIProvider):
    name = "anthropic"
    _DEFAULT_MODEL = "claude-opus-4-8"

    def __init__(self, api_key: str = "", model: str = "", base_url: str = ""):
        self._key = api_key or os.environ.get("VALKYRIE_AI_KEY") or \
            os.environ.get("ANTHROPIC_API_KEY") or ""
        self._model = model or os.environ.get("VALKYRIE_AI_MODEL") or self._DEFAULT_MODEL
        self._base = (base_url or os.environ.get("VALKYRIE_AI_BASE_URL")
                      or "https://api.anthropic.com").rstrip("/")

    def available(self) -> bool:
        return bool(_HTTPX and self._key)

    def analyze(self, system: str, user: str, schema: dict) -> Optional[dict]:
        if not self.available():
            return None
        try:
            r = httpx.post(
                f"{self._base}/v1/messages",
                headers={"x-api-key": self._key,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": self._model, "max_tokens": 2048,
                      "system": system,
                      "messages": [{"role": "user", "content": user}]},
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            blocks = r.json().get("content", [])
            text = next((b.get("text", "") for b in blocks
                         if b.get("type") == "text"), "")
        except Exception:
            return None
        return _extract_json(text)


# ---------------------------------------------------------------------------
# OpenAI-compatible (OpenAI cloud, and local servers via LocalProvider)
# ---------------------------------------------------------------------------

class OpenAIProvider(AIProvider):
    name = "openai"
    _DEFAULT_MODEL = "gpt-4o-mini"
    _DEFAULT_BASE = "https://api.openai.com/v1"
    _KEY_ENVS = ("VALKYRIE_AI_KEY", "OPENAI_API_KEY")
    _requires_key = True

    def __init__(self, api_key: str = "", model: str = "", base_url: str = ""):
        self._key = api_key or next(
            (os.environ[e] for e in self._KEY_ENVS if os.environ.get(e)), "")
        self._model = model or os.environ.get("VALKYRIE_AI_MODEL") or self._DEFAULT_MODEL
        self._base = (base_url or os.environ.get("VALKYRIE_AI_BASE_URL")
                      or self._DEFAULT_BASE).rstrip("/")

    def available(self) -> bool:
        if not _HTTPX:
            return False
        return bool(self._key) if self._requires_key else bool(self._base)

    def analyze(self, system: str, user: str, schema: dict) -> Optional[dict]:
        if not self.available():
            return None
        headers = {"content-type": "application/json"}
        if self._key:
            headers["authorization"] = f"Bearer {self._key}"
        try:
            r = httpx.post(
                f"{self._base}/chat/completions",
                headers=headers,
                json={"model": self._model,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}],
                      "response_format": {"type": "json_object"},
                      "max_tokens": 2048},
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
        except Exception:
            return None
        return _extract_json(text)


class LocalProvider(OpenAIProvider):
    """Any OpenAI-compatible server running on the box (Ollama, LM Studio,
    llama.cpp, vLLM). Keeps everything local — nothing leaves the machine."""
    name = "local"
    _DEFAULT_MODEL = "llama3.1"
    _DEFAULT_BASE = "http://localhost:11434/v1"    # Ollama default
    _requires_key = False


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "local": LocalProvider,
    "offline": OfflineProvider,
}


def _auto_name() -> str:
    """Pick a provider from the environment when none is named explicitly."""
    if os.environ.get("VALKYRIE_AI_BASE_URL") and not (
            os.environ.get("VALKYRIE_AI_KEY") or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("OPENAI_API_KEY")):
        return "local"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("VALKYRIE_AI_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "offline"


def get_provider() -> AIProvider:
    """Return the configured provider (never raises; defaults to offline).

    Honors ``VALKYRIE_AI_PROVIDER`` and falls back to environment auto-detection
    so an existing ``ANTHROPIC_API_KEY``-only deployment behaves exactly as
    before, now through the vendor-neutral interface.
    """
    name = (os.environ.get("VALKYRIE_AI_PROVIDER") or _auto_name()).strip().lower()
    cls = _PROVIDERS.get(name, OfflineProvider)
    try:
        return cls()
    except Exception:
        return OfflineProvider()
