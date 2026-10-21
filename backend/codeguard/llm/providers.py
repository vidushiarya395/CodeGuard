"""The three free AI providers: Gemini (default), Groq and Ollama.

Each one only turns (system prompt, user prompt) into the model's raw text answer. Caching,
rate limits, retries and validation are the same for all of them and live in client.py.

Every request asks for temperature 0, a fixed seed and JSON output. API keys are sent in request
headers, never in the URL, and never appear in error messages or logs.
"""

from __future__ import annotations

import email.utils
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from codeguard import __version__
from codeguard.config import Settings
from codeguard.llm.base import (
    SEED,
    TEMPERATURE,
    LLMAuthError,
    LLMUnavailable,
    PermanentError,
    Provider,
    ProviderReply,
    RateLimited,
    TransientError,
)

USER_AGENT = f"CodeGuard/{__version__}"
MAX_ERROR_CHARS = 300

# Defaults for the free tiers. The providers change these from time to time, so every value can be
# overridden in .env (GEMINI_MODEL, GEMINI_RPD, CODEGUARD_LLM_RPM, CODEGUARD_LLM_RPD, ...). The limits
# are set a little below the published free-tier limits, so CodeGuard slows itself down before the
# provider starts refusing requests. Check the current limits in Google AI Studio and the Groq console.
# The Gemini 2.5 Flash free tier allows about 20 requests per day.
GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
GEMINI_RPM, GEMINI_RPD = 8, 18
GROQ_DEFAULT_MODEL = "openai/gpt-oss-120b"
GROQ_RPM, GROQ_RPD = 25, 900
OLLAMA_DEFAULT_MODEL = "qwen2.5-coder:7b"

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class HttpResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]):
        self.status = status
        self.body = body
        self.headers = {k.lower(): v for k, v in headers.items()}

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8", errors="replace"))
        except ValueError:
            return None

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def http_post(url: str, headers: dict[str, str], body: dict, timeout_s: float) -> HttpResponse:
    """POST JSON and return the response, whatever its status. Raises TransientError when the
    server cannot be reached. Tests replace this function, so no test ever reaches a real API."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return HttpResponse(resp.status, resp.read(10_000_000), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, exc.read(1_000_000) if exc.fp else b"", dict(exc.headers or {}))
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransientError(f"could not reach {urllib.parse.urlsplit(url).netloc} ({reason})") from exc


def _retry_after(resp: HttpResponse, body: Any) -> float | None:
    raw = resp.headers.get("retry-after")
    if raw:
        try:
            return max(float(raw), 0.0)
        except ValueError:
            try:
                return max(email.utils.parsedate_to_datetime(raw).timestamp() - time.time(), 0.0)
            except (TypeError, ValueError):
                pass
    # Gemini puts the wait in the error details: {"@type": "...RetryInfo", "retryDelay": "37s"}
    for detail in _error(body).get("details") or []:
        if isinstance(detail, dict) and isinstance(detail.get("retryDelay"), str):
            m = re.match(r"^([\d.]+)s$", detail["retryDelay"])
            if m:
                return float(m.group(1))
    return None


def _error(body: Any) -> dict:
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return body["error"]
    return {}


def _error_message(resp: HttpResponse, body: Any) -> str:
    msg = _error(body).get("message") or resp.text()
    return " ".join(str(msg).split())[:MAX_ERROR_CHARS]


def raise_for_status(service: str, resp: HttpResponse) -> Any:
    """Turn an HTTP error into the right LLMError. Returns the JSON body on success."""
    body = resp.json()
    if 200 <= resp.status < 300:
        if body is None:
            raise TransientError(f"{service} returned a response that is not JSON")
        return body
    msg = _error_message(resp, body)
    if resp.status == 429:
        # "per day" quotas (Gemini: ...PerDay..., Groq: "requests per day (RPD)") are not worth retrying.
        daily = bool(re.search(r"per ?day|RPD|TPD", resp.text(), re.IGNORECASE))
        raise RateLimited(f"{service} rate limit: {msg}", _retry_after(resp, body), daily)
    if resp.status in (401, 403):
        raise LLMAuthError(f"{service} rejected the API key (HTTP {resp.status}): {msg}")
    if resp.status in (408, 409) or resp.status >= 500:
        raise TransientError(f"{service} HTTP {resp.status}: {msg}")
    raise PermanentError(f"{service} HTTP {resp.status}: {msg}")


class GeminiProvider:
    name = "gemini"
    default_rpm, default_rpd = GEMINI_RPM, GEMINI_RPD

    def __init__(self, api_key: str, model: str = "", timeout_s: float = 90, rpd: int = 0):
        if not api_key:
            raise LLMUnavailable(
                "No GEMINI_API_KEY is set. Get a free key at https://aistudio.google.com/apikey and put it in .env"
            )
        self._key = api_key
        self.model = model or GEMINI_DEFAULT_MODEL
        self.timeout_s = timeout_s
        if rpd > 0:
            self.default_rpd = rpd

    def __repr__(self) -> str:
        return f"GeminiProvider(model={self.model!r})"

    def complete(self, system: str, user: str) -> ProviderReply:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "temperature": TEMPERATURE,
                "seed": SEED,
                "responseMimeType": "application/json",
            },
        }
        resp = http_post(
            GEMINI_URL.format(model=urllib.parse.quote(self.model, safe="-._")),
            {"x-goog-api-key": self._key},
            body,
            self.timeout_s,
        )
        data = raise_for_status("Gemini", resp)
        block = (data.get("promptFeedback") or {}).get("blockReason")
        if block:
            raise PermanentError(f"Gemini blocked the request ({block})")
        candidates = data.get("candidates") or []
        if not candidates:
            raise TransientError("Gemini returned no answer")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and not p.get("thought"))
        if not text:
            reason = candidates[0].get("finishReason", "unknown")
            raise TransientError(f"Gemini returned an empty answer (finishReason: {reason})")
        return ProviderReply(text=text, model_version=data.get("modelVersion"))


class GroqProvider:
    name = "groq"
    default_rpm, default_rpd = GROQ_RPM, GROQ_RPD

    def __init__(self, api_key: str, model: str = "", timeout_s: float = 90):
        if not api_key:
            raise LLMUnavailable(
                "No GROQ_API_KEY is set. Get a free key at https://console.groq.com/keys and put it in .env"
            )
        self._key = api_key
        self.model = model or GROQ_DEFAULT_MODEL
        self.timeout_s = timeout_s

    def __repr__(self) -> str:
        return f"GroqProvider(model={self.model!r})"

    def complete(self, system: str, user: str) -> ProviderReply:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": TEMPERATURE,
            "seed": SEED,
            "response_format": {"type": "json_object"},
        }
        resp = http_post(GROQ_URL, {"Authorization": f"Bearer {self._key}"}, body, self.timeout_s)
        data = raise_for_status("Groq", resp)
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise TransientError("Groq returned an answer in an unexpected shape") from exc
        version = data.get("model")
        if data.get("system_fingerprint"):
            version = f"{version} ({data['system_fingerprint']})"
        return ProviderReply(text=text, model_version=version)


class OllamaProvider:
    """A model running on this laptop with Ollama (https://ollama.com). No key, no limits."""

    name = "ollama"
    default_rpm, default_rpd = 0, 0

    def __init__(self, base_url: str, model: str = "", timeout_s: float = 300):
        self.base_url = base_url.rstrip("/")
        self.model = model or OLLAMA_DEFAULT_MODEL
        # Local models are slow on a laptop CPU; give them longer.
        self.timeout_s = max(timeout_s, 300)

    def __repr__(self) -> str:
        return f"OllamaProvider(model={self.model!r}, base_url={self.base_url!r})"

    def complete(self, system: str, user: str) -> ProviderReply:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": "json",
            "options": {"temperature": TEMPERATURE, "seed": SEED},
        }
        try:
            resp = http_post(f"{self.base_url}/api/chat", {}, body, self.timeout_s)
        except TransientError as exc:
            raise LLMUnavailable(
                f"Ollama is not running at {self.base_url}. Start the Ollama app, or set LLM_PROVIDER=gemini. ({exc})"
            ) from exc
        if resp.status == 404:
            raise LLMUnavailable(f"Ollama does not have the model '{self.model}'. Run: ollama pull {self.model}")
        data = raise_for_status("Ollama", resp)
        text = (data.get("message") or {}).get("content") or ""
        return ProviderReply(text=text, model_version=data.get("model"))


def build_provider(settings: Settings) -> Provider:
    """The provider chosen in .env (LLM_PROVIDER). Raises LLMUnavailable if it cannot be used."""
    name = settings.llm_provider
    if name == "gemini":
        return GeminiProvider(settings.gemini_api_key, settings.gemini_model, settings.llm_timeout_s, settings.gemini_rpd)
    if name == "groq":
        return GroqProvider(settings.groq_api_key, settings.groq_model, settings.llm_timeout_s)
    if name == "ollama":
        return OllamaProvider(settings.ollama_base_url, settings.ollama_model, settings.llm_timeout_s)
    raise LLMUnavailable(f"Unknown LLM_PROVIDER '{name}'. Use gemini, groq or ollama.")
