"""LLMClient: the one way CodeGuard talks to an AI model.

What it does around every call, the same for every provider:
  1. Cache: the answer for (provider, model, prompt version, input hash) is saved in .cache/llm/
     and reused, so the same scan never asks twice and research runs can be repeated for free.
  2. Rate limits: waits between requests (requests per minute) and stops at a daily cap, both a
     little below the provider's free-tier limits. The daily count is saved on disk.
  3. Retries: rate-limit answers (HTTP 429), server errors and timeouts are retried with
     exponential backoff, honouring the provider's Retry-After.
  4. Validation: the answer must be JSON that passes a pydantic model and the caller's own checks.
     If it does not, the model is asked again once or twice, told what was wrong. Only validated
     answers are cached. Nothing the AI says is used unchecked.
  5. Log: every call (cache hits too) is written to .cache/llm/calls.jsonl with the provider,
     model, model version, prompt name and version, attempts and outcome. Never the API key.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from codeguard.config import Settings, get_settings
from codeguard.llm.base import (
    InvalidAnswer,
    LLMError,
    Provider,
    QuotaExhausted,
    RateLimited,
    TransientError,
)
from codeguard.rulechecks.netclient import JsonCache

log = logging.getLogger("codeguard.llm")

T = TypeVar("T", bound=BaseModel)

CACHE_NAMESPACE = "llm"
MAX_WAIT_S = 60.0  # longest single wait between retries
BASE_BACKOFF_S = 2.0
REPAIR_ATTEMPTS = 2  # extra tries when the answer is not valid
_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class Prompt:
    id: str  # what the prompt is for, e.g. "checklist"
    version: str  # bumped whenever the prompt text changes, e.g. "checklist-v1"
    system: str
    user: str

    @property
    def input_hash(self) -> str:
        return hashlib.sha256(f"{self.system}\0{self.user}".encode("utf-8")).hexdigest()


@dataclass
class LLMResult(Generic[T]):
    value: T
    raw: str
    cache_hit: bool
    requests: int  # requests sent to the provider for this answer (0 on a cache hit)
    model_version: str | None = None


def _utc_today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


class RateLimiter:
    """Spaces requests out (per minute) and stops at a daily cap. One per provider + model.

    The daily count is saved in the cache folder so it survives restarts. It resets at midnight
    UTC; providers may reset at a different hour, which is why the default caps sit below theirs.
    """

    def __init__(
        self,
        rpm: int,
        rpd: int,
        usage_file: Path | None,
        key: str,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        today: Callable[[], str] = _utc_today,
    ):
        self.interval = 60.0 / rpm if rpm > 0 else 0.0
        self.rpd = rpd
        self.usage_file = usage_file
        self.key = key
        self.clock, self.sleep, self.today = clock, sleep, today
        self._last: float | None = None
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            if self.rpd > 0:
                used = self._read_usage()
                if used >= self.rpd:
                    raise QuotaExhausted(
                        f"daily limit of {self.rpd} requests reached for {self.key} "
                        "(CODEGUARD_LLM_RPD). It resets tomorrow (UTC)."
                    )
            if self.interval and self._last is not None:
                wait = self._last + self.interval - self.clock()
                if wait > 0:
                    self.sleep(wait)
            self._last = self.clock()
            if self.rpd > 0:
                self._write_usage(self._read_usage() + 1)

    def used_today(self) -> int:
        with self._lock:
            return self._read_usage()

    def _load(self) -> dict:
        if self.usage_file is None:
            return {}
        try:
            data = json.loads(self.usage_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _read_usage(self) -> int:
        data = self._load()
        if data.get("date") != self.today():
            return 0
        return int((data.get("counts") or {}).get(self.key, 0))

    def _write_usage(self, count: int) -> None:
        if self.usage_file is None:
            return
        data = self._load()
        if data.get("date") != self.today():
            data = {"date": self.today(), "counts": {}}
        data.setdefault("counts", {})[self.key] = count
        try:
            self.usage_file.parent.mkdir(parents=True, exist_ok=True)
            self.usage_file.write_text(json.dumps(data, indent=1), encoding="utf-8")
        except OSError:
            pass


# Shared per process, so requests from scans that run one after another are spaced out too.
_LIMITERS: dict[tuple, RateLimiter] = {}
_LIMITERS_LOCK = threading.Lock()


def shared_limiter(provider: Provider, rpm: int, rpd: int, usage_file: Path) -> RateLimiter:
    key = (provider.name, provider.model, rpm, rpd, str(usage_file))
    with _LIMITERS_LOCK:
        if key not in _LIMITERS:
            _LIMITERS[key] = RateLimiter(rpm, rpd, usage_file, f"{provider.name}/{provider.model}")
        return _LIMITERS[key]


class LLMClient:
    def __init__(
        self,
        provider: Provider,
        cache_dir: Path,
        *,
        rpm: int | None = None,
        rpd: int | None = None,
        max_retries: int = 4,
        limiter: RateLimiter | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.provider = provider
        self.root = Path(cache_dir) / CACHE_NAMESPACE
        self.cache = JsonCache(Path(cache_dir))
        self.max_retries = max(max_retries, 0)
        self.sleep = sleep
        rpm = provider.default_rpm if not rpm else rpm
        rpd = provider.default_rpd if not rpd else rpd
        self.limiter = limiter or shared_limiter(provider, rpm, rpd, self.root / "usage.json")
        self.log_path = self.root / "calls.jsonl"
        self._log_lock = threading.Lock()

    @property
    def name(self) -> str:
        return self.provider.name

    @property
    def model(self) -> str:
        return self.provider.model

    def cache_key(self, prompt: Prompt) -> str:
        return f"{self.provider.name}|{self.provider.model}|{prompt.version}|{prompt.input_hash}"

    def complete_json(
        self,
        prompt: Prompt,
        schema: type[T],
        check: Callable[[T], None] | None = None,
        use_cache: bool = True,
    ) -> LLMResult[T]:
        """Ask for a JSON answer that passes `schema` and `check` (which raises InvalidAnswer).

        Raises QuotaExhausted, InvalidAnswer or another LLMError when no valid answer could be had.
        """
        start = time.perf_counter()
        key = self.cache_key(prompt)
        cached = self.cache.get(CACHE_NAMESPACE, key) if use_cache else None
        if cached is not None:
            entry = cached[0]
            try:
                value = parse_answer(entry["raw"], schema, check)
            except (InvalidAnswer, KeyError, TypeError):
                pass  # the checks became stricter since this was cached: ask again
            else:
                result = LLMResult(value, entry["raw"], True, 0, entry.get("model_version"))
                self._log(prompt, result, start, "ok")
                return result

        requests = 0
        feedback: list[str] = []
        last_error: InvalidAnswer | None = None
        model_version = None
        try:
            for _ in range(REPAIR_ATTEMPTS + 1):
                user = prompt.user
                if feedback:
                    user += (
                        "\n\nYour previous answer was rejected: "
                        + feedback[-1]
                        + "\nAnswer again with valid JSON that follows every rule above."
                    )
                reply, sent = self._send(prompt.system, user)
                requests += sent
                model_version = reply.model_version
                try:
                    value = parse_answer(reply.text, schema, check)
                except InvalidAnswer as exc:
                    last_error = exc
                    feedback.append(str(exc))
                    continue
                if use_cache:
                    self.cache.put(CACHE_NAMESPACE, key, {"raw": reply.text, "model_version": model_version})
                result = LLMResult(value, reply.text, False, requests, model_version)
                self._log(prompt, result, start, "ok")
                return result
        except LLMError as exc:
            self._log_failure(prompt, requests, start, exc)
            exc.requests = requests  # type: ignore[attr-defined]
            raise
        assert last_error is not None
        err = InvalidAnswer(f"no valid answer after {REPAIR_ATTEMPTS + 1} tries: {last_error}")
        err.requests = requests  # type: ignore[attr-defined]
        self._log_failure(prompt, requests, start, err)
        raise err

    def _send(self, system: str, user: str):
        """One answer from the provider, retrying rate limits and temporary errors with backoff."""
        sent = 0
        for attempt in range(self.max_retries + 1):
            self.limiter.acquire()
            sent += 1
            try:
                return self.provider.complete(system, user), sent
            except RateLimited as exc:
                if exc.daily:
                    raise QuotaExhausted(str(exc)) from exc
                if attempt == self.max_retries:
                    raise
                wait = exc.retry_after if exc.retry_after is not None else self._backoff(attempt)
            except TransientError:
                if attempt == self.max_retries:
                    raise
                wait = self._backoff(attempt)
            log.info("AI request failed, retrying in %.1f s (attempt %d)", min(wait, MAX_WAIT_S), attempt + 1)
            self.sleep(min(wait, MAX_WAIT_S))
        raise TransientError("no answer")  # not reached

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(BASE_BACKOFF_S * (2**attempt), MAX_WAIT_S)

    # --- log ---

    def _log(self, prompt: Prompt, result: LLMResult, start: float, outcome: str, error: str | None = None) -> None:
        self._write_log(
            prompt,
            {
                "cache_hit": result.cache_hit,
                "requests": result.requests,
                "model_version": result.model_version,
                "outcome": outcome,
                "error": error,
            },
            start,
        )

    def _log_failure(self, prompt: Prompt, requests: int, start: float, exc: Exception) -> None:
        self._write_log(
            prompt,
            {"cache_hit": False, "requests": requests, "model_version": None, "outcome": type(exc).__name__, "error": str(exc)[:300]},
            start,
        )

    def _write_log(self, prompt: Prompt, fields: dict, start: float) -> None:
        record = {
            "time": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "provider": self.provider.name,
            "model": self.provider.model,
            "prompt_id": prompt.id,
            "prompt_version": prompt.version,
            "input_hash": prompt.input_hash[:16],
            "duration_s": round(time.perf_counter() - start, 3),
            **fields,
        }
        log.info(
            "AI call %s %s/%s prompt=%s cache_hit=%s requests=%s outcome=%s",
            prompt.id, record["provider"], record["model"], prompt.version,
            record["cache_hit"], record["requests"], record["outcome"],
        )  # fmt: skip
        with self._log_lock:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
            except OSError:
                pass


def parse_answer(raw: str, schema: type[T], check: Callable[[T], None] | None = None) -> T:
    """Model text -> validated object. Raises InvalidAnswer with a short, model-readable reason."""
    text = raw.strip()
    m = _FENCE.match(text)
    if m:
        text = m.group(1)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InvalidAnswer(f"the answer is not valid JSON ({exc.msg} at position {exc.pos})") from exc
    try:
        value = schema.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'answer'}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise InvalidAnswer(f"the JSON does not have the required shape ({problems})") from exc
    if check is not None:
        check(value)
    return value


def make_client(settings: Settings | None = None) -> LLMClient:
    """The client for the provider chosen in .env. Raises LLMUnavailable (e.g. no API key)."""
    from codeguard.llm.providers import build_provider

    settings = settings or get_settings()
    return LLMClient(
        build_provider(settings),
        settings.cache_dir,
        rpm=settings.llm_rpm,
        rpd=settings.llm_rpd,
        max_retries=settings.llm_max_retries,
    )
