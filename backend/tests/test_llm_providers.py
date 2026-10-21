"""Gemini, Groq and Ollama providers: request shape (temperature 0, JSON mode), answer parsing and
error handling. The HTTP call is replaced in every test, so nothing goes to a real API."""

import json
from dataclasses import replace

import pytest

from codeguard.config import Settings
from codeguard.llm.base import LLMAuthError, LLMUnavailable, PermanentError, RateLimited, TransientError
from codeguard.llm.providers import (
    GeminiProvider,
    GroqProvider,
    HttpResponse,
    OllamaProvider,
    build_provider,
)

FAKE_KEY = "test-key-not-real-0123456789"


class FakeHttp:
    def __init__(self, status=200, body=None, headers=None, error=None):
        self.status, self.body, self.headers, self.error = status, body, headers or {}, error
        self.requests = []

    def __call__(self, url, headers, body, timeout_s):
        self.requests.append({"url": url, "headers": headers, "body": body})
        if self.error:
            raise self.error
        raw = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        return HttpResponse(self.status, raw, self.headers)


@pytest.fixture
def http(monkeypatch):
    def install(**kwargs):
        fake = FakeHttp(**kwargs)
        monkeypatch.setattr("codeguard.llm.providers.http_post", fake)
        return fake

    return install


def gemini_ok(text='{"ok": true}'):
    return {"candidates": [{"content": {"parts": [{"text": text}]}}], "modelVersion": "gemini-2.5-flash-001"}


def test_gemini_request_is_deterministic_json_and_key_is_in_a_header(http):
    fake = http(body=gemini_ok())
    reply = GeminiProvider(FAKE_KEY).complete("sys", "user")
    assert reply.text == '{"ok": true}' and reply.model_version == "gemini-2.5-flash-001"
    req = fake.requests[0]
    assert req["url"].endswith("/models/gemini-2.5-flash:generateContent")
    assert FAKE_KEY not in req["url"] and req["headers"] == {"x-goog-api-key": FAKE_KEY}
    cfg = req["body"]["generationConfig"]
    assert cfg["temperature"] == 0 and cfg["responseMimeType"] == "application/json" and cfg["seed"] == 42
    assert req["body"]["systemInstruction"]["parts"][0]["text"] == "sys"


def test_gemini_skips_thought_parts(http):
    http(body={"candidates": [{"content": {"parts": [{"text": "thinking", "thought": True}, {"text": "{}"}]}}]})
    assert GeminiProvider(FAKE_KEY).complete("s", "u").text == "{}"


def test_gemini_blocked_prompt_is_permanent(http):
    http(body={"promptFeedback": {"blockReason": "SAFETY"}})
    with pytest.raises(PermanentError, match="SAFETY"):
        GeminiProvider(FAKE_KEY).complete("s", "u")


def test_gemini_429_with_retry_delay(http):
    body = {"error": {"code": 429, "message": "Quota exceeded", "details": [{"retryDelay": "37s"}]}}
    http(status=429, body=body)
    with pytest.raises(RateLimited) as exc:
        GeminiProvider(FAKE_KEY).complete("s", "u")
    assert exc.value.retry_after == 37 and exc.value.daily is False


def test_gemini_daily_quota_is_recognized(http):
    body = {"error": {"code": 429, "message": "quota", "details": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}]}}
    http(status=429, body=body)
    with pytest.raises(RateLimited) as exc:
        GeminiProvider(FAKE_KEY).complete("s", "u")
    assert exc.value.daily is True


def test_groq_request_and_answer(http):
    fake = http(body={"choices": [{"message": {"content": '{"ok": true}'}}], "model": "llama-3.3-70b-versatile"})
    reply = GroqProvider(FAKE_KEY).complete("sys", "user")
    assert reply.text == '{"ok": true}' and reply.model_version == "llama-3.3-70b-versatile"
    req = fake.requests[0]
    assert req["headers"] == {"Authorization": f"Bearer {FAKE_KEY}"}
    body = req["body"]
    assert body["temperature"] == 0 and body["response_format"] == {"type": "json_object"}
    assert body["messages"][0] == {"role": "system", "content": "sys"}


def test_groq_retry_after_header_and_daily_limit(http):
    http(status=429, body={"error": {"message": "Rate limit reached on requests per minute"}}, headers={"Retry-After": "12"})
    with pytest.raises(RateLimited) as exc:
        GroqProvider(FAKE_KEY).complete("s", "u")
    assert exc.value.retry_after == 12 and not exc.value.daily
    http(status=429, body={"error": {"message": "Rate limit reached on tokens per day (TPD)"}})
    with pytest.raises(RateLimited) as exc:
        GroqProvider(FAKE_KEY).complete("s", "u")
    assert exc.value.daily


@pytest.mark.parametrize("status,error", [(401, LLMAuthError), (403, LLMAuthError), (500, TransientError), (503, TransientError), (400, PermanentError)])
def test_http_errors_map_to_the_right_error(http, status, error):
    http(status=status, body={"error": {"message": "something"}})
    with pytest.raises(error):
        GroqProvider(FAKE_KEY).complete("s", "u")


def test_error_messages_never_contain_the_key(http):
    http(status=401, body={"error": {"message": "API key not valid"}})
    with pytest.raises(LLMAuthError) as exc:
        GeminiProvider(FAKE_KEY).complete("s", "u")
    assert FAKE_KEY not in str(exc.value)


def test_ollama_request_and_answer(http):
    fake = http(body={"message": {"content": '{"ok": true}'}, "model": "qwen2.5-coder:7b"})
    assert OllamaProvider("http://localhost:11434/").complete("s", "u").text == '{"ok": true}'
    req = fake.requests[0]
    assert req["url"] == "http://localhost:11434/api/chat"
    assert req["body"]["format"] == "json" and req["body"]["stream"] is False
    assert req["body"]["options"]["temperature"] == 0


def test_ollama_not_running_is_unavailable(http):
    http(error=TransientError("could not reach localhost:11434 (connection refused)"))
    with pytest.raises(LLMUnavailable, match="Ollama is not running"):
        OllamaProvider("http://localhost:11434").complete("s", "u")


def test_missing_model_in_ollama(http):
    http(status=404, body={"error": "model not found"})
    with pytest.raises(LLMUnavailable, match="ollama pull"):
        OllamaProvider("http://localhost:11434").complete("s", "u")


def test_missing_keys_explain_where_to_get_one():
    with pytest.raises(LLMUnavailable, match="aistudio.google.com/apikey"):
        GeminiProvider("")
    with pytest.raises(LLMUnavailable, match="console.groq.com/keys"):
        GroqProvider("")


def test_build_provider_follows_settings():
    s = replace(Settings(), gemini_api_key=FAKE_KEY, groq_api_key=FAKE_KEY, gemini_model="", groq_model="")
    assert build_provider(replace(s, llm_provider="gemini")).name == "gemini"
    assert build_provider(replace(s, llm_provider="groq", groq_model="llama-3.1-8b-instant")).model == "llama-3.1-8b-instant"
    assert build_provider(replace(s, llm_provider="ollama")).name == "ollama"
    with pytest.raises(LLMUnavailable, match="Unknown LLM_PROVIDER"):
        build_provider(replace(s, llm_provider="openai"))


def test_gemini_daily_limit_default_and_override():
    assert GeminiProvider(FAKE_KEY).default_rpd == 18
    assert GeminiProvider(FAKE_KEY, rpd=5).default_rpd == 5
    s = replace(Settings(), llm_provider="gemini", gemini_api_key=FAKE_KEY)
    assert build_provider(replace(s, gemini_rpd=0)).default_rpd == 18
    assert build_provider(replace(s, gemini_rpd=12)).default_rpd == 12


def test_gemini_rpd_is_read_from_env(monkeypatch):
    monkeypatch.setenv("GEMINI_RPD", "7")
    assert Settings().gemini_rpd == 7


def test_keys_never_show_in_repr():
    s = replace(Settings(), gemini_api_key=FAKE_KEY, groq_api_key=FAKE_KEY)
    assert FAKE_KEY not in repr(s)
    assert FAKE_KEY not in repr(GeminiProvider(FAKE_KEY)) and FAKE_KEY not in repr(GroqProvider(FAKE_KEY))


def test_real_ai_calls_are_blocked_in_tests():
    # The autouse guard in conftest.py: even with a key, nothing can reach a real API.
    with pytest.raises(AssertionError, match="real AI API"):
        GeminiProvider(FAKE_KEY).complete("s", "u")
