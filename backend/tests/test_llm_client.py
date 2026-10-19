"""LLMClient: caching, retries with backoff, rate limits, JSON validation and the call log (fake provider only)."""

import json

import pytest
from pydantic import BaseModel

from codeguard.llm.base import InvalidAnswer, QuotaExhausted, RateLimited, TransientError
from codeguard.llm.client import LLMClient, Prompt, RateLimiter, parse_answer

from conftest import FakeProvider


class Answer(BaseModel):
    ok: bool


def prompt(version="test-v1", user="question"):
    return Prompt(id="test", version=version, system="system", user=user)


def test_valid_answer_is_parsed(make_llm):
    client = make_llm(['{"ok": true}'])
    result = client.complete_json(prompt(), Answer)
    assert result.value.ok is True
    assert result.cache_hit is False and result.requests == 1
    assert result.model_version == "fake-model-001"


def test_second_identical_call_uses_the_cache(make_llm):
    client = make_llm(['{"ok": true}'])
    client.complete_json(prompt(), Answer)
    again = client.complete_json(prompt(), Answer)  # the fake has no answers left: it must not be asked
    assert again.cache_hit is True and again.requests == 0 and again.value.ok is True
    assert len(client.provider.calls) == 1


def test_cache_key_has_provider_model_prompt_version_and_input(make_llm, tmp_path):
    client = make_llm(['{"ok": true}', '{"ok": false}', '{"ok": true}', '{"ok": false}'])
    client.complete_json(prompt("v1"), Answer)
    assert client.complete_json(prompt("v2"), Answer).cache_hit is False  # new prompt version
    assert client.complete_json(prompt("v1", user="other input"), Answer).cache_hit is False  # new input
    other_model = LLMClient(
        FakeProvider(['{"ok": true}'], model="other-model"),
        tmp_path / "cache",
        limiter=RateLimiter(0, 0, None, "x"),
        sleep=lambda s: None,
    )
    assert other_model.complete_json(prompt("v1"), Answer).cache_hit is False  # new model
    key = client.cache_key(prompt("v1"))
    assert key.startswith("fake|fake-model|v1|") and len(key.split("|")[-1]) == 64


def test_use_cache_false_always_asks(make_llm):
    client = make_llm(['{"ok": true}', '{"ok": true}'])
    client.complete_json(prompt(), Answer, use_cache=False)
    assert client.complete_json(prompt(), Answer, use_cache=False).cache_hit is False
    assert len(client.provider.calls) == 2


def test_code_fences_are_accepted():
    assert parse_answer('```json\n{"ok": true}\n```', Answer).ok is True


def test_invalid_json_is_asked_again_with_the_reason(make_llm):
    client = make_llm(["Sure! Here is the answer: ok", '{"ok": "maybe"}', '{"ok": true}'])
    result = client.complete_json(prompt(), Answer)
    assert result.value.ok is True and result.requests == 3
    second_user = client.provider.calls[1][1]
    assert "Your previous answer was rejected" in second_user and "not valid JSON" in second_user
    assert "required shape" in client.provider.calls[2][1]


def test_never_valid_answer_fails_and_is_not_cached(make_llm):
    client = make_llm(["nope", "nope", "nope", '{"ok": true}'])
    with pytest.raises(InvalidAnswer, match="no valid answer after 3 tries"):
        client.complete_json(prompt(), Answer)
    assert client.complete_json(prompt(), Answer).cache_hit is False  # the failure was not cached


def test_custom_check_rejects_answer(make_llm):
    def must_be_true(a):
        if not a.ok:
            raise InvalidAnswer("ok must be true")

    client = make_llm(['{"ok": false}', '{"ok": true}'])
    assert client.complete_json(prompt(), Answer, must_be_true).value.ok is True
    assert "ok must be true" in client.provider.calls[1][1]


def test_rate_limit_is_retried_after_the_wait_the_provider_asks_for(make_llm):
    waits = []
    client = make_llm([RateLimited("429", retry_after=7), '{"ok": true}'], sleep=waits.append)
    result = client.complete_json(prompt(), Answer)
    assert result.value.ok and result.requests == 2
    assert waits == [7]


def test_temporary_errors_back_off_exponentially(make_llm):
    waits = []
    client = make_llm(
        [TransientError("503"), TransientError("503"), RateLimited("429"), '{"ok": true}'], sleep=waits.append
    )
    assert client.complete_json(prompt(), Answer).requests == 4
    assert waits == [2.0, 4.0, 8.0]


def test_waits_are_capped(make_llm):
    waits = []
    client = make_llm([RateLimited("429", retry_after=3600), '{"ok": true}'], sleep=waits.append)
    client.complete_json(prompt(), Answer)
    assert waits == [60.0]


def test_gives_up_after_max_retries(make_llm):
    client = make_llm([TransientError("down")] * 3, max_retries=2)
    with pytest.raises(TransientError):
        client.complete_json(prompt(), Answer)
    assert len(client.provider.calls) == 3


def test_daily_quota_is_not_retried(make_llm):
    waits = []
    client = make_llm([RateLimited("429 per day", daily=True), '{"ok": true}'], sleep=waits.append)
    with pytest.raises(QuotaExhausted):
        client.complete_json(prompt(), Answer)
    assert waits == [] and len(client.provider.calls) == 1


class Clock:
    def __init__(self):
        self.now = 100.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.slept.append(round(s, 3))
        self.now += s


def test_rate_limiter_spaces_requests_out():
    clock = Clock()
    limiter = RateLimiter(rpm=10, rpd=0, usage_file=None, key="k", clock=clock, sleep=clock.sleep)
    limiter.acquire()
    limiter.acquire()
    clock.now += 2
    limiter.acquire()
    assert clock.slept == [6.0, 4.0]  # 10 per minute = one every 6 s


def test_daily_cap_is_saved_and_resets_the_next_day(tmp_path):
    usage = tmp_path / "usage.json"
    day = {"d": "2026-10-18"}
    make = lambda: RateLimiter(0, 2, usage, "fake/m", today=lambda: day["d"])  # noqa: E731
    make().acquire()
    make().acquire()  # a new limiter (e.g. after a restart) still sees today's count
    with pytest.raises(QuotaExhausted, match="daily limit of 2"):
        make().acquire()
    day["d"] = "2026-10-19"
    make().acquire()
    assert json.loads(usage.read_text())["counts"] == {"fake/m": 1}


def test_quota_from_limiter_stops_the_call(make_llm, tmp_path):
    limiter = RateLimiter(0, 1, tmp_path / "u.json", "fake/m")
    client = make_llm(['{"ok": true}', '{"ok": true}'], limiter=limiter)
    client.complete_json(prompt("a"), Answer)
    with pytest.raises(QuotaExhausted):
        client.complete_json(prompt("b"), Answer)
    assert client.complete_json(prompt("a"), Answer).cache_hit  # cached answers still work


def test_every_call_is_logged_with_model_and_prompt_version(make_llm):
    client = make_llm(['{"ok": true}', "bad", "bad", "bad"])
    client.complete_json(prompt("v1"), Answer)
    client.complete_json(prompt("v1"), Answer)
    with pytest.raises(InvalidAnswer):
        client.complete_json(prompt("v2"), Answer)
    records = [json.loads(line) for line in client.log_path.read_text().splitlines()]
    assert [(r["prompt_version"], r["cache_hit"], r["outcome"]) for r in records] == [
        ("v1", False, "ok"),
        ("v1", True, "ok"),
        ("v2", False, "InvalidAnswer"),
    ]
    for r in records:
        assert r["provider"] == "fake" and r["model"] == "fake-model" and r["prompt_id"] == "test"
    assert records[0]["model_version"] == "fake-model-001" and records[2]["requests"] == 3
