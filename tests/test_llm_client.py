"""Exercises the real Anthropic SDK against a mock HTTP transport, so the wire format is tested too."""

from __future__ import annotations

import json

import anthropic
import httpx2
import pytest
from anthropic import DefaultHttpxClient
from carylle.config import LLMSettings
from carylle.pipeline.reasoning.llm_client import FALLBACK_BETA, LLMClient


def message(text: str = '{"ok": true}', stop_reason: str = "end_turn", **extra) -> dict:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
        **extra,
    }


def make_client(handler, **settings) -> LLMClient:
    config = LLMSettings(max_retries=0, **settings)
    http = DefaultHttpxClient(transport=httpx2.MockTransport(handler))
    return LLMClient(config, anthropic.Anthropic(api_key="test", http_client=http, max_retries=0))


def test_request_shape():
    seen: dict = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["beta"] = request.headers.get("anthropic-beta")
        return httpx2.Response(200, json=message())

    result = make_client(handler).analyze("assess this")
    assert result.status == "ok" and result.data == {"ok": True}

    body = seen["body"]
    assert body["model"] == "claude-opus-5-5"
    assert body["thinking"] == {"type": "adaptive"}
    assert body["fallbacks"] == "default"
    assert seen["beta"] == FALLBACK_BETA
    assert body["output_config"]["effort"] == "medium"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    # These return a 400 on this model.
    assert "tool_choice" not in body and "temperature" not in body
    assert body["messages"] == [{"role": "user", "content": "assess this"}]


def test_system_prompt_is_stable_between_requests():
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx2.Response(200, json=message())

    client = make_client(handler)
    client.analyze("one")
    client.analyze("two")
    assert bodies[0]["system"] == bodies[1]["system"]


def test_fallbacks_can_be_disabled():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["beta"] = request.headers.get("anthropic-beta")
        return httpx2.Response(200, json=message())

    make_client(handler, server_side_fallbacks=False).analyze("x")
    assert "fallbacks" not in seen["body"] and not seen["beta"]


def test_refusal_is_a_status_not_an_error():
    def handler(request):
        return httpx2.Response(
            200,
            json=message(
                text="",
                stop_reason="refusal",
                stop_details={"type": "refusal", "category": "cyber", "explanation": "declined"},
            ),
        )

    client = make_client(handler, breaker_failures=1)
    result = client.analyze("x")
    assert result.status == "refused" and result.detail == "cyber"
    # A refusal isn't an outage, so the breaker must stay closed.
    assert client.analyze("y").status == "refused"


def test_truncation_is_detected():
    result = make_client(lambda r: httpx2.Response(200, json=message(text='{"a"', stop_reason="max_tokens"))).analyze("x")
    assert result.status == "truncated"


@pytest.mark.parametrize("text", ["not json", "[1, 2]", ""])
def test_unparseable_output(text):
    result = make_client(lambda r: httpx2.Response(200, json=message(text=text))).analyze("x")
    assert result.status == "invalid_json"


def test_uses_last_text_block_after_a_fallback():
    body = message()
    body["content"] = [{"type": "text", "text": "partial"}, {"type": "text", "text": '{"final": 1}'}]
    assert make_client(lambda r: httpx2.Response(200, json=body)).analyze("x").data == {"final": 1}


@pytest.mark.parametrize(
    "status,detail",
    [
        (400, "BadRequestError"),
        (401, "AuthenticationError"),
        (403, "PermissionDeniedError"),
        (404, "NotFoundError"),
        (429, "RateLimitError"),
        (500, "APIStatusError:500"),
        (529, "APIStatusError:529"),
    ],
)
def test_http_errors_never_raise(status, detail):
    def handler(request):
        return httpx2.Response(status, json={"type": "error", "error": {"type": "x", "message": "boom"}})

    result = make_client(handler).analyze("x")
    assert result.status == "error" and result.detail == detail


def test_connection_error_never_raises():
    def handler(request):
        raise httpx2.ConnectError("no route")

    assert make_client(handler).analyze("x").detail == "APIConnectionError"


def test_timeout_never_raises():
    def handler(request):
        raise httpx2.ReadTimeout("slow")

    assert make_client(handler).analyze("x").detail == "APITimeoutError"


def test_breaker_opens_after_repeated_failures():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx2.Response(500, json={"type": "error", "error": {"type": "x", "message": "boom"}})

    client = make_client(handler, breaker_failures=2)
    client.analyze("a")
    client.analyze("b")
    assert client.analyze("c").status == "breaker_open"
    assert len(calls) == 2


def test_bad_credentials_open_the_breaker_immediately():
    def handler(request):
        return httpx2.Response(401, json={"type": "error", "error": {"type": "x", "message": "no"}})

    client = make_client(handler)
    client.analyze("a")
    assert client.analyze("b").status == "breaker_open"


def test_call_budget():
    client = make_client(lambda r: httpx2.Response(200, json=message()), max_calls_per_minute=2)
    assert client.analyze("a").status == "ok"
    assert client.analyze("b").status == "ok"
    assert client.analyze("c").status == "budget"


def test_disabled_makes_no_call():
    def handler(request):
        raise AssertionError("should not be called")

    assert make_client(handler, enabled=False).analyze("x").status == "disabled"
