"""Claude client for case analysis. Every failure returns a status and never raises.

Detection must keep working when the model is slow, down, over budget or declines a
request, so the pipeline treats anything other than status "ok" as "use the
deterministic scorer".
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import anthropic

from ...config import LLMSettings
from .prompts import SYSTEM_PROMPT, VERDICT_SCHEMA

log = logging.getLogger(__name__)

FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass
class LLMResult:
    status: str  # ok | disabled | budget | breaker_open | refused | truncated | invalid_json | error
    data: dict[str, Any] | None = None
    model: str | None = None
    detail: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)


class LLMClient:
    def __init__(self, settings: LLMSettings, client: Any | None = None):
        self.settings = settings
        self._client = client
        self._lock = threading.Lock()
        self._calls: deque[float] = deque()
        self._consecutive_failures = 0
        self._breaker_open_until = 0.0

    def _get_client(self) -> Any:
        if self._client is None:
            # Credentials resolve through the SDK's normal chain (ANTHROPIC_API_KEY, profile, ...).
            self._client = anthropic.Anthropic(
                timeout=self.settings.timeout_seconds, max_retries=self.settings.max_retries
            )
        return self._client

    def _admit(self) -> str | None:
        now = time.monotonic()
        with self._lock:
            if now < self._breaker_open_until:
                return "breaker_open"
            while self._calls and now - self._calls[0] > 60:
                self._calls.popleft()
            if len(self._calls) >= self.settings.max_calls_per_minute:
                return "budget"
            self._calls.append(now)
        return None

    def _record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0

    def _record_failure(self, *, immediate: bool = False) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if immediate or self._consecutive_failures >= self.settings.breaker_failures:
                self._breaker_open_until = time.monotonic() + self.settings.breaker_cooldown_seconds
                self._consecutive_failures = 0
                log.warning("LLM breaker open for %ss", self.settings.breaker_cooldown_seconds)

    def analyze(self, user_prompt: str) -> LLMResult:
        if not self.settings.enabled:
            return LLMResult(status="disabled")
        blocked = self._admit()
        if blocked:
            return LLMResult(status=blocked)

        params: dict[str, Any] = {
            "model": self.settings.model,
            "max_tokens": self.settings.max_tokens,
            "thinking": {"type": "adaptive"},
            "system": [
                {"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
            ],
            "messages": [{"role": "user", "content": user_prompt}],
            "output_config": {
                "effort": self.settings.effort,
                "format": {"type": "json_schema", "schema": VERDICT_SCHEMA},
            },
        }

        try:
            client = self._get_client()
            if self.settings.server_side_fallbacks:
                response = client.beta.messages.create(
                    betas=[FALLBACK_BETA], fallbacks="default", **params
                )
            else:
                response = client.messages.create(**params)
        # Credential and configuration errors will not fix themselves, so stop calling for a while.
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            log.error("LLM credentials rejected: %s", type(exc).__name__)
            self._record_failure(immediate=True)
            return LLMResult(status="error", detail=type(exc).__name__)
        except anthropic.NotFoundError as exc:
            log.error("LLM model not found: %s", self.settings.model)
            self._record_failure(immediate=True)
            return LLMResult(status="error", detail=type(exc).__name__)
        except anthropic.BadRequestError as exc:
            log.error("LLM rejected the request: %s", exc.message)
            self._record_failure()
            return LLMResult(status="error", detail="BadRequestError")
        except anthropic.RateLimitError:
            log.warning("LLM rate limited")
            self._record_failure()
            return LLMResult(status="error", detail="RateLimitError")
        except anthropic.APIStatusError as exc:
            log.warning("LLM API error %s", exc.status_code)
            self._record_failure()
            return LLMResult(status="error", detail=f"APIStatusError:{exc.status_code}")
        except anthropic.APITimeoutError:
            log.warning("LLM request timed out")
            self._record_failure()
            return LLMResult(status="error", detail="APITimeoutError")
        except anthropic.APIConnectionError:
            log.warning("LLM connection error")
            self._record_failure()
            return LLMResult(status="error", detail="APIConnectionError")
        except anthropic.AnthropicError as exc:
            # For example, no credentials configured at all.
            log.warning("LLM unavailable: %s", type(exc).__name__)
            self._record_failure(immediate=True)
            return LLMResult(status="error", detail=type(exc).__name__)

        return self._parse(response)

    def _parse(self, response: Any) -> LLMResult:
        usage = {}
        if getattr(response, "usage", None) is not None:
            usage = {
                "input_tokens": getattr(response.usage, "input_tokens", None),
                "output_tokens": getattr(response.usage, "output_tokens", None),
                "cache_read_input_tokens": getattr(response.usage, "cache_read_input_tokens", None),
            }
        model = getattr(response, "model", None)
        self._record_success()

        # Check the stop reason before reading content: a refusal has no usable output.
        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            log.info("LLM declined the case (category=%s)", category)
            return LLMResult(status="refused", model=model, detail=str(category), usage=usage)
        if stop_reason == "max_tokens":
            return LLMResult(status="truncated", model=model, usage=usage)

        # After a server-side fallback the final model's answer is the last text block.
        texts = [b.text for b in response.content if getattr(b, "type", None) == "text"]
        if not texts:
            return LLMResult(status="invalid_json", model=model, detail="no text block", usage=usage)
        try:
            data = json.loads(texts[-1])
        except json.JSONDecodeError:
            return LLMResult(status="invalid_json", model=model, detail="unparseable", usage=usage)
        if not isinstance(data, dict):
            return LLMResult(status="invalid_json", model=model, detail="not an object", usage=usage)
        return LLMResult(status="ok", data=data, model=model, usage=usage)
