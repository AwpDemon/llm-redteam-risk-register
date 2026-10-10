"""Minimal client for any OpenAI-compatible /v1/chat/completions endpoint.

Works with Ollama (default), llama.cpp server, vLLM, LM Studio, or a hosted provider: only the base URL,
model name and (optional) API key change. No vendor SDK, so the request that was sent is exactly what is logged.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen2.5:7b-instruct"


@dataclass
class ChatResult:
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = "stop"
    latency_s: float = 0.0


class ChatClient(Protocol):
    model: str

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> ChatResult: ...


@dataclass
class EndpointConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str | None = None
    timeout_s: float = 600.0

    @classmethod
    def from_env(cls) -> EndpointConfig:
        return cls(
            base_url=os.environ.get("REDTEAM_BASE_URL", DEFAULT_BASE_URL),
            model=os.environ.get("REDTEAM_MODEL", DEFAULT_MODEL),
            api_key=os.environ.get("REDTEAM_API_KEY") or None,
        )


class OpenAICompatClient:
    """Thin synchronous client with retry on transient errors."""

    def __init__(self, cfg: EndpointConfig, retries: int = 3):
        self.cfg = cfg
        self.model = cfg.model
        self.retries = retries
        headers = {"Content-Type": "application/json"}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        self._http = httpx.Client(base_url=cfg.base_url.rstrip("/"), headers=headers, timeout=cfg.timeout_s)

    def chat(self, messages, *, tools=None, max_tokens=512, temperature=0.0, seed=None) -> ChatResult:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if seed is not None:
            body["seed"] = seed
        if tools:
            body["tools"] = tools
        last_err: Exception | None = None
        for attempt in range(self.retries):
            t0 = time.perf_counter()
            try:
                resp = self._http.post("/chat/completions", json=body)
                resp.raise_for_status()
                data = resp.json()
                choice = data["choices"][0]
                msg = choice["message"]
                usage = data.get("usage") or {}
                return ChatResult(
                    content=msg.get("content") or "",
                    tool_calls=msg.get("tool_calls") or [],
                    prompt_tokens=int(usage.get("prompt_tokens", 0)),
                    completion_tokens=int(usage.get("completion_tokens", 0)),
                    finish_reason=choice.get("finish_reason") or "stop",
                    latency_s=time.perf_counter() - t0,
                )
            except (httpx.TransportError, httpx.HTTPStatusError) as err:  # pragma: no cover - network
                last_err = err
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"chat completion failed after {self.retries} attempts: {last_err}")
