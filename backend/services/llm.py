"""LLM provider interface.

One real implementation is included: any OpenAI-compatible chat-completions
endpoint (OpenAI, Groq, OpenRouter, a local Ollama server, ...), configured
only through environment variables. If LLM_API_KEY or LLM_MODEL is missing,
get_llm_provider() returns None and the caller uses the extractive fallback.

This is a single LLM call. It is not an agent: no tools, no planning, no loops.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from backend.config import get_settings


class LLMError(RuntimeError):
    pass


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's text reply. Raise LLMError on any failure."""


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, api_key: str, model: str, base_url: str, *,
                 timeout: float = 30.0, transport: httpx.BaseTransport | None = None):
        self._api_key = api_key
        self._model = model
        self._url = f"{base_url.rstrip('/')}/chat/completions"
        self._timeout = timeout
        self._transport = transport  # injectable for tests
        self.name = f"llm:{model}"

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self._model,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                response = client.post(self._url, json=payload,
                                       headers={"Authorization": f"Bearer {self._api_key}"})
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as exc:
            # Status only: response bodies and headers are not echoed, the key never is.
            raise LLMError(f"LLM endpoint returned HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from exc
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError("LLM response did not have the expected chat-completions shape") from exc


def get_llm_provider() -> LLMProvider | None:
    settings = get_settings()
    if not settings.llm_api_key or not settings.llm_model:
        return None
    return OpenAICompatibleProvider(settings.llm_api_key, settings.llm_model, settings.llm_base_url)
