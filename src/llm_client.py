"""Provider-agnostic chat client with retries and clear error messages."""

import time
from dataclasses import dataclass

import requests


class LLMError(Exception):
    """Any failure talking to a model provider. Messages are safe to show to users."""


@dataclass(frozen=True)
class LLMConfig:
    kind: str            # "openai" (any /chat/completions API) or "anthropic"
    base_url: str
    model: str
    api_key: str
    temperature: float = 0.2
    max_tokens: int = 1000
    timeout: int = 60


_RETRY_STATUS = {429, 500, 502, 503, 504}


def _post(url: str, headers: dict, payload: dict, timeout: int, retries: int = 3) -> dict:
    delay = 2.0
    for attempt in range(retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            if attempt == retries:
                raise LLMError(f"Could not reach the provider ({type(exc).__name__}). Check the base URL and your network.")
            time.sleep(delay)
            delay *= 2
            continue

        if resp.status_code in _RETRY_STATUS and attempt < retries:
            try:
                wait = float(resp.headers.get("retry-after", delay))
            except ValueError:
                wait = delay
            time.sleep(min(wait, 30))
            delay *= 2
            continue

        if resp.status_code in (401, 403):
            raise LLMError("The provider rejected the API key (401/403). Check the key and the selected provider.")
        if resp.status_code == 404:
            raise LLMError("Not found (404). Check the model name and base URL.")
        if resp.status_code == 429:
            raise LLMError("Rate limit still exceeded after retries. Lower the parallel workers or wait a minute.")
        if resp.status_code >= 400:
            raise LLMError(f"Provider error HTTP {resp.status_code}: {resp.text[:200]}")

        try:
            return resp.json()
        except ValueError:
            raise LLMError("The provider returned a non-JSON response.")
    raise LLMError("Request failed.")  # pragma: no cover


def _query_openai(cfg: LLMConfig, prompt: str, system: str | None) -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {
        "model": cfg.model,
        "messages": messages,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    if "gpt-oss" in cfg.model:
        # Reasoning models spend tokens thinking; keep that small so the answer is not cut off.
        payload["reasoning_effort"] = "low"
    data = _post(
        f"{cfg.base_url.rstrip('/')}/chat/completions",
        {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
        payload,
        cfg.timeout,
    )
    try:
        content = data["choices"][0]["message"].get("content") or ""
    except (KeyError, IndexError, TypeError):
        raise LLMError("Unexpected response format from the provider.")
    if not content.strip():
        # An empty reply would be silently scored as a pass, so surface it as an error instead.
        raise LLMError("The model returned an empty reply (it may have used its whole token budget on reasoning).")
    return content


def _query_anthropic(cfg: LLMConfig, prompt: str, system: str | None) -> str:
    payload = {
        "model": cfg.model,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        payload["system"] = system
    data = _post(
        f"{cfg.base_url.rstrip('/')}/messages",
        {
            "x-api-key": cfg.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        payload,
        cfg.timeout,
    )
    try:
        return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
    except (KeyError, TypeError):
        raise LLMError("Unexpected response format from the provider.")


def query_llm(cfg: LLMConfig, prompt: str, system: str | None = None) -> str:
    if not cfg.api_key:
        raise LLMError("No API key provided.")
    if cfg.kind == "anthropic":
        return _query_anthropic(cfg, prompt, system)
    return _query_openai(cfg, prompt, system)
