from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from openai import AsyncOpenAI

from src.services.pipeline import _extract_cash_code

from .schemas import GenerationResult


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def complete_openrouter(
    *,
    model: str,
    user_prompt: str,
    system_prompt: str,
    temperature: float,
    max_tokens: int,
    api_key: Optional[str] = None,
) -> dict[str, Any]:
    key = api_key or os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    client = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=key,
        default_headers={
            "HTTP-Referer": "http://localhost",
            "X-Title": "NexOps-ModelLab",
        },
    )
    started = time.perf_counter()
    create_kwargs: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    response = await client.chat.completions.create(**create_kwargs)
    latency_ms = int((time.perf_counter() - started) * 1000)
    choice = response.choices[0]
    msg = choice.message
    content = msg.content or ""
    if not content.strip():
        reasoning = getattr(msg, "reasoning", None)
        if reasoning:
            content = reasoning
        else:
            extra = getattr(msg, "model_extra", None) or {}
            if isinstance(extra, dict):
                content = extra.get("reasoning") or extra.get("reasoning_content") or ""
    finish_reason = getattr(choice, "finish_reason", None)
    usage = response.usage
    tokens = None
    if usage is not None:
        tokens = {
            "prompt": usage.prompt_tokens or 0,
            "completion": usage.completion_tokens or 0,
            "total": usage.total_tokens or 0,
        }
    return {
        "content": content,
        "tokens": tokens,
        "latency_ms": latency_ms,
        "actual_model": response.model,
        "finish_reason": finish_reason,
    }


async def generate_for_model(
    *,
    model_slug: str,
    model_alias: str,
    prompt_id: str,
    system_prompt: str,
    user_prompt: str,
    phase1_model: str,
    temperature: float,
    max_tokens: int,
) -> tuple[GenerationResult, str]:
    """Return metadata and extracted CashScript."""
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        raw = await complete_openrouter(
            model=model_slug,
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        response_text = raw["content"]
        error = None
        success = True
        if not response_text.strip():
            completion = (raw.get("tokens") or {}).get("completion", 0)
            finish = raw.get("finish_reason")
            if completion > 0:
                error = (
                    f"empty response body (completion_tokens={completion}, "
                    f"finish_reason={finish})"
                )
                success = False
    except Exception as exc:
        response_text = f"ERROR: {exc}"
        raw = {"tokens": None, "latency_ms": 0}
        error = str(exc)
        success = False

    extracted = _extract_cash_code(response_text)
    meta = GenerationResult(
        model=model_slug,
        model_alias=model_alias,
        prompt_id=prompt_id,
        timestamp=timestamp,
        temperature=temperature,
        max_tokens=max_tokens,
        phase1_model=phase1_model,
        tokens=raw.get("tokens"),
        latency_ms=raw.get("latency_ms", 0),
        response_sha256=sha256_text(response_text),
        extracted_sha256=sha256_text(extracted),
        response=response_text,
        error=error,
        success=success,
    )
    return meta, extracted
