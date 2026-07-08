"""Phase 1A — classify-only intent extraction (no guessing)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from src.models import RawIntent

logger = logging.getLogger("nexops.spec.extraction")


def build_phase1a_prompt(intent: str) -> str:
    return f"""You are the NexOps Intent Classifier. Classify ONLY — do not invent values.

Rules:
1. Set "intent" to the high-level pattern (treasury, escrow, vault, multisig, token, etc.).
2. List "capabilities" using ONLY names from this set when applicable:
   treasury, weighted_multisig, linear_decay, withdrawal_policy, multisig, timelock,
   escrow, split, vault, token_ft, nft_immutable, nft_mutable, nft_minting, hybrid_token
3. Put ONLY values explicitly stated by the user in "constraints". Do NOT guess.
4. Do NOT include defaults, signer counts, thresholds, or weights unless the user stated them.

User request: "{intent}"

If the message is NOT a contract request (greeting, small talk, off-topic, or unclear), return:
{{"intent": "", "capabilities": [], "constraints": {{}}}}
Do NOT guess a contract type for greetings or casual chat.

Output ONLY valid JSON:
{{
  "intent": "...",
  "capabilities": ["..."],
  "constraints": {{}}
}}

Return ONLY the JSON object. No markdown. No explanation."""


def parse_extraction(raw: str) -> RawIntent:
    text = raw.strip()
    if text.startswith("```json"):
        text = text[7:].strip()
    if text.startswith("```"):
        text = text[3:].strip()
    if text.endswith("```"):
        text = text[:-3].strip()
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("expected object")
        return RawIntent(
            intent=str(data.get("intent") or ""),
            capabilities=[str(c) for c in (data.get("capabilities") or [])],
            constraints=dict(data.get("constraints") or {}),
        )
    except Exception as exc:
        logger.warning("Phase1A parse failed: %s", exc)
        return RawIntent(intent="", capabilities=[], constraints={})


async def extract_intent(
    intent: str,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    phase1_model: Optional[str] = None,
) -> RawIntent:
    from src.services.llm.factory import LLMFactory

    prompt = build_phase1a_prompt(intent)
    if phase1_model:
        from src.services.llm.base import LLMConfig, ResilientProvider
        from src.services.llm.openrouter import OpenRouterProvider

        llm = ResilientProvider(
            LLMConfig(
                OpenRouterProvider(model=phase1_model, api_key=openrouter_key or api_key),
                temperature=0.0,
                label=f"Phase1A-{phase1_model}",
                max_tokens=512,
            )
        )
    else:
        llm = LLMFactory.get_provider(
            "phase1",
            api_key=api_key,
            provider_type=provider,
            openrouter_key=openrouter_key,
        )
    raw = await llm.complete(prompt)
    parsed = parse_extraction(raw)
    if not parsed.intent:
        parsed.intent = intent.split()[0].lower() if intent else "generic"
    return parsed
