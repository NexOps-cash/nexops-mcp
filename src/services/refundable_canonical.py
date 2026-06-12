"""Deterministic refundable canonical templates (Phase 1B).

Returns pre-validated .cash for subscription (rp_003) and gradual-release (rp_004)
intents without LLM synthesis.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("nexops.refundable_canonical")

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "knowledge" / "templates"

_TEMPLATE_FILES = {
    "refundable_subscription_escrow": "refundable_subscription_escrow.cash",
    "refundable_gradual_release": "refundable_gradual_release.cash",
}


def match_refundable_canonical_template(intent: str) -> str | None:
    """Return template id for narrow refundable subscription / vesting intents."""
    text = (intent or "").lower()
    if not text:
        return None
    if _matches_subscription(text):
        return "refundable_subscription_escrow"
    if _matches_gradual_release(text):
        return "refundable_gradual_release"
    return None


def load_refundable_canonical_template(template_id: str) -> str | None:
    filename = _TEMPLATE_FILES.get(template_id)
    if not filename:
        return None
    path = _TEMPLATES_DIR / filename
    if not path.is_file():
        logger.warning("[RefundableCanonical] Missing template file: %s", path)
        return None
    return path.read_text(encoding="utf-8")


def resolve_refundable_canonical_code(intent: str) -> str | None:
    template_id = match_refundable_canonical_template(intent)
    if not template_id:
        return None
    code = load_refundable_canonical_template(template_id)
    if code:
        logger.info("[RefundableCanonical] Using template: %s", template_id)
    return code


def _matches_subscription(text: str) -> bool:
    if "subscription" not in text:
        return False
    if "crowdfund" in text or "fundrais" in text:
        return False
    return any(
        w in text
        for w in ("cancel", "reclaim", "monthly", "subscriber", "service can claim")
    )


def _matches_gradual_release(text: str) -> bool:
    if any(w in text for w in ("crowdfund", "fundrais", "goal", "backers")):
        return False
    has_gradual = any(
        w in text
        for w in ("gradual", "25%", "every 7 days", "linear release", "vesting")
    )
    has_reclaim = any(w in text for w in ("reclaim", "inactive", "refund", "sender"))
    return has_gradual and has_reclaim
