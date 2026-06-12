"""Deterministic vault canonical templates for high-flake real-world intents.

Returns pre-validated .cash sources without LLM synthesis when intent text
matches a narrow backup-cancel or founder-treasury profile (Vault Phase 1B P0).
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("nexops.vault_canonical")

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "knowledge" / "templates"

_TEMPLATE_FILES = {
    "vault_backup_cancel": "vault_backup_cancel.cash",
    "vault_founder_treasury": "vault_founder_treasury.cash",
}


def match_vault_canonical_template(intent: str, *, effective_mode: str = "") -> str | None:
    """Return template id when intent matches a canonical vault profile."""
    if (effective_mode or "").lower() != "vault":
        return None

    text = (intent or "").lower()
    if not text:
        return None

    if _matches_backup_cancel(text):
        return "vault_backup_cancel"

    if _matches_founder_treasury(text):
        return "vault_founder_treasury"

    return None


def load_vault_canonical_template(template_id: str) -> str | None:
    """Load template source by id."""
    filename = _TEMPLATE_FILES.get(template_id)
    if not filename:
        return None
    path = _TEMPLATES_DIR / filename
    if not path.is_file():
        logger.warning("[VaultCanonical] Missing template file: %s", path)
        return None
    return path.read_text(encoding="utf-8")


def resolve_vault_canonical_code(intent: str, *, effective_mode: str = "") -> str | None:
    """Match intent and return template source, or None."""
    template_id = match_vault_canonical_template(intent, effective_mode=effective_mode)
    if not template_id:
        return None
    code = load_vault_canonical_template(template_id)
    if code:
        logger.info("[VaultCanonical] Using template: %s", template_id)
    return code


def _matches_backup_cancel(text: str) -> bool:
    """Safety wallet: announce withdrawal, delayed claim, backup cancels first."""
    if "backup" not in text or "cancel" not in text:
        return False
    return any(
        w in text
        for w in (
            "announce",
            "claim",
            "safety",
            "safety wallet",
            "withdrawal today",
            "unless my backup",
        )
    )


def _matches_founder_treasury(text: str) -> bool:
    """Founder treasury: instant small ops + delayed large moves + cold recovery."""
    if "founder" not in text:
        return False
    if not any(w in text for w in ("treasury", "cold key", "cold recovery", "cold")):
        return False
    return any(
        w in text
        for w in (
            "small",
            "ops",
            "operation",
            "expense",
            "instant",
            "easy",
            "recover immediately",
            "recover",
        )
    )
