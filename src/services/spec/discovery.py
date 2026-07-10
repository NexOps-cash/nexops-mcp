"""Discovery phase — converse until a contract pattern is identified."""

from __future__ import annotations

from typing import Optional

from src.models import CapabilityInstance, ContractSpecification, RawIntent, SpecStatus
from src.services.spec.detection import detect_capabilities
from src.services.spec.validator import SpecValidator

_GREETING_ONLY = frozenset({
    "hi",
    "hello",
    "hey",
    "yo",
    "sup",
    "hiya",
    "howdy",
    "good morning",
    "good afternoon",
    "good evening",
})

_CONTRACT_HINTS = (
    "contract",
    "vault",
    "treasury",
    "escrow",
    "multisig",
    "split",
    "distribute",
    "vest",
    "vesting",
    "auction",
    "token",
    "nft",
    "timelock",
    "refund",
    "dao",
    "governance",
    "founder",
    "payroll",
    "hashlock",
    "covenant",
    "wallet",
    "bch",
    "bitcoin",
)


def lacks_contract_signal(text: str) -> bool:
    """True for greetings and messages with no identifiable contract intent."""
    t = text.strip().lower()
    if not t:
        return True
    normalized = t.rstrip("!?. ")
    if normalized in _GREETING_ONLY:
        return True
    if any(hint in t for hint in _CONTRACT_HINTS):
        return False
    # Very short messages without contract vocabulary are discovery, not specs.
    if len(t) < 20:
        return True
    return False


def has_ambiguous_pattern_choice(text: str) -> bool:
    """True when the user names multiple distinct contract patterns (e.g. vesting or auction)."""
    t = text.strip().lower()
    if not t:
        return False

    primary: set[str] = set()
    if any(k in t for k in ("vest", "vesting", "founder", "cliff")):
        primary.add("vesting")
    if "auction" in t or "dutch" in t or "bid" in t:
        primary.add("auction")
    if "escrow" in t or "arbiter" in t:
        primary.add("escrow")
    if any(k in t for k in ("treasury", "dao", "governance")):
        primary.add("treasury")
    if "multisig" in t and "escrow" not in t:
        primary.add("multisig")

    if len(primary) >= 2:
        return True
    if (" or " in t or " vs " in t or " versus " in t) and len(primary) >= 1:
        # "founders vesting or an auction" — OR with any pattern hint stays exploratory
        if " or " in t and any(h in t for h in _CONTRACT_HINTS):
            return True
    return False


def is_pushback_or_confusion(message: str) -> bool:
    """User is confused, frustrated, or asking to pause — do not append field wizard nudges."""
    t = message.strip().lower().rstrip(".!?")
    if t in {"wtf", "wth", "huh", "what", "why", "wait", "hold on", "hang on", "stop", "slow down"}:
        return True
    return any(
        p in t
        for p in (
            "what do you mean",
            "slow down",
            "hold on",
            "hang on",
            "that doesn't",
            "doesn't make sense",
            "make no sense",
            "back up",
            "too fast",
        )
    )


def is_in_discovery_phase(spec: ContractSpecification) -> bool:
    return not spec.capabilities


def try_discover_specification(
    spec: ContractSpecification,
    user_message: str,
) -> Optional[ContractSpecification]:
    """
    Promote chit-chat into a structured spec when the message carries contract signal.
    Uses keyword + Phase1A extraction results already merged in detect_capabilities.
    """
    if spec.capabilities:
        return None

    if has_ambiguous_pattern_choice(user_message):
        return None

    detected = detect_capabilities(
        RawIntent(intent=user_message.strip(), capabilities=[], constraints={}),
        original_intent=user_message,
    )
    if not detected.capabilities:
        return None

    labels = ", ".join(c.name.replace("_", " ") for c in detected.capabilities)
    discovered = ContractSpecification(
        intent=user_message.strip() or spec.intent,
        capabilities=list(detected.capabilities),
        parameters=dict(spec.parameters),
        confirmed_fields=list(spec.confirmed_fields),
        pending_parameters=dict(spec.pending_parameters),
        status=SpecStatus.NEEDS_INPUT,
    )
    validation = SpecValidator.validate(discovered)
    discovered.status = (
        SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
    )
    discovered.intent = discovered.intent or labels
    return discovered
