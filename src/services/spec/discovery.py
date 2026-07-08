"""Discovery phase — converse until a contract pattern is identified."""

from __future__ import annotations

from typing import Optional

from src.models import CapabilityInstance, ContractSpecification, RawIntent, SpecStatus
from src.services.spec.detection import detect_capabilities
from src.services.spec.validator import SpecValidator


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
