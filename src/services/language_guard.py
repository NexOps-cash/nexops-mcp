import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("nexops.language_guard")

class LanguageGuard:
    """
    Phase 2B: Language Guard (Static Filter)
    Immediately rejects generation if forbidden patterns appear.
    """

    # Forbidden patterns (Regex)
    FORBIDDEN = {
        r"\.lockingBytecode": "Accessing .lockingBytecode directly is forbidden. Use this.lockingBytecode or validate lockingBytecode for outputs.",
        r"\.tokenCategory": "Direct .tokenCategory access is forbidden. Validate lockingBytecode first.",
        r"\.tokenAmount": "Direct .tokenAmount access is forbidden. Validate lockingBytecode first.",
        r"msg\.sender": "EVM Hallucination: msg.sender does not exist in CashScript.",
        r"tx\.inputs\[": "Accessing tx.inputs by index is generally restricted to this.activeInputIndex.",
        r"mapping\s*\(": "EVM Hallucination: mappings do not exist in CashScript.",
        r"emit\s+\w+": "EVM Hallucination: events (emit) do not exist in CashScript.",
        r"modifier\s+\w+": "EVM Hallucination: modifiers do not exist in CashScript.",
        r"block\.timestamp": "Forbidden: use tx.time for temporal checks.",
        r"address\s+": "EVM Hallucination: address type should be bytes20/bytes in CashScript.",
    }

    @staticmethod
    def validate(code: str) -> Optional[str]:
        """
        Scan code for forbidden patterns.
        Returns failure message if a pattern is found, else None.
        """
        for pattern, reason in LanguageGuard.FORBIDDEN.items():
            if re.search(pattern, code):
                logger.warning(f"Language Guard Triggered: {pattern}")
                return reason
        return None

def get_language_guard() -> LanguageGuard:
    return LanguageGuard()
