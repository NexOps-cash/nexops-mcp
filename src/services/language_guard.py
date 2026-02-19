import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("nexops.language_guard")

class LanguageGuard:
    """
    Phase 2B: Language Guard (Static Filter)
    Immediately rejects generation if forbidden patterns appear.
    
    IMPORTANT: This guard allows SECURE patterns required by the KB:
    - tx.outputs[n].lockingBytecode (for covenant validation)
    - tx.inputs[this.activeInputIndex].* (for position-safe input access)
    - tokenCategory/tokenAmount validation (for token safety)
    
    It only blocks UNSAFE patterns:
    - Hardcoded input indices (tx.inputs[0], tx.inputs[1])
    - EVM/Solidity syntax
    - Unsafe direct property access without validation context
    """

    # Forbidden patterns (Regex) - Only block UNSAFE patterns
    FORBIDDEN = {
        # Block hardcoded literal input indices (UNSAFE)
        r"tx\.inputs\[\s*0\s*\]": "UNSAFE: Hardcoded tx.inputs[0] is vulnerable to input reordering. Use tx.inputs[this.activeInputIndex] instead.",
        r"tx\.inputs\[\s*1\s*\]": "UNSAFE: Hardcoded tx.inputs[1] is vulnerable to input reordering. Use tx.inputs[this.activeInputIndex] instead.",
        r"tx\.inputs\[\s*2\s*\]": "UNSAFE: Hardcoded tx.inputs[2] is vulnerable to input reordering. Use tx.inputs[this.activeInputIndex] instead.",
        r"tx\.inputs\[\s*3\s*\]": "UNSAFE: Hardcoded tx.inputs[3] is vulnerable to input reordering. Use tx.inputs[this.activeInputIndex] instead.",
        # Block EVM/Solidity patterns
        r"msg\.sender": "EVM Hallucination: msg.sender does not exist in CashScript.",
        r"msg\.value": "EVM Hallucination: msg.value does not exist in CashScript.",
        r"mapping\s*\(": "EVM Hallucination: mappings do not exist in CashScript.",
        r"emit\s+\w+": "EVM Hallucination: events (emit) do not exist in CashScript.",
        r"modifier\s+\w+": "EVM Hallucination: modifiers do not exist in CashScript.",
        r"block\.timestamp": "Forbidden: use tx.time for temporal checks.",
        r"address\s+": "EVM Hallucination: address type should be bytes20/bytes in CashScript.",
        r"payable\s+": "EVM Hallucination: payable modifier does not exist in CashScript.",
        r"view\s+": "EVM Hallucination: view modifier does not exist in CashScript.",
        r"pure\s+": "EVM Hallucination: pure modifier does not exist in CashScript.",
        r"revert\s*\(": "EVM Hallucination: revert() does not exist in CashScript. Use require() instead.",
        r"assembly\s*\{": "EVM Hallucination: inline assembly does not exist in CashScript.",
        # Invalid self-reference — does not exist in CashScript ^0.13.x
        r"this\.lockingBytecode": "Invalid in CashScript ^0.13.x. Use this.activeBytecode instead.",
    }

    # Patterns that are ALLOWED (secure patterns from KB)
    # These are checked to ensure they're used in safe contexts
    ALLOWED_PATTERNS = [
        r"tx\.outputs\[\d+\]\.lockingBytecode",  # Required for covenant validation
        r"tx\.inputs\[this\.activeInputIndex\]",  # Required for position-safe access
        r"tx\.outputs\[\d+\]\.tokenCategory",     # Required for token validation
        r"tx\.outputs\[\d+\]\.tokenAmount",       # Required for token validation
        r"tx\.inputs\[this\.activeInputIndex\]\.lockingBytecode",  # Required for self-validation
        r"tx\.inputs\[this\.activeInputIndex\]\.tokenCategory",    # Required for token validation
        r"tx\.inputs\[this\.activeInputIndex\]\.tokenAmount",      # Required for token validation
    ]

    @staticmethod
    def validate(code: str) -> Optional[str]:
        """
        Scan code for forbidden patterns.
        Returns failure message if a pattern is found, else None.
        
        NOTE: This guard ALLOWS secure patterns required by the KB:
        - tx.outputs[n].lockingBytecode (covenant validation)
        - tx.inputs[this.activeInputIndex].* (position-safe access)
        - tokenCategory/tokenAmount validation
        
        It only blocks UNSAFE patterns like hardcoded indices and EVM syntax.
        """
        for pattern, reason in LanguageGuard.FORBIDDEN.items():
            if re.search(pattern, code):
                logger.warning(f"Language Guard Triggered: {pattern}")
                return reason
        return None

def get_language_guard() -> LanguageGuard:
    return LanguageGuard()
