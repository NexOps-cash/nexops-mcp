import re
import logging
from typing import List, Dict, Any, Optional
from src.models import IntentModel

logger = logging.getLogger("nexops.sanity_checker")

class SanityChecker:
    """
    Phase 4: Intent Sanity Check (Deterministic Semantic Layer)
    Lightweight validation based on Intent Model.
    """

    @staticmethod
    def validate(code: str, model: IntentModel) -> Dict[str, Any]:
        """
        Check if code contains evidence for features required by the intent model.
        Returns result dict: success (bool), violations (list of strings)
        """
        violations = []
        features = model.features or []

        # Feature Mapping & Pattern Evidence
        checks = {
            "timelock": [r"tx\.time", r"tx\.age"],
            "multisig": [r"checkSig", r"checkMultiSig", r"pubkey"],
            "escrow": [r"tx\.outputs", r"lockingBytecode"],
            "tokens": [r"tokenCategory", r"tokenAmount"],
            "minting": [r"tokenAmount"],
            "stateful": [r"this\.lockingBytecode", r"activeInputIndex"],
        }

        # 1. Feature -> Pattern Evidence
        for feature in features:
            if feature in checks:
                patterns = checks[feature]
                if not any(re.search(p, code) for p in patterns):
                    violations.append(f"Intent specified '{feature}' but no evidence (e.g., {patterns[0]}) found in code.")

        # 2. Signature Accountancy
        if "multisig" in features and model.threshold:
            # Count distinct pubkeys used in checkSig
            pubkeys = set(re.findall(r"pubkey\s+(\w+)", code))
            if len(pubkeys) < model.threshold:
                violations.append(f"Intent required {model.threshold}-of-{len(model.signers)} multisig, but found only {len(pubkeys)} pubkeys defined.")

        # 3. Time Validation Operator Check
        if "timelock" in features:
            if not re.search(r">=", code) and re.search(r"tx\.time", code):
                violations.append("Timelock detected but secure operator '>=' is missing for temporal check.")

        success = len(violations) == 0
        return {
            "success": success,
            "violations": violations
        }

def get_sanity_checker() -> SanityChecker:
    return SanityChecker()
