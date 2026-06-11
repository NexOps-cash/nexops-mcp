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
        ctype = (model.contract_type or "").lower()

        # Feature Mapping & Pattern Evidence
        checks = {
            "timelock": [r"tx\.time", r"this\.age", r"tx\.age"],
            "multisig": [r"checkSig", r"checkMultiSig", r"pubkey"],
            "escrow": [r"tx\.outputs", r"lockingBytecode"],
            "tokens": [r"tokenCategory", r"tokenAmount"],
            "minting": [r"tokenAmount"],
            "stateful": [r"this\.activeBytecode", r"this\.age", r"activeInputIndex"],
        }

        # 1. Feature -> Pattern Evidence
        for feature in features:
            if feature in checks:
                patterns = checks[feature]
                if feature == "minting" and ctype in {
                    "nft_minting_authority",
                    "nft_minting_failure",
                    "nft_minting",
                }:
                    patterns = list(patterns) + [r"tokenCategory", r"nftCommitment"]
                if not any(re.search(p, code) for p in patterns):
                    violations.append(f"Intent specified '{feature}' but no evidence (e.g., {patterns[0]}) found in code.")

        # 2. Signature Accountancy (skip for CashTokens covenant modes — single-owner vault/mint)
        _skip_multisig_accountancy = ctype in {
            "hybrid_token",
            "stablecoin_minter_sidecar",
            "nft_mutable_state_update",
            "nft_minting_authority",
            "nft_minting_failure",
        }
        if "multisig" in features and model.threshold and not _skip_multisig_accountancy:
            # Count distinct pubkeys used in checkSig
            pubkeys = set(re.findall(r"pubkey\s+(\w+)", code))
            if len(pubkeys) < model.threshold:
                violations.append(f"Intent required {model.threshold}-of-{len(model.signers)} multisig, but found only {len(pubkeys)} pubkeys defined.")

        # 3. Time Validation Operator Check
        if "timelock" in features:
            if not re.search(r">=", code) and re.search(r"tx\.time", code):
                violations.append("Timelock detected but secure operator '>=' is missing for temporal check.")

        # 4. Pattern-specific deterministic checks (minimal branching, no major refactor)
        if ctype in {"vault", "covenant", "stateful"}:
            if not re.search(r"this\.activeBytecode", code):
                violations.append(f"{ctype} intent requires covenant continuation signal (this.activeBytecode).")

        if ctype == "split_payment" or "split" in features:
            from src.utils.split_conservation import (
                has_bch_value_conservation,
                has_token_amount_conservation,
            )
            if not re.search(r"tx\.outputs\.length", code):
                violations.append("Split payment intent requires explicit output-count validation.")
            has_conservation = has_bch_value_conservation(code)
            if "tokenAmount" in code:
                has_conservation = has_conservation or has_token_amount_conservation(code)
            if not has_conservation:
                violations.append("Split payment intent requires sum-preservation check across multiple outputs.")

        if ctype in {"decay", "streaming", "dutch_auction", "linear_vesting"}:
            # Require evidence of elapsed-time arithmetic so model doesn't hallucinate unrelated logic.
            has_elapsed = bool(re.search(r"(elapsed|passed|age|timeDiff|blocksPassed)", code, re.IGNORECASE))
            has_arith = bool(re.search(r"[\+\-\*/]", code))
            if not (has_elapsed and has_arith):
                violations.append("Decay/streaming intent requires explicit elapsed-time arithmetic formula.")

        _skip_token_amount_pairing = ctype in {
            "nft_minting_authority",
            "nft_minting_failure",
            "nft_minting",
            "hybrid_token",
            "stablecoin_minter_sidecar",
            "nft_mutable_state_update",
            "nft_immutable",
            "nft_transfer_immutable",
            "ft_transfer",
            "token_ft",
        }
        if not _skip_token_amount_pairing and (
            ctype in {"token", "minting", "escrow_2of3_nft"}
            or "tokens" in features
            or "minting" in features
        ):
            if re.search(r"tokenCategory", code) and not re.search(r"tokenAmount", code):
                violations.append("Token logic references tokenCategory but misses tokenAmount validation.")
            if re.search(r"tokenAmount", code) and not re.search(r"tokenCategory", code):
                violations.append("Token logic references tokenAmount but misses tokenCategory validation.")

        success = len(violations) == 0
        return {
            "success": success,
            "violations": violations
        }

def get_sanity_checker() -> SanityChecker:
    return SanityChecker()
