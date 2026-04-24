from typing import Dict, List


def canonical_pattern(contract_mode: str) -> str:
    mode = (contract_mode or "").lower().strip()
    alias_map = {
        "escrow_2of3_nft": "escrow",
        "refundable_crowdfund": "refundable_payment",
        "dutch_auction": "decay",
        "linear_vesting": "decay",
        "streaming": "decay",
        "distribution": "single_sig_transfer",
        "swap": "conditional_spend",
        "stateful": "covenant",
        "token": "token",
        "minting": "minting",
        "minter": "minting",
        "parser": "parser",
        "manager": "manager",
        "hybrid": "hybrid",
    }
    return alias_map.get(mode, mode or "generic")


PATTERN_PROFILES: Dict[str, Dict[str, List[str]]] = {
    "single_sig_transfer": {
        "knowledge_files": ["single_sig_transfer_rules.yaml"],
        "disable_lint_rules": ["LNC-008", "LNC-016"],
        "disable_detectors": ["missing_output_anchor"],
    },
    "timelock": {
        "knowledge_files": ["timelock_rules.yaml"],
        "disable_lint_rules": ["LNC-008", "LNC-016"],
        "disable_detectors": ["missing_output_anchor"],
    },
    "hashlock": {
        "knowledge_files": ["hashlock_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
    "multisig": {
        "knowledge_files": ["multisig_rules.yaml"],
        "disable_lint_rules": ["LNC-008", "LNC-016"],
        "disable_detectors": ["missing_output_anchor"],
    },
    "escrow": {
        "knowledge_files": ["escrow_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
    "refundable_payment": {
        "knowledge_files": ["refundable_payment_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
    "split_payment": {
        "knowledge_files": ["split_rules.yaml"],
        "disable_lint_rules": ["LNC-016"],
        "disable_detectors": [],
    },
    "vault": {
        "knowledge_files": ["vault_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [
            "missing_output_anchor",
            "missing_output_limit",
            "missing_value_enforcement",
            "output_binding_missing",
        ],
    },
    "covenant": {
        "knowledge_files": ["covenant_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
    "token": {
        "knowledge_files": ["covenant_rules.yaml", "cashtokens_rules.yaml", "nft_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
    "minting": {
        "knowledge_files": ["covenant_rules.yaml", "cashtokens_rules.yaml", "nft_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [
            "missing_output_limit",
            "missing_value_enforcement",
            "missing_token_amount_validation",
            "output_binding_missing",
        ],
    },
    "parser": {
        "knowledge_files": ["covenant_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [
            "missing_output_limit",
            "missing_value_enforcement",
            "missing_output_anchor",
            "weak_output_count_limit",
            "output_binding_missing",
            "partial_aggregation_risk",
        ],
    },
    "manager": {
        "knowledge_files": ["covenant_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
    "hybrid": {
        "knowledge_files": ["covenant_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": ["output_binding_missing"],
    },
    "conditional_spend": {
        "knowledge_files": ["conditional_spend_rules.yaml"],
        "disable_lint_rules": ["LNC-008", "LNC-016"],
        "disable_detectors": ["missing_output_anchor"],
    },
    "decay": {
        "knowledge_files": ["decay_rules.yaml"],
        "disable_lint_rules": [],
        "disable_detectors": [],
    },
}


def get_pattern_profile(contract_mode: str) -> Dict[str, List[str]]:
    pattern = canonical_pattern(contract_mode)
    return PATTERN_PROFILES.get(
        pattern,
        {"knowledge_files": [], "disable_lint_rules": [], "disable_detectors": []},
    )
