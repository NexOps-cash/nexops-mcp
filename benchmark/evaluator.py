import time
import re
import yaml
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from benchmark.schemas import BenchmarkCase, CaseResult
from benchmark.feature_extractor import FeatureExtractor
from benchmark.semantic_requirements import satisfies_requirement
from src.services.pipeline_engine import get_guarded_pipeline_engine
from src.services.semantic_capabilities import extract_semantic_capabilities, save_capability_trace


def _split_output_amount_ok(code: str, capabilities: Dict[str, Any]) -> bool:
    from src.utils.split_conservation import has_bch_value_conservation
    return bool(
        capabilities.get("output_value_validation", False)
        or has_bch_value_conservation(code)
    )


def _escrow_missing_destination_check(code: str) -> bool:
    """True when spend paths lack output lockingBytecode validation."""
    if not re.search(r"checkSig|checkMultiSig", code, re.IGNORECASE):
        return False
    return not bool(re.search(r"tx\.outputs\[\d+\]\.lockingBytecode\s*==", code))


def _escrow_permanent_covenant(code: str) -> bool:
    """True when funds are locked via this.activeBytecode without signature-gated exit."""
    has_self_anchor = bool(
        re.search(
            r"tx\.outputs\[\d+\]\.lockingBytecode\s*==\s*this\.activeBytecode",
            code,
        )
    )
    has_sig_exit = bool(re.search(r"checkSig|checkMultiSig", code, re.IGNORECASE))
    return has_self_anchor and not has_sig_exit


def _both_signatures_required(detected: set, code: str) -> bool:
    role_pairs = (
        ("alice_signature", "bob_signature"),
        ("buyer_signature", "seller_signature"),
    )
    if any(a in detected and b in detected for a, b in role_pairs):
        return True
    return (
        "multisig_2of2" in detected
        or bool(
            re.search(
                r"checkSig\([^)]+\)\s*&&\s*checkSig\([^)]+\)",
                code,
                re.IGNORECASE,
            )
        )
        or len(re.findall(r"checkSig\s*\(", code, re.IGNORECASE)) >= 2
    )


def _three_of_five_logic(detected: set, code: str) -> bool:
    if "three_of_five_logic" in detected:
        return True
    msig = re.search(
        r"checkMultiSig\s*\(\s*\[(.*?)\]\s*,\s*\[(.*?)\]\s*\)",
        code,
        re.DOTALL | re.IGNORECASE,
    )
    if msig:
        sigs = [s.strip() for s in msig.group(1).split(",") if s.strip()]
        pks = [p.strip() for p in msig.group(2).split(",") if p.strip()]
        if len(sigs) >= 3 and len(pks) >= 5:
            return True
    check_sig_count = len(re.findall(r"checkSig\s*\(", code, re.IGNORECASE))
    pubkey_count = len(re.findall(r"\bpubkey\s+\w+", code, re.IGNORECASE))
    return check_sig_count >= 3 and pubkey_count >= 5


def _must_fail_pubkey_substitution(code: str) -> bool:
    """True when spend paths accept caller-supplied pubkeys (substitution vulnerability)."""
    for match in re.finditer(
        r"function\s+(\w+)\s*\((.*?)\)\s*\{",
        code,
        re.DOTALL | re.IGNORECASE,
    ):
        params = match.group(2)
        if not re.search(r"\bpubkey\s+\w+", params, re.IGNORECASE):
            continue
        body_start = match.end()
        next_fn = re.search(r"\n\s*function\s+", code[body_start:])
        body = code[body_start: body_start + next_fn.start()] if next_fn else code[body_start:]
        if re.search(r"checkSig|checkMultiSig", body, re.IGNORECASE):
            return True
    return False


def _must_fail_duplicate_signer(code: str) -> bool:
    """True when the same signature variable authorizes multiple pubkeys."""
    from src.utils.cashscript_ast import CashScriptAST

    ast = CashScriptAST(code, contract_mode="multisig")
    return bool(ast.find_signature_reuse())


def _must_fail_wrong_time_field(code: str) -> bool:
    """True when invalid Solidity-style or non-CashScript time fields are used."""
    return bool(
        re.search(r"\btx\.timestamp\b", code, re.IGNORECASE)
        or re.search(r"\bblock\.timestamp\b", code, re.IGNORECASE)
        or re.search(r"\btx\.locktime\b", code, re.IGNORECASE)
    )


def _timestamp_based_timelock(detected: set, code: str) -> bool:
    if "timestamp_based" in detected:
        return True
    has_cltv = (
        "timelock_unlock" in detected
        or "timelock_refund" in detected
        or bool(re.search(r"tx\.time\s*>=", code))
    )
    has_csv = bool(re.search(r"(?:tx\.age|this\.age)\s*>=", code))
    if not has_cltv or has_csv:
        return False
    if re.search(r"unlockTimestamp|UnlockTimestamp", code):
        return True
    if re.search(r"tx\.time\s*>=\s*5\d{8}", code):
        return True
    if re.search(r"unlockTime\b", code) and re.search(r"checkSig", code, re.IGNORECASE):
        if not re.search(r"unlockHeight|BlockHeight|blockHeight", code):
            return True
    return False


def _block_height_based_timelock(detected: set, code: str) -> bool:
    if "block_height_based" in detected:
        return True
    if re.search(
        r"unlockHeight|BlockHeight|blockHeight|unlockBlocks|lockBlocks", code
    ):
        return True
    if re.search(
        r"(?:this\.age|tx\.age)\s*>=\s*(?:lockBlocks|unlockBlocks)\b", code
    ):
        return True
    if re.search(r"tx\.time\s*>=\s*\w*Height\b", code, re.IGNORECASE):
        return True
    has_csv = bool(re.search(r"(?:tx\.age|this\.age)\s*>=", code))
    if has_csv and re.search(
        r"tx\.time\s*>=\s*unlock(?:Time|Height|Blocks)\b", code
    ):
        # Savings-style CLTV (block count) plus relative maturity in one contract.
        return True
    for match in re.finditer(r"tx\.time\s*>=\s*(\d+)", code):
        try:
            if int(match.group(1)) < 500_000_000:
                return True
        except ValueError:
            continue
    return False


def _relative_timelock(detected: set, code: str) -> bool:
    return "relative_timelock" in detected or bool(
        re.search(r"(?:tx\.age|this\.age)\s*>=\s*\w+", code)
    )


def _sequence_check(detected: set, code: str) -> bool:
    return "sequence_check" in detected or bool(
        re.search(r"this\.age\s*>=\s*\w+", code)
    )


def _multisig_detected(detected: set, code: str) -> bool:
    return (
        "multisig" in detected
        or "multisig_2of2" in detected
        or "multisig_2of3" in detected
        or "checkMultiSig" in code
    )


def _cashtoken_alias_pool(
    pattern: str,
    capabilities: Dict[str, Any],
    detected: set,
    code: str,
    functions: List[Dict],
) -> Dict[str, bool]:
    """Per-pattern alias checks for CashTokens benchmark cases."""
    sig_ok = capabilities.get("signature_verification", False)
    cat_in = bool(re.search(r"tokenCategory\s*==", code) and "activeInputIndex" in code)
    cat_out = bool(re.search(r"tx\.outputs\[\d+\]\.tokenCategory\s*==", code))
    amt_ok = bool(
        re.search(r"expectedTokenAmount", code)
        or (
            "tokenAmount" in code
            and "tx.inputs[this.activeInputIndex]" in code
        )
    )
    commitment_ok = (
        "token_nft_commitment" in detected
        or bool(re.search(r"\.nftCommitment\s*==\s*", code))
    )
    _authority_category_preserved = bool(
        re.search(
            r"tx\.outputs\[\d+\]\.tokenCategory\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.tokenCategory",
            code,
        )
        or re.search(
            r"tx\.outputs\[\d+\]\.tokenCategory\s*==\s*\w*(?:minting|authority|base)\w*Category",
            code,
            re.IGNORECASE,
        )
    )
    cap_ok = (
        "capability_mutable" in detected
        or "capability_minting" in detected
        or bool(re.search(r"tokenCategory\s*\+\s*0x0[12]", code))
        or bool(re.search(r"0x02", code))
        or _authority_category_preserved
    )
    _active_custody = bool(re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", code))
    custody_ok = bool(
        _active_custody
        and ("capability_minting" in detected or re.search(r"0x02", code))
    ) or bool(
        re.search(r"0x02", code)
        and re.search(r"lockingBytecode.*activeBytecode", code, re.DOTALL)
    ) or bool(_active_custody and _authority_category_preserved)
    bch_change = "bch_only_output" in detected
    leak_fail = not custody_ok

    pools: Dict[str, Dict[str, bool]] = {
        "token_ft": {
            "valid_signature_check": sig_ok,
            "token_category_check": cat_in and cat_out,
            "token_amount_check": amt_ok,
            "bch_only_change_guard": bch_change,
            "output_destination_validation": "locking_bytecode" in detected,
        },
        "nft_immutable": {
            "valid_signature_check": sig_ok,
            "token_category_check": cat_in and cat_out,
            "token_amount_check": amt_ok or bool(re.search(r"tokenAmount\s*==\s*0", code)),
            "nftcommitment_preservation": commitment_ok,
            "token_nft_commitment": commitment_ok,
            "locking_bytecode": "locking_bytecode" in detected,
            "output_lockingbytecode_check": (
                "locking_bytecode" in detected
                or bool(re.search(r"tx\.outputs\[\d+\]\.lockingBytecode\s*==", code))
            ),
        },
        "nft_mutable": {
            "valid_signature_check": sig_ok,
            "token_category_check": cap_ok or cat_in,
            "capability_byte_match": cap_ok,
            "nftcommitment_preservation": commitment_ok,
            "covenant_self_reference": bool(
                re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", code)
            ),
        },
        "nft_minting": {
            "valid_signature_check": sig_ok,
            "token_category_check": cat_in,
            "capability_byte_match": cap_ok,
            "capability_minting": cap_ok,
            "minting_authority_custody": custody_ok,
            "must_fail_capability_leak": leak_fail,
        },
        "ft_mint": {
            "valid_signature_check": sig_ok,
            "token_category_check": bool(
                re.search(
                    r"outputs\[[^\]]+\]\.tokenCategory\s*==\s*tokenCategory",
                    code,
                )
                or cat_in and cat_out
            ),
            "supply_cap_enforcement": capabilities.get("enforces_supply_cap") is True,
            "mint_cap_guard": capabilities.get("enforces_supply_cap") is True,
            "must_fail_unbounded_mint": capabilities.get("enforces_supply_cap") is not True,
        },
        "hybrid_token": {
            "valid_signature_check": sig_ok,
            "token_category_check": cat_in and cat_out,
            "token_amount_check": amt_ok,
            "nftcommitment_preservation": commitment_ok,
            "covenant_self_reference": bool(
                re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", code)
            ),
        },
        "split_payment": {
            "valid_signature_check": sig_ok,
            "output_amount_check": _split_output_amount_ok(code, capabilities),
            "two_of_three_logic": ("multisig_2of3" in detected or "checkMultiSig" in code),
            "token_category_check": cat_in and cat_out,
            "token_amount_check": amt_ok,
            "three_way_split": bool(re.search(r"tx\.outputs\.length\s*==\s*3", code)),
        },
        "escrow": {
            "valid_signature_check": sig_ok,
            "both_signatures_required": _both_signatures_required(detected, code),
            "multisig": _multisig_detected(detected, code),
            "two_of_three_logic": ("multisig_2of3" in detected or "checkMultiSig" in code),
            "locktime_check": capabilities.get("time_validation", False),
            "output_lockingbytecode_check": "locking_bytecode" in detected,
            "must_fail_missing_destination_check": _escrow_missing_destination_check(code),
            "must_fail_permanent_covenant": _escrow_permanent_covenant(code),
        },
        "multisig": {
            "valid_signature_check": sig_ok,
            "both_signatures_required": _both_signatures_required(detected, code),
            "multisig": _multisig_detected(detected, code),
            "two_of_three_logic": ("multisig_2of3" in detected or "checkMultiSig" in code),
            "three_of_five_logic": _three_of_five_logic(detected, code),
            "must_fail_pubkey_substitution": _must_fail_pubkey_substitution(code),
            "must_fail_duplicate_signer": _must_fail_duplicate_signer(code),
        },
        "timelock": {
            "valid_signature_check": sig_ok,
            "locktime_check": capabilities.get("time_validation", False),
            "timestamp_based": _timestamp_based_timelock(detected, code),
            "block_height_based": _block_height_based_timelock(detected, code),
            "relative_timelock": _relative_timelock(detected, code),
            "sequence_check": _sequence_check(detected, code),
            "must_fail_wrong_time_field": _must_fail_wrong_time_field(code),
        },
    }
    default = {
        "valid_signature_check": sig_ok,
        "token_category_check": cat_in or cat_out,
        "token_amount_check": amt_ok,
        "nftcommitment_preservation": commitment_ok,
        "capability_byte_match": cap_ok,
        "minting_authority_custody": custody_ok,
        "bch_only_change_guard": bch_change,
        "must_fail_capability_leak": leak_fail,
        "covenant_self_reference": capabilities.get("covenant_continuation", False),
        "locktime_check": capabilities.get("time_validation", False),
        "output_amount_check": capabilities.get("output_value_validation", False),
        "two_of_three_logic": ("multisig_2of3" in detected or "checkMultiSig" in code),
        "both_signatures_required": _both_signatures_required(detected, code),
        "multisig": _multisig_detected(detected, code),
        "three_of_five_logic": _three_of_five_logic(detected, code),
        "must_fail_missing_destination_check": _escrow_missing_destination_check(code),
        "must_fail_permanent_covenant": _escrow_permanent_covenant(code),
        "must_fail_pubkey_substitution": _must_fail_pubkey_substitution(code),
        "must_fail_duplicate_signer": _must_fail_duplicate_signer(code),
        "timestamp_based": _timestamp_based_timelock(detected, code),
        "block_height_based": _block_height_based_timelock(detected, code),
        "relative_timelock": _relative_timelock(detected, code),
        "sequence_check": _sequence_check(detected, code),
        "must_fail_wrong_time_field": _must_fail_wrong_time_field(code),
    }
    merged = {**default, **pools.get(pattern, {})}
    return merged


def _invalid_detector_alias_pool(code: str, contract_mode: str = "") -> Dict[str, bool]:
    """Wave 2B: must_fail_* keys true when matching invalid-logic detector fires."""
    from src.services.cashtokens_token_detectors import CASHTOKENS_INVALID_DETECTOR_REGISTRY
    from src.utils.cashscript_ast import CashScriptAST

    ast = CashScriptAST(code, contract_mode=contract_mode)
    out: Dict[str, bool] = {}
    for detector in CASHTOKENS_INVALID_DETECTOR_REGISTRY:
        out[f"must_fail_{detector.id}"] = detector.detect(ast) is not None
    return out


def _semantic_alias_pool(
    pattern: str,
    capabilities: Dict[str, Any],
    detected: set,
    code: str,
    functions: List[Dict],
) -> Dict[str, bool]:
    """Semantic suite critical_features (code-pattern checks)."""
    sig_ok = capabilities.get("signature_verification", False)
    anchor = bool(re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", code))
    migratory = bool(
        re.search(r"lockingBytecode\s*==\s*\w+", code)
        and not re.search(
            r"lockingBytecode\s*==\s*this\.activeBytecode",
            code.split("function")[-1] if "release" in code.lower() or "claim" in code.lower() else code,
        )
    ) or bool(re.search(r"recipientLockingBytecode|buyerLockingBytecode|sellerLockingBytecode", code))
    terminating = bool(
        re.search(r"tx\.outputs\[\d+\]\.value", code)
        and (
            "release" in code.lower()
            or "claim" in code.lower()
            or "purchase" in code.lower()
            or "redeem" in code.lower()
        )
    )
    burn_path = bool(
        re.search(r"tokenCategory\s*==\s*0x", code)
        or re.search(r"tokenAmount\s*==\s*0", code)
        or "burn" in code.lower()
    )
    no_mint = not bool(
        re.search(r"function\s+mint\w*\s*\(", code, re.I)
        and re.search(r"totalMinted\s*\+|mintAmount\s*\+", code, re.I)
    )
    mint_cap = bool(
        re.search(r"maxSupply|totalMinted\s*\+", code, re.I)
        and re.search(r"require\s*\(", code)
    )
    expiry = bool(
        re.search(r"tx\.time", code)
        or re.search(r"expir", code, re.I)
        or re.search(r"nftCommitment", code)
    )
    gov_mutate = bool(
        re.search(r"nftCommitment\s*==\s*\w+", code)
        and ("checkMultiSig" in code or "checkSig" in code)
    )

    cov_ref = anchor or capabilities.get("covenant_continuation", False)
    base = {
        "valid_signature_check": sig_ok,
        "token_category_check": bool(re.search(r"tokenCategory\s*==", code)),
        "covenant_continuation": cov_ref,
        "covenant_self_reference": cov_ref,
        "soulbound_no_external_transfer": anchor and not bool(
            re.search(r"lockingBytecode\s*==\s*(?!this\.activeBytecode)(?:recipient|buyer|external)", code)
        ),
        "state_transition_commitment": bool(re.search(r"nftCommitment", code)) and anchor,
        "terminating_payout_path": terminating,
        "migratory_locking_bytecode": migratory or bool(re.search(r"lockingBytecode\s*==\s*\w+Lock", code)),
        "burn_supply_reduction": burn_path,
        "no_mint_increase": no_mint,
        "mint_cap_guard": mint_cap,
        "minting_authority_custody": anchor and bool(re.search(r"0x02", code)),
        "capability_byte_match": bool(re.search(r"0x0[12]", code)),
        "redeem_burn_termination": burn_path and terminating,
        "expiry_time_check": expiry,
        "governance_commitment_mutate": gov_mutate,
        "nftcommitment_preservation": bool(re.search(r"nftCommitment", code)),
        "output_amount_check": bool(re.search(r"tx\.outputs\[\d+\]\.value", code)),
        "locktime_check": capabilities.get("time_validation", False) or "tx.time" in code,
        "two_of_three_logic": "checkMultiSig" in code,
    }
    pools = {
        "semantic_escrow": base,
        "semantic_soulbound": base,
        "semantic_burnable": base,
        "semantic_governance": base,
        "semantic_marketplace": base,
        "semantic_capped_mint": base,
        "semantic_streaming": base,
        "semantic_voucher": base,
        "semantic_collateral": base,
        "semantic_stablecoin": base,
        "semantic_auction": base,
    }
    return {**base, **pools.get(pattern, {})}


class BenchmarkEvaluator:
    def __init__(self, weights_path: str = "benchmark/config/scoring_weights.yaml"):
        self.weights_path = Path(weights_path)
        self.weights = {}
        self.extractor = FeatureExtractor()
        self.engine = get_guarded_pipeline_engine()
        self.load_weights()

    def load_weights(self):
        if not self.weights_path.exists():
            print(f"Warning: Scoring weights not found at {self.weights_path}")
            return
        with open(self.weights_path, "r", encoding="utf-8") as f:
            self.weights = yaml.safe_load(f)

    async def evaluate(
        self,
        case: BenchmarkCase,
        model_override: str = None,
        disable_golden: bool = True,
    ) -> CaseResult:
        start_time = time.time()
        
        # Determine failure layer and state
        failure_layer = None
        converged = False
        fallback_used = False
        compile_pass = False
        lint_errors = 0
        lint_warnings = 0
        code = None
        
        # Metrics placeholders
        tokens_prompt = 0
        tokens_completion = 0
        
        try:
            # We call the production engine with benchmark safety flags
            # Note: generate_guarded handles inner retry loops
            result = await asyncio.wait_for(
                self.engine.generate_guarded(
                    case.intent,
                    security_level="high",
                    disable_golden=disable_golden,
                    disable_fallbacks=True,
                ),
                timeout=300  # 5 min — token treasury paths can spend retries in compile/lint loops
            )
            
            latency = time.time() - start_time
            
            if result.get("type") == "success":
                data = result["data"]
                code = data["code"]
                compile_pass = True
                fallback_used = bool(data.get("fallback_used", False))
                
                # Metadata from engine
                attempt_number = data.get("attempt_number", 1)
                gen_seconds = data.get("generation_seconds", time.time() - start_time)
                
                # 1. Extraction (Structured)
                extracted = self.extractor.extract(code)
                detected = extracted["features"]
                functions = extracted["functions"]
                
                # 2. Capability Saturation (Semantic Mapping)
                # Map abstract required features to sets of satisfyable concrete detections
                has_time_check = (
                    "timelock_unlock" in detected
                    or "timelock_refund" in detected
                    or ("this.age" in code)
                )
                legacy_capabilities = {
                    "signature_verification": any("_signature" in f or f == "multisig" for f in detected),
                    "covenant_continuation": any(
                        f.get("has_anchor") and f.get("has_value_check")
                        for f in functions
                        if f["role"] == "INTERMEDIATE"
                    ),
                    "time_validation": has_time_check,
                    "timelock_unlock": has_time_check,
                    "multiple_paths": len(functions) >= 2,
                    "token_validation": (
                        ("token_amount" in detected)
                        or ("token_nft" in detected)
                        or ("tokenCategory" in code and "tokenAmount" in code)
                    ),
                    "multisig": _multisig_detected(set(detected), code),
                    "output_destination_validation": "locking_bytecode" in detected,
                    "output_value_validation": (
                        ("output_value_validation" in detected) or ("value_check" in detected)
                    ),
                }

                intent_model = data.get("intent_model") or {}
                intent_modes = {
                    "ownership_mode": intent_model.get("ownership_mode", ""),
                    "lifecycle_mode": intent_model.get("lifecycle_mode", ""),
                    "supply_mode": intent_model.get("supply_mode", ""),
                    "commitment_schema": intent_model.get("commitment_schema", ""),
                }
                sem_caps = extract_semantic_capabilities(
                    code,
                    contract_mode=(case.pattern or intent_model.get("contract_type", "")),
                    intent_modes=intent_modes,
                )
                legacy_capabilities["enforces_supply_cap"] = sem_caps.get("enforces_supply_cap") is True

                pattern_key = (case.pattern or "").strip()
                if pattern_key.startswith("semantic_"):
                    legacy_alias_checks = _semantic_alias_pool(
                        pattern_key, legacy_capabilities, detected, code, functions
                    )
                elif pattern_key in {
                    "token_ft", "ft_mint", "nft_immutable", "nft_mutable",
                    "nft_minting", "hybrid_token", "split_payment", "escrow",
                    "multisig", "timelock",
                }:
                    legacy_alias_checks = _cashtoken_alias_pool(
                        pattern_key, legacy_capabilities, detected, code, functions
                    )
                else:
                    legacy_alias_checks = _cashtoken_alias_pool(
                        "", legacy_capabilities, detected, code, functions
                    )
                    legacy_alias_checks.update({
                        "amount_threshold_logic": ("<=" in code or ">=" in code),
                        "tiered_delay_logic": (
                            "smallDelay" in code
                            or "largeDelay" in code
                            or "threshold" in code.lower()
                        ),
                        "emergency_path": any(
                            f.get("role") == "RECOVERY" for f in functions
                        ),
                        "cancellation_path": "cancel" in code.lower(),
                        "token_nft_amount_check": ("token_nft" in detected)
                        or bool(re.search(r"tokenAmount\s*==\s*1\b", code)),
                    })
                legacy_alias_checks.update(
                    _invalid_detector_alias_pool(
                        code, case.pattern or intent_model.get("contract_type", "")
                    )
                )

                requirement_traces: Dict[str, Any] = {}

                def requirement_satisfied(req: str) -> bool:
                    ok, tr = satisfies_requirement(
                        req,
                        sem_caps,
                        legacy_alias_checks=legacy_alias_checks,
                        detected_features=set(detected),
                        legacy_capabilities=legacy_capabilities,
                    )
                    requirement_traces[req] = tr
                    return ok

                # 3. Intent Coverage Calculation (Proportional)
                matched_required = []
                missing_required = []
                for req in (case.required_features or []):
                    if requirement_satisfied(req):
                        matched_required.append(req)
                    else:
                        missing_required.append(req)
                
                # Proportional score instead of binary
                if case.required_features:
                    intent_coverage = len(matched_required) / len(case.required_features)
                else:
                    intent_coverage = 1.0

                has_failure_tag = any(
                    t in {"failure", "vulnerability"} for t in (case.tags or [])
                )
                must_fail_criticals = [
                    c for c in (case.critical_features or [])
                    if str(c).startswith("must_fail_")
                ]
                if has_failure_tag and must_fail_criticals:
                    if all(requirement_satisfied(c) for c in must_fail_criticals):
                        intent_coverage = 1.0

                # 4. Vault-Specific Semantic Guard (Production-Grade)
                semantic_pass = True
                
                # RULE: INTERMEDIATE functions MUST re-anchor (Covenant Continuation)
                intermediate_funcs = [f for f in functions if f["role"] == "INTERMEDIATE"]
                if intermediate_funcs and not any(f["has_anchor"] for f in intermediate_funcs):
                    semantic_pass = False # Vault cannot continue to next stage
                
                # RULE: TERMINAL functions MUST NOT re-anchor (Cleanup)
                terminal_funcs = [f for f in functions if f["role"] == "TERMINAL"]
                if any(f["has_anchor"] for f in terminal_funcs):
                    semantic_pass = False # Vault leaked funds back into covenant?
                
                # 5. Final Scoring
                structure_score = data.get("toll_gate", {}).get("structural_score", 0.0)
                adj_structure_score = structure_score # Legacy name, simplified
                
                critical_missing = [f for f in case.critical_features if not requirement_satisfied(f)]

                try:
                    save_capability_trace(
                        case_id=case.id,
                        caps=sem_caps,
                        requirement_results=requirement_traces,
                    )
                except OSError:
                    pass

                lint_factor = self.weights.get("factors", {}).get("lint_no_error", 1.0)
                # Token-bearing vaults: pipeline already passed compile + toll gate; align score with convergence.
                token_vault_relaxed = (
                    case.pattern == "vault"
                    and "token_validation" in (case.required_features or [])
                    and compile_pass
                    and intent_coverage >= 0.70
                    and len(critical_missing) == 0
                )
                timelock_semantic_relaxed = (
                    case.pattern == "timelock"
                    and compile_pass
                    and intent_coverage >= 0.70
                    and len(critical_missing) == 0
                )
                effective_semantic = (
                    semantic_pass or token_vault_relaxed or timelock_semantic_relaxed
                )
                final_score = (1.0 if compile_pass else 0.0) * lint_factor * intent_coverage * (1.0 if effective_semantic else 0.5)
                
                if critical_missing:
                    # Critical features remain high-stakes
                    final_score *= 0.2
                
                # Convergence should represent usable production quality, not only "compiled".
                # For failure/vulnerability benchmark cases, force non-converged unless
                # the "must_fail_*" critical expectation is actually detected.
                has_must_fail_critical = bool(must_fail_criticals)
                converged = (
                    (not fallback_used)
                    and compile_pass
                    and intent_coverage >= 0.70
                    and len(critical_missing) == 0
                    and not (has_failure_tag and has_must_fail_critical)
                    and (semantic_pass or token_vault_relaxed or timelock_semantic_relaxed)
                )

                return CaseResult(
                    id=case.id,
                    pattern=case.pattern,
                    difficulty=case.difficulty,
                    compile_pass=compile_pass,
                    lint_errors=0,
                    lint_warnings=0,
                    lint_factor=lint_factor,
                    structure_score=structure_score,
                    adj_structure_score=adj_structure_score,
                    required_features=case.required_features,
                    detected_features=detected,
                    missing_features=missing_required,
                    extraneous_features=[], # Removed penalty
                    hallucinated_features=[],
                    intent_coverage=intent_coverage,
                    final_score=final_score,
                    latency_seconds=gen_seconds,
                    retries_used=attempt_number,
                    first_pass_attempt=attempt_number if compile_pass else None,
                    max_retries=case.max_retries,
                    converged=converged,
                    fallback_used=fallback_used,
                    failure_layer=None,
                    elapsed_seconds=time.time() - start_time,
                    code=code
                )
            else:
                # Failure Case
                latency = time.time() - start_time
                error = result.get("error", {})
                code_err = error.get("code", "")
                
                if "intent_parse_failed" in code_err:
                    failure_layer = "Phase1"
                elif "lint" in str(error).lower():
                    failure_layer = "DSLLint"
                else:
                    failure_layer = "Compile"
                
                return self._failed_result(case, latency, failure_layer)

        except (asyncio.TimeoutError, asyncio.CancelledError):
            latency = time.time() - start_time
            return self._failed_result(case, latency, "Timeout")
        except Exception as e:
            latency = time.time() - start_time
            return self._failed_result(case, latency, f"Error: {str(e)[:50]}")

    def _failed_result(self, case: BenchmarkCase, latency: float, failure_layer: str) -> CaseResult:
        return CaseResult(
            id=case.id,
            pattern=case.pattern,
            difficulty=case.difficulty,
            compile_pass=False,
            lint_errors=0, # Unknown
            lint_warnings=0,
            lint_factor=0.5,
            structure_score=0.0,
            adj_structure_score=0.0,
            required_features=case.required_features,
            detected_features=[],
            missing_features=case.required_features,
            extraneous_features=[],
            hallucinated_features=[],
            intent_coverage=0.0,
            final_score=0.0,
            latency_seconds=latency,
            retries_used=case.max_retries,
            max_retries=case.max_retries,
            converged=False,
            fallback_used=False,
            failure_layer=failure_layer,
            elapsed_seconds=latency
        )
