"""Context-aware Capability -> GenerationModule planning."""

from __future__ import annotations

from typing import Dict, List, Tuple

from src.models import ContractSpecification, GenerationModule


def _dedupe_modules_by_name(modules: List[GenerationModule]) -> List[GenerationModule]:
    """Keep first occurrence of each module name (treasury and vault both map to VaultModule)."""
    seen: set[str] = set()
    out: List[GenerationModule] = []
    for mod in modules:
        if mod.name in seen:
            continue
        seen.add(mod.name)
        out.append(mod)
    return out


class ModulePlanner:
    """Maps capabilities to generation modules (not 1:1 with capabilities)."""

    @staticmethod
    def select_modules(spec: ContractSpecification) -> Tuple[List[GenerationModule], Dict[str, str]]:
        """
        Returns (modules, capability_to_module decisions for PlanningReport).
        """
        decisions: Dict[str, str] = {}
        modules: List[GenerationModule] = []
        cap_names = {c.name for c in spec.capabilities}
        asset = str(spec.parameters.get("asset_type", "")).lower()

        if "treasury" in cap_names or "vault" in cap_names:
            if asset in ("nft", "token") or "nft" in spec.intent.lower():
                mod = GenerationModule(name="EscrowModule", capability="treasury", params={"variant": "escrow"})
                mod_name = "EscrowModule"
            else:
                mod = GenerationModule(name="VaultModule", capability="treasury", params={"variant": "vault"})
                mod_name = "VaultModule"
            if "treasury" in cap_names:
                decisions["treasury"] = mod_name
            if "vault" in cap_names:
                decisions["vault"] = mod_name
            modules.append(mod)

        if "weighted_multisig" in cap_names:
            mod = GenerationModule(
                name="WeightedMultisigModule",
                capability="weighted_multisig",
                params={
                    "holders": spec.parameters.get("holders"),
                    "weights": spec.parameters.get("weights"),
                },
                depends_on=[modules[0].name] if modules else [],
            )
            decisions["weighted_multisig"] = "WeightedMultisigModule"
            modules.append(mod)
        elif "multisig" in cap_names or "escrow" in cap_names:
            mod = GenerationModule(
                name="MultisigModule",
                capability="multisig",
                params={
                    "signers": spec.parameters.get("signers"),
                    "threshold": spec.parameters.get("threshold"),
                },
                depends_on=[modules[0].name] if modules else [],
            )
            decisions["multisig"] = "MultisigModule"
            modules.append(mod)

        if "linear_decay" in cap_names:
            lifecycle = str(spec.parameters.get("lifecycle_mode", "")).lower()
            if lifecycle == "vesting" or "vest" in spec.intent.lower():
                mod_name = "VestingScheduleModule"
            else:
                mod_name = "LinearThresholdModule"
            mod = GenerationModule(
                name=mod_name,
                capability="linear_decay",
                params={
                    "initial_threshold": spec.parameters.get("initial_threshold"),
                    "final_threshold": spec.parameters.get("final_threshold"),
                    "duration_days": spec.parameters.get("duration_days"),
                },
                depends_on=[m.name for m in modules[-1:]] if modules else [],
            )
            decisions["linear_decay"] = mod_name
            modules.append(mod)

        if "split" in cap_names:
            mod = GenerationModule(
                name="SplitPaymentModule",
                capability="split",
                params={
                    "recipients": spec.parameters.get("recipients"),
                    "shares": spec.parameters.get("shares"),
                },
            )
            decisions["split"] = "SplitPaymentModule"
            modules.append(mod)

        for cap in cap_names:
            if cap in decisions:
                continue
            mod_name = _default_module_for_capability(cap)
            if mod_name:
                modules.append(GenerationModule(name=mod_name, capability=cap, params={}))
                decisions[cap] = mod_name

        if not modules:
            modules.append(GenerationModule(name="MultisigModule", capability="multisig", params={}))
            decisions["multisig"] = "MultisigModule"

        return _dedupe_modules_by_name(modules), decisions


def _default_module_for_capability(cap: str) -> str:
    mapping = {
        "token_ft": "FTTransferModule",
        "nft_immutable": "NFTImmutableModule",
        "nft_mutable": "NFTMutableModule",
        "nft_minting": "NFTMintingModule",
        "hybrid_token": "HybridTokenModule",
        "timelock": "TimelockModule",
        "withdrawal_policy": "WithdrawalModule",
        "escrow": "EscrowModule",
        "vault": "VaultModule",
        "auction": "DutchAuctionModule",
    }
    return mapping.get(cap, "")
