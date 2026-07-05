"""
TEMPORARY bridge: UTXOArchitecture + ExecutionPlan -> legacy effective_mode.

Delete this module once Phase 2 consumes UTXOArchitecture directly.
"""

from __future__ import annotations

from src.models import ExecutionPlan, UTXOArchitecture

CONTRACT_TYPE_TO_MODE = {
    "Vault": "vault",
    "Escrow": "escrow_2of3_nft",
    "Multisig": "multisig",
    "ThresholdPolicy": "vault",
    "VestingPolicy": "linear_vesting",
    "Split": "split",
    "FT": "token_ft",
    "NFT": "nft_immutable",
    "MutableNFT": "nft_mutable",
    "MintAuthority": "nft_minting",
    "Hybrid": "hybrid_token",
    "Timelock": "timelock",
    "Withdrawal": "vault",
    "Auction": "dutch_auction",
}

MODULE_TO_MODE = {
    "VaultModule": "vault",
    "EscrowModule": "escrow_2of3_nft",
    "WeightedMultisigModule": "multisig",
    "MultisigModule": "multisig",
    "LinearThresholdModule": "vault",
    "VestingScheduleModule": "linear_vesting",
    "SplitPaymentModule": "split",
    "FTTransferModule": "token_ft",
    "NFTImmutableModule": "nft_immutable",
    "NFTMutableModule": "nft_mutable",
    "NFTMintingModule": "nft_minting",
    "HybridTokenModule": "hybrid_token",
    "TimelockModule": "timelock",
    "WithdrawalModule": "vault",
    "DutchAuctionModule": "dutch_auction",
}


def resolve_effective_mode(
    utxo_architecture: UTXOArchitecture,
    execution_plan: ExecutionPlan,
) -> str:
    if utxo_architecture.contracts:
        ctype = utxo_architecture.contracts[0].type
        mode = CONTRACT_TYPE_TO_MODE.get(ctype)
        if mode:
            return mode

    if execution_plan.modules:
        for mod in execution_plan.modules:
            mode = MODULE_TO_MODE.get(mod.name)
            if mode:
                return mode

    return "multisig"
