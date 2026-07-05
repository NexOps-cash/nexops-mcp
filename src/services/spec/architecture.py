"""Build UTXO architecture from execution plan — deterministic, no LLM."""

from __future__ import annotations

from typing import Dict, List

from src.models import (
    ContractNode,
    ContractSpecification,
    ExecutionPlan,
    StateObject,
    TransactionSpec,
    UTXOArchitecture,
)

MODULE_CONTRACT_TYPE: Dict[str, tuple] = {
    "VaultModule": ("treasury", "Vault"),
    "EscrowModule": ("treasury", "Escrow"),
    "WeightedMultisigModule": ("auth", "Multisig"),
    "MultisigModule": ("auth", "Multisig"),
    "LinearThresholdModule": ("decay", "ThresholdPolicy"),
    "VestingScheduleModule": ("decay", "VestingPolicy"),
    "SplitPaymentModule": ("distribution", "Split"),
    "FTTransferModule": ("token", "FT"),
    "NFTImmutableModule": ("token", "NFT"),
    "NFTMutableModule": ("token", "MutableNFT"),
    "NFTMintingModule": ("token", "MintAuthority"),
    "HybridTokenModule": ("token", "Hybrid"),
    "TimelockModule": ("time", "Timelock"),
    "WithdrawalModule": ("withdraw", "Withdrawal"),
}

MODULE_STATE: Dict[str, tuple] = {
    "VaultModule": ("TreasuryState", "Mutable NFT Commitment"),
    "EscrowModule": ("EscrowState", "Mutable NFT Commitment"),
    "LinearThresholdModule": ("ThresholdState", "Mutable NFT Commitment"),
    "VestingScheduleModule": ("VestingState", "Mutable NFT Commitment"),
}

TRANSACTION_PATTERNS: Dict[str, List[TransactionSpec]] = {
    "Vault": [
        TransactionSpec(
            name="withdraw",
            inputs=["TreasuryNFT", "AuthUTXO"],
            outputs=["TreasuryNFT", "WithdrawalBCH"],
        ),
        TransactionSpec(
            name="deposit",
            inputs=["FundingUTXO"],
            outputs=["TreasuryNFT"],
        ),
    ],
    "Escrow": [
        TransactionSpec(
            name="release",
            inputs=["EscrowUTXO", "AuthUTXO"],
            outputs=["PayoutBCH"],
        ),
    ],
    "Multisig": [
        TransactionSpec(
            name="authorize",
            inputs=["PolicyUTXO", "SignerUTXOs"],
            outputs=["AuthUTXO"],
        ),
    ],
}


class ArchitectureBuilder:
    @staticmethod
    def build(execution_plan: ExecutionPlan, spec: ContractSpecification) -> UTXOArchitecture:
        contracts: List[ContractNode] = []
        transactions: List[TransactionSpec] = []
        state_objects: List[StateObject] = []
        seen_contract_ids: set = set()

        for mod in execution_plan.modules:
            mapping = MODULE_CONTRACT_TYPE.get(mod.name)
            if mapping:
                cid, ctype = mapping
                if cid not in seen_contract_ids:
                    contracts.append(ContractNode(id=cid, type=ctype))
                    seen_contract_ids.add(cid)
                for tx in TRANSACTION_PATTERNS.get(ctype, []):
                    if tx.name not in {t.name for t in transactions}:
                        transactions.append(tx)
            state = MODULE_STATE.get(mod.name)
            if state:
                sname, storage = state
                if sname not in {s.name for s in state_objects}:
                    state_objects.append(StateObject(name=sname, storage=storage))

        if not contracts and execution_plan.modules:
            mod = execution_plan.modules[0]
            contracts.append(ContractNode(id="main", type=mod.name.replace("Module", "")))

        if not transactions and contracts:
            transactions.append(
                TransactionSpec(name="spend", inputs=["InputUTXO"], outputs=["OutputUTXO"])
            )

        return UTXOArchitecture(
            contracts=contracts,
            transactions=transactions,
            state_objects=state_objects,
        )
