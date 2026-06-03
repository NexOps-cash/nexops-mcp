"""Run validate_audit on sample contracts; print violations by mode."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MINTING_SAMPLE = """
pragma cashscript ^0.13.0;

contract OpenEditionNFT(
    bytes32 baseCategory,
    pubkey mintAuthority,
    int maxSupply,
    int totalMinted
) {
    function mint(sig mintSig, int mintAmount, bytes recipientLockingBytecode) {
        require(tx.outputs.length <= 3);
        require(checkSig(mintSig, mintAuthority));
        require(tx.inputs[this.activeInputIndex].tokenCategory == baseCategory + 0x02);
        require(totalMinted + mintAmount <= maxSupply);
        require(tx.outputs[0].tokenCategory == baseCategory + 0x02);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(tx.outputs[1].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[1].lockingBytecode == recipientLockingBytecode);
    }
}
"""

FT_SAMPLE = """
pragma cashscript ^0.13.0;

contract LoyaltyPoints(pubkey owner, bytes32 tokenCategory) {
    function transfer(sig ownerSig, bytes recipientLock) {
        require(checkSig(ownerSig, owner));
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
        require(tx.outputs[0].lockingBytecode == recipientLock);
    }
}
"""

IMMUTABLE_SAMPLE = """
pragma cashscript ^0.13.0;
contract ArtNFT(pubkey owner, bytes32 tokenCategory) {
    function transfer(sig ownerSig, bytes recipientLock) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
        require(tx.outputs[0].nftCommitment == tx.inputs[this.activeInputIndex].nftCommitment);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(tx.outputs[0].lockingBytecode == recipientLock);
    }
}
"""

MUTABLE_SAMPLE = """
pragma cashscript ^0.13.0;
contract EvolvingNFT(pubkey owner, bytes32 baseCategory, bytes newCommit) {
    function levelUp(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.inputs[this.activeInputIndex].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[0].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(tx.outputs[0].nftCommitment == newCommit);
    }
}
"""

HYBRID_SAMPLE = """
pragma cashscript ^0.13.0;
contract StableVault(pubkey owner) {
    function transition(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
        require(tx.outputs[0].nftCommitment == tx.inputs[this.activeInputIndex].nftCommitment);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""


def audit_report(code: str, mode: str) -> dict:
    from src.services.audit_engine.audit_phase import validate_audit

    r = validate_audit(code, contract_mode=mode)
    violations = []
    for v in r.violations:
        violations.append(
            {
                "rule": v.rule,
                "severity": v.severity,
                "reason": (v.reason or "")[:120],
            }
        )
    return {
        "mode": mode,
        "passed": r.passed,
        "structural_score": round(r.structural_score, 3),
        "critical_count": sum(1 for v in r.violations if v.severity == "critical"),
        "violation_count": len(r.violations),
        "violations": violations,
    }


def main() -> None:
    cases = [
        ("minting", MINTING_SAMPLE, ["nft_minting_authority"]),
        ("ft_transfer", FT_SAMPLE, ["token_ft"]),
        ("immutable", IMMUTABLE_SAMPLE, ["nft_immutable"]),
        ("mutable", MUTABLE_SAMPLE, ["nft_mutable"]),
        ("hybrid", HYBRID_SAMPLE, ["hybrid_token"]),
    ]
    out = []
    for label, code, modes in cases:
        for mode in modes:
            out.append({"sample": label, **audit_report(code, mode)})

    print(json.dumps(out, indent=2))

    parity_dir = ROOT / "benchmark/results/parity_compare"
    if parity_dir.exists():
        for path in sorted(parity_dir.glob("*.cash")):
            for mode in ["", "nft_minting_authority"]:
                rep = audit_report(path.read_text(encoding="utf-8"), mode)
                rep["file"] = path.name
                print("\n---", path.name, "mode=", mode, "---")
                print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
