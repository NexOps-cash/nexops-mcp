#!/usr/bin/env python3
"""Generate adversarial scenario registry for Workstream B."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "adversarial_registry.json"

CATEGORIES = {
    "FAKE_AUTH": ("Fake auth", 25),
    "MISLEAD": ("Misleading comments", 25),
    "PARTIAL": ("Partial protection", 25),
    "HIDDEN_AUTH": ("Hidden authorization failure", 25),
    "TRUST": ("Trust-boundary traps", 25),
    "TOKEN": ("Token edge cases", 25),
    "UTXO": ("UTXO edge cases", 25),
    "CONTRA": ("Contradictory signals", 25),
}

EXISTING = [
    ("AG-1", "FAKE_AUTH", "Attacker gain dust redirect", "ONE_SATOSHI_REDIRECT"),
    ("AG-2", "FAKE_AUTH", "Destruction without gain", "PERMANENT_LOCK"),
    ("AG-3", "FAKE_AUTH", "Token burn no attacker gain", "TOKEN_BURN_NO_GAIN"),
    ("AUTH-1", "HIDDEN_AUTH", "Dual path partial auth", "PARTIAL_AUTH_BYPASS"),
    ("AUTH-2", "FAKE_AUTH", "Hallucinated missing auth", "PAYROLL_FIXED_SALARY"),
    ("AUTH-3", "HIDDEN_AUTH", "Real missing auth", "PAYROLL_NO_AUTH"),
    ("TRUST-1", "TRUST", "Oracle price trust", "ORACLE_PRICE"),
    ("TRUST-2", "TRUST", "Off-chain key rotation", "OFFCHAIN_KEY_ROTATION"),
    ("TRUST-3", "TRUST", "External LP funding", "MIXED-2"),
    ("INTENT-1", "CONTRA", "Secure code benign intent", None),
    ("INTENT-2", "CONTRA", "Scary intent secure code", None),
    ("INTENT-3", "MISLEAD", "Business metadata as vuln", None),
    ("CONTRA-1", "CONTRA", "Judge vs cap.has_checksig", None),
    ("CONTRA-2", "CONTRA", "Judge vs inv.value_conservation", None),
    ("CONTRA-3", "CONTRA", "Judge vs inv.recipient_binding", None),
    ("CONF-1", "TRUST", "Low confidence deployment note", None),
    ("CONF-2", "CONTRA", "Low confidence exploit claim", None),
    ("CONF-3", "HIDDEN_AUTH", "High confidence real vuln", None),
    ("BCH-1", "TOKEN", "Category drift exploit", None),
    ("BCH-2", "TRUST", "Partial oracle binding", "ORACLE_PRICE"),
    ("BCH-3", "CONTRA", "Secure oracle over-flagged", "ORACLE_PRICE"),
    ("MIXED-1", "TRUST", "Mixed trust+auth signals", None),
    ("MIXED-2", "TRUST", "Treasury LP assumption", None),
]


def stub_scenarios() -> list[dict]:
    scenarios = []
    for sid, cat, desc, fixture in EXISTING:
        scenarios.append(
            {
                "id": sid,
                "category": cat,
                "description": desc,
                "contract_ref": fixture,
                "status": "implemented",
                "evaluation_mode": "policy_only",
            }
        )
    seq = 1
    for cat, (label, count) in CATEGORIES.items():
        existing_in_cat = sum(1 for s in scenarios if s["category"] == cat)
        for i in range(existing_in_cat + 1, count + 1):
            scenarios.append(
                {
                    "id": f"{cat}-{i:02d}",
                    "category": cat,
                    "description": f"{label} scenario stub {i}",
                    "contract_ref": "TBD",
                    "status": "planned",
                    "evaluation_mode": "full_audit" if cat in ("UTXO", "TOKEN", "HIDDEN_AUTH") else "policy_only",
                    "family_hint": _family_hint(cat, i),
                }
            )
            seq += 1
    return scenarios


def _family_hint(cat: str, i: int) -> str:
    hints = {
        "FAKE_AUTH": ["payroll", "escrow", "vault", "multisig"],
        "MISLEAD": ["escrow", "covenant", "cashtokens_nft"],
        "PARTIAL": ["payroll", "split_payment", "multisig"],
        "HIDDEN_AUTH": ["multisig", "escrow", "conditional_spend"],
        "TRUST": ["oracle", "payroll", "dao_treasury"],
        "TOKEN": ["cashtokens_ft", "cashtokens_nft", "hybrid"],
        "UTXO": ["vault", "covenant", "split_payment"],
        "CONTRA": ["payroll", "escrow", "oracle"],
    }
    opts = hints.get(cat, ["generic"])
    return opts[i % len(opts)]


def main() -> None:
    scenarios = stub_scenarios()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "description": "NexOps adversarial audit scenario registry",
                "total_count": len(scenarios),
                "categories": {k: v[0] for k, v in CATEGORIES.items()},
                "scenarios": scenarios,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {len(scenarios)} scenarios to {OUT}")


if __name__ == "__main__":
    main()
