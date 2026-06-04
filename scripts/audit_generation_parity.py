"""
Compare generation vs audit CashTokens detector coverage.

Usage:
  python scripts/audit_generation_parity.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.services.anti_pattern_detectors import generation_detector_registry
from src.services.audit_engine.audit_enforcer import audit_detector_registry

CASHTOKENS_PARITY_IDS = {
    "missing_token_amount_validation",
    "minting_authority_escape",
    "unbounded_mint",
    "authority_leak",
    "mutable_capability_leak",
    "token_category_drift",
    "token_amount_inflation",
    "token_amount_burn",
    "nft_commitment_loss",
    "hybrid_continuity_break",
    "unrestricted_token_transfer",
    "capability_token_continuity_break",
}

OUT = ROOT / "docs" / "wave_2_audit_parity_report.md"


def main() -> int:
    gen_ids = {d.id for d in generation_detector_registry()}
    audit_ids = {d.id for d in audit_detector_registry()}
    cap_audit = {"capability_token_continuity_break"}  # capability registry id

    missing = sorted(CASHTOKENS_PARITY_IDS - gen_ids - audit_ids - cap_audit)
    gen_only = sorted(gen_ids & CASHTOKENS_PARITY_IDS - audit_ids)
    audit_only = sorted(audit_ids & CASHTOKENS_PARITY_IDS - gen_ids)

    lines = [
        "# Wave 2 audit–generation parity report",
        "",
        "## CashTokens detector IDs",
        "",
        f"- Generation registry: {len(gen_ids)} detectors",
        f"- Audit registry: {len(audit_ids)} detectors",
        "",
        "## Parity set",
        "",
    ]
    for pid in sorted(CASHTOKENS_PARITY_IDS):
        g = "yes" if pid in gen_ids or pid.replace("capability_", "") in gen_ids else "no"
        a = "yes" if pid in audit_ids or pid in cap_audit else "no"
        lines.append(f"- `{pid}`: generation={g}, audit={a}")

    lines.extend(["", "## Gaps", ""])
    if missing:
        lines.append("Missing from both: " + ", ".join(missing))
    else:
        lines.append("No missing CashTokens parity IDs.")
    if gen_only:
        lines.append("Generation only: " + ", ".join(gen_only))
    if audit_only:
        lines.append("Audit only: " + ", ".join(audit_only))

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"missing": missing, "report": str(OUT)}, indent=2))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
