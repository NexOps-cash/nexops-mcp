"""Resolve benchmark contract_ref strings to CashScript source."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ResolvedContract:
    code: str
    source: str
    effective_mode: str = ""


def resolve_contract_ref(contract_ref: str) -> Optional[ResolvedContract]:
    """Return contract source or None if not materialized."""
    if not contract_ref or contract_ref in ("TBD", "synthetic"):
        return None

    if contract_ref.endswith(".cash"):
        path = ROOT / contract_ref
        if path.is_file():
            return ResolvedContract(code=path.read_text(encoding="utf-8"), source=str(path))
        return None

    if ":" in contract_ref and contract_ref.startswith("tests/"):
        module_path, symbol = contract_ref.rsplit(":", 1)
        mod_name = module_path.replace("/", ".").removesuffix(".py")
        try:
            mod = importlib.import_module(mod_name)
            code = getattr(mod, symbol, None)
            if isinstance(code, str):
                return ResolvedContract(code=code, source=contract_ref)
        except ImportError:
            pass

    # classification:scenario_id — map to classification matrix
    if contract_ref.startswith("classification:"):
        sid = contract_ref.split(":", 1)[1]
        from tests.audit_classification_matrix import scenarios as cm

        for sc in cm.SCENARIOS:
            if sc.scenario_id == sid:
                return ResolvedContract(
                    code=sc.code,
                    source=contract_ref,
                    effective_mode=sc.effective_mode or "",
                )
        return None

    # benchmark/suites/foo.yaml:case_id — not materialized
    if contract_ref.startswith("benchmark/suites/"):
        return None

    return None
