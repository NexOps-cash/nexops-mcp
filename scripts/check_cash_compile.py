"""Compile .cash knowledge files with pinned cashc (0.13.0-next.7)."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.services.compiler import CompilerService, get_cashc_path

FILES = [
    "knowledge/anti_pattern/minting_authority_leak.cash",
    "knowledge/patterns/covenant_validation.cash",
    "knowledge/patterns/cross_contract_auth.cash",
    "knowledge/patterns/input_validation.cash",
    "knowledge/patterns/minting_control.cash",
    "knowledge/patterns/output_count_limit.cash",
    "knowledge/patterns/sidecar_attach.cash",
    "knowledge/primitives/token_mint_control.cash",
    "knowledge/golden/patterns/stablecoin_minter_sidecar.cash",
    "knowledge/templates/ft_transfer.cash",
    "knowledge/templates/nft_transfer_immutable.cash",
]

PRAGMA_LINE = "pragma cashscript ^0.13.0;"


def _extract_contracts_in_unit(text: str) -> list[tuple[str, str]]:
    """Split a single pragma unit into (name, source) per contract."""
    indices = [m.start() for m in re.finditer(r"(?m)^contract\s+[A-Z]\w*\s*\(", text)]
    if not indices:
        body = text if PRAGMA_LINE in text else f"{PRAGMA_LINE}\n\n{text}"
        return [("whole_file", body)]

    chunks: list[tuple[str, str]] = []
    for i, start in enumerate(indices):
        end = indices[i + 1] if i + 1 < len(indices) else len(text)
        block = text[start:end].strip()
        name_m = re.search(r"contract\s+(\w+)", block)
        name = name_m.group(1) if name_m else f"contract_{i}"
        if not block.startswith("pragma"):
            block = f"{PRAGMA_LINE}\n\n{block}"
        chunks.append((name, block))
    return chunks


def extract_contracts(text: str) -> list[tuple[str, str]]:
    """Split file into (name, source) per contract; respect multiple pragma blocks."""
    pragma_parts = re.split(r"(?m)^(?=pragma cashscript)", text)
    if len(pragma_parts) > 1:
        chunks: list[tuple[str, str]] = []
        for part in pragma_parts:
            part = part.strip()
            if not part or not re.search(r"(?m)^contract\s+[A-Z]\w*\s*\(", part):
                continue
            chunks.extend(_extract_contracts_in_unit(part))
        return chunks
    return _extract_contracts_in_unit(text)


def main() -> int:
    print(f"cashc: {get_cashc_path()}\n")
    failures: list[str] = []

    for rel in FILES:
        path = ROOT / rel
        if not path.exists():
            print(f"MISSING  {rel}")
            failures.append(rel)
            continue

        raw = path.read_text(encoding="utf-8")
        whole = CompilerService.compile(raw)
        n = raw.count("contract ")
        whole_ok = whole["success"]
        print(f"{'OK' if whole_ok else 'FAIL'}  [whole file]  {rel}  ({n} contracts)")
        if not whole_ok:
            err = whole.get("error") or {}
            print(f"       whole: {err.get('raw') or err.get('message') or err}")

        for name, code in extract_contracts(raw):
            if name == "whole_file":
                continue
            r = CompilerService.compile(code)
            if r["success"]:
                print(f"  OK   {name}")
            else:
                err = r.get("error") or {}
                msg = err.get("raw") or err.get("message") or str(err)
                print(f"  FAIL {name}: {msg}")
                failures.append(f"{rel}::{name}")

        print()

    print("--- SUMMARY ---")
    per_contract_fails = [f for f in failures if "::" in f]
    print(f"Per-contract failures: {len(per_contract_fails)}")
    for f in per_contract_fails:
        print(f"  {f}")
    return 1 if per_contract_fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
