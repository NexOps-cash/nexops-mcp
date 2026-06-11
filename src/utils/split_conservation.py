"""N-output BCH and tokenAmount conservation detection (lint, sanity, AST)."""

from __future__ import annotations

import re

ACTIVE_INPUT_VALUE = r"tx\.inputs\[this\.activeInputIndex\]\.value"
ACTIVE_INPUT_TOKEN = r"tx\.inputs\[this\.activeInputIndex\]\.tokenAmount"


def input_value_pattern(extra_vars: set[str] | None = None) -> str:
    names = list(extra_vars or []) + ["inputVal"]
    alts = [ACTIVE_INPUT_VALUE] + [re.escape(v) for v in names if v]
    return "(?:" + "|".join(alts) + ")"


def has_chained_field_sum(body: str, field: str, input_pattern: str) -> bool:
    """True when a require() sums two or more tx.outputs[i].field terms to input."""
    if re.search(
        rf"require\s*\(\s*tx\.outputs\[\d+\]\.{field}\s*\+\s*tx\.outputs\[\d+\]\.{field}\s*==\s*{input_pattern}",
        body,
        re.DOTALL,
    ):
        return True

    for block in re.finditer(r"require\s*\((.*?)\)\s*;", body, re.DOTALL):
        expr = block.group(1)
        if "==" not in expr or "+" not in expr:
            continue
        if not re.search(input_pattern, expr):
            continue
        refs = re.findall(rf"tx\.outputs\[\d+\]\.{field}", expr)
        if len(refs) >= 2:
            return True
    return False


def has_bch_value_conservation(body: str, input_pattern: str | None = None) -> bool:
    ip = input_pattern or ACTIVE_INPUT_VALUE

    if re.search(
        rf"require\s*\(\s*tx\.outputs\[\d+\]\.value\s*==\s*{ip}\s*-\s*[\w\d]+\s*\)",
        body,
        re.DOTALL,
    ):
        return True

    return has_chained_field_sum(body, "value", ip)


def has_token_amount_conservation(body: str) -> bool:
    return has_chained_field_sum(body, "tokenAmount", ACTIVE_INPUT_TOKEN)


def has_split_value_conservation(code: str, extra_input_vars: set[str] | None = None) -> bool:
    ip = input_value_pattern(extra_input_vars)
    return has_bch_value_conservation(code, ip)
