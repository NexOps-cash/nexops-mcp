"""Tests for interactive CLI helpers."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "interactive_generate",
    ROOT / "scripts" / "interactive_generate.py",
)
interactive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interactive)


def test_modification_input_detects_requirement_bullets():
    assert interactive._looks_like_modification_input(
        "- If the seller does not complete delivery within 30 days, the buyer may reclaim."
    )
    assert interactive._looks_like_modification_input(
        "Requirements:\n- Buyer deposits 20 BCH\n- Arbiter dispute path"
    )


def test_modification_input_rejects_ymq():
    assert not interactive._looks_like_modification_input("Y")
    assert not interactive._looks_like_modification_input("modify")
