import os
import hashlib
from dataclasses import dataclass


GOLDEN_PATTERNS_DIR = os.path.join(
    "knowledge",
    "golden",
    "patterns"
)


@dataclass
class GoldenPattern:
    pattern_id: str
    template_path: str
    anchor_hash: str


class GoldenRegistry:

    def __init__(self):
        self.patterns = {}

    def load_pattern(self, pattern_id: str, filename: str):
        path = os.path.join(GOLDEN_PATTERNS_DIR, filename)

        if not os.path.exists(path):
            raise FileNotFoundError(f"Golden template not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        invariant_block = self._extract_invariant_block(content)

        anchor_hash = hashlib.sha256(
            invariant_block.encode("utf-8")
        ).hexdigest()

        self.patterns[pattern_id] = GoldenPattern(
            pattern_id=pattern_id,
            template_path=path,
            anchor_hash=anchor_hash
        )

    def _extract_invariant_block(self, content: str) -> str:
        start_marker = "=== INVARIANT_ANCHOR_START ==="
        end_marker = "=== INVARIANT_ANCHOR_END ==="

        start_index = content.find(start_marker)
        end_index = content.find(end_marker)

        if start_index == -1 or end_index == -1:
            raise ValueError("Invariant markers not found in template")

        start_index += len(start_marker)

        invariant_block = content[start_index:end_index].strip()

        if not invariant_block:
            raise ValueError("Invariant block is empty")

        return invariant_block


if __name__ == "__main__":
    registry = GoldenRegistry()

    registry.load_pattern(
        "escrow_2of3_nft",
        "escrow_2of3_nft.cash"
    )

    pattern = registry.patterns["escrow_2of3_nft"]

    print("Loaded pattern:", pattern.pattern_id)
    print("Anchor hash:", pattern.anchor_hash)
