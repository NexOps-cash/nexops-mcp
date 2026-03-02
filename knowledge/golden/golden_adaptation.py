import hashlib

try:
    from knowledge.golden.registry import GoldenRegistry
except ImportError:
    from registry import GoldenRegistry


def extract_invariant(content: str) -> str:
    start_marker = "=== INVARIANT_ANCHOR_START ==="
    end_marker = "=== INVARIANT_ANCHOR_END ==="

    si = content.find(start_marker) + len(start_marker)
    ei = content.find(end_marker)

    return content[si:ei].strip()


def adapt_business_logic(template_content: str, new_logic: str) -> str:
    placeholder = "// Optional fee splits, metadata checks, etc."
    return template_content.replace(placeholder, new_logic)


def verify_anchor_integrity(original_hash: str, new_content: str):
    invariant_block = extract_invariant(new_content)
    new_hash = hashlib.sha256(invariant_block.encode()).hexdigest()

    if new_hash != original_hash:
        raise Exception("Invariant Mutation Detected")

    return True


if __name__ == "__main__":
    registry = GoldenRegistry()
    registry.load_pattern("escrow_2of3_nft", "escrow_2of3_nft.cash")

    pattern = registry.patterns["escrow_2of3_nft"]

    with open(pattern.template_path, "r") as f:
        template = f.read()

    # ── Step 2: Safe Adaptation ──────────────────────────────────────────
    new_logic = "// injected business logic test"

    adapted = adapt_business_logic(template, new_logic)

    verify_anchor_integrity(pattern.anchor_hash, adapted)

    print("Golden adaptation safe.")

    # ── Step 3: Mutation Failure Test ────────────────────────────────────
    print("\n[Test] Simulating invariant mutation...")
    mutated = adapted.replace(
        "require(multisigPath || refundPath);",
        "// MUTATED: require(multisigPath || refundPath);"
    )

    try:
        verify_anchor_integrity(pattern.anchor_hash, mutated)
        print("ERROR: Mutation was NOT detected! Extraction is broken.")
    except Exception as e:
        print(f"Mutation correctly rejected: {e}")
