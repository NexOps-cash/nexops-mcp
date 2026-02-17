from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class SynthesisRule:
    id: str
    tags: List[str]
    require: List[str]
    forbidden: List[str]
    pattern: str
    severity: str = "CRITICAL"

class RuleEngine:
    """Manages structural and semantic rules for CashScript synthesis."""
    
    def __init__(self):
        self.rules = [
            SynthesisRule(
                id="MULTISIG_DISTINCT_KEYS",
                tags=["multisig"],
                require=[
                    "require(pk1 != pk2) for every pubkey pair",
                    "Unique signature variable names (e.g. aliceSig, bobSig)",
                    "Discrete checkSig(sig, pk) calls"
                ],
                forbidden=[
                    "Reusing the same signature variable for different pubkeys",
                    "Implicit threshold assumptions"
                ],
                pattern="require(pk1 != pk2); require(checkSig(sig1, pk1) && checkSig(sig2, pk2));"
            ),
            SynthesisRule(
                id="COVENANT_PROPERTY_ACCESS_ANCHOR",
                tags=["escrow", "covenant", "spending"],
                require=[
                    "Validate lockingBytecode BEFORE any other output property",
                    "Use explicit thisBytecode anchor for self-continuation"
                ],
                forbidden=[
                    "Accessing tx.outputs[N].value before lockingBytecode validation",
                    "Index-based property access without script validation"
                ],
                pattern="require(tx.outputs[0].lockingBytecode == expected); require(tx.outputs[0].value == amt);"
            ),
            SynthesisRule(
                id="SECURE_TEMPORAL_VALIDATION",
                tags=["timelock", "escrow"],
                require=[
                    "Use >= for 'at or after' checks",
                    "Use < for 'before' checks"
                ],
                forbidden=[
                    "Using > for time checks",
                    "Using block.timestamp (Solidity habit)"
                ],
                pattern="require(tx.time >= deadline);"
            ),
            SynthesisRule(
                id="INPUT_ANCHORING",
                tags=["covenant", "stateful"],
                require=[
                    "Validate this.activeInputIndex == 0 (or specific index)",
                    "Anchor input identity via this.lockingBytecode"
                ],
                forbidden=[
                    "Implicit index assumptions"
                ],
                pattern="require(this.activeInputIndex == 0); require(tx.inputs[0].lockingBytecode == this.lockingBytecode);"
            )
        ]

    def get_rules_for_tags(self, tags: List[str]) -> List[SynthesisRule]:
        """Activate rules based on matching tags."""
        active_rules = []
        for rule in self.rules:
            if any(tag in tags for tag in rule.tags):
                active_rules.append(rule)
        return active_rules

    def format_rules_for_prompt(self, rules: List[SynthesisRule]) -> str:
        """Format active rules into a high-density constraint block."""
        if not rules:
            return ""
            
        lines = ["### ENFORCED SYNTHESIS RULES (MANDATORY)"]
        for rule in rules:
            lines.append(f"#### {rule.id}")
            lines.append(f"**REQUIRED**:")
            for req in rule.require:
                lines.append(f"- {req}")
            lines.append(f"**FORBIDDEN**:")
            for forb in rule.forbidden:
                lines.append(f"- {forb}")
            lines.append(f"**MANDATORY PATTERN**: `{rule.pattern}`")
            lines.append("")
            
        return "\n".join(lines)

_engine = RuleEngine()

def get_rule_engine() -> RuleEngine:
    return _engine
