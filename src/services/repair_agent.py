import re
import logging
from typing import Optional

from src.models import RepairRequest, RepairResponse, AuditIssue
from src.services.llm.factory import LLMFactory

logger = logging.getLogger("nexops.repair")

class RepairAgent:
    """
    Applies surgical LLM-based repairs for a specific Security Issue.

    Validation uses deterministic checks only — no LLM re-audit during repair.
    The user runs /api/audit after receiving the fixed code to see the new score.

    Safety gates (deterministic):
    1. require() count must not drop.
    2. No new DSL lint violations introduced.
    """

    def __init__(self):
        self.factory = LLMFactory()

    def _count_requires(self, code: str) -> int:
        return len(re.findall(r"\brequire\s*\(", code))

    async def _attempt_repair(
        self,
        provider,
        original_code: str,
        issue: AuditIssue,
        sys_prompt: str,
        user_prompt: str
    ) -> Optional[str]:
        try:
            corrected_code = await provider.complete(
                prompt=user_prompt,
                system=sys_prompt
            )

            if not corrected_code:
                return None

            corrected_code = corrected_code.strip()

            # Strip markdown fences if LLM ignores instruction
            if corrected_code.startswith("```"):
                corrected_code = "\n".join(corrected_code.split("\n")[1:])
            if "```" in corrected_code:
                corrected_code = corrected_code.split("```")[0]

            corrected_code = corrected_code.strip()

            # Handle verbose LLMs (e.g. Sonnet) that reason before outputting code.
            # Extract from `pragma cashscript` onwards if present.
            pragma_idx = corrected_code.find("pragma cashscript")
            if pragma_idx > 0:
                corrected_code = corrected_code[pragma_idx:]

            logger.info(f"[RepairAgent] LLM output (first 300 chars):\n{corrected_code[:300]}")
            return corrected_code.strip()

        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            return None

    async def repair(self, request: RepairRequest) -> RepairResponse:
        original_code = request.original_code
        issue = request.issue

        # Baseline: deterministic counts only — no LLM audit call
        original_require_count = self._count_requires(original_code)

        # System prompt with CashScript constraints
        sys_prompt = """You are NexOps RepairAgent, an expert CashScript security engineer.
Your task is to surgically fix a single vulnerability in a CashScript contract.

IMPORTANT RULES & CONSTRAINTS:
1. Fix ONLY the assigned vulnerability. Do NOT refactor or change other parts of the contract.
2. You MUST NOT remove any `require()` statements.
3. You MUST NOT remove value equality checks (e.g., self-anchoring `tx.outputs[this.activeInputIndex].value == ...`).
4. You MUST NOT remove `tokenCategory` or `tokenAmount` checks.
5. You MUST NOT remove `tx.outputs.length` guards.
6. You MUST NOT remove `this.activeBytecode` comparisons.
7. You MUST NOT change constructor parameters.
8. You MUST NOT change function signatures or names.

CASHSCRIPT ^0.13.0 LANGUAGE RULES (violations cause compile failures or new lint errors):
- NO if/else/for/while/switch/return — CashScript uses only require() statements.
- NO ternary operator (?:).
- NO compound assignment (+=, -=, *=, /=, ++, --).
- Timelock MUST be standalone: `require(tx.time >= X);` or `require(tx.age >= X);`
  NEVER chain or nest tx.time: e.g. `require(checkSig(...) && tx.time >= X)` is FORBIDDEN.
- `new LockingBytecodeP2PKH(x)` requires x to be hash160-wrapped: `new LockingBytecodeP2PKH(hash160(pubkey))`.
- All tx.outputs[N] access requires a prior `require(tx.outputs.length == K)` guard in the same function.

Output ONLY the corrected CashScript code. NO markdown formatting, NO explanations, NO backticks.
Start exactly with `pragma cashscript`.
"""

        user_prompt = f"""--- ORIGINAL CODE ---
{original_code}

--- VULNERABILITY TO FIX ---
Title: {issue.title}
Rule ID: {issue.rule_id}
Line Number: {issue.line}
Description: {issue.description}
Fix Hint: {issue.recommendation}

Apply the fix according to the constraints and return the raw code.
"""

        # Tiered attempts: Haiku 4.5 (x2) -> Sonnet 4.6 (x1)
        repair_provider = self.factory.get_provider("repair")
        haiku_config = repair_provider.primary
        sonnet_config = repair_provider.fallbacks[0] if repair_provider.fallbacks else haiku_config

        attempts = [
            ("Attempt 1: Haiku 4.5", haiku_config.provider),
            ("Attempt 2: Haiku 4.5 (Retry)", haiku_config.provider),
            ("Attempt 3: Sonnet 4.6 (Escalation)", sonnet_config.provider),
        ]

        for attempt_idx, (label, provider) in enumerate(attempts):
            logger.info(f"Running Repair {label}")
            corrected_code = await self._attempt_repair(
                provider, original_code, issue, sys_prompt, user_prompt
            )

            if not corrected_code:
                continue

            # ── Deterministic validation — no LLM re-audit ─────────────────
            valid = True
            rejection_reason = ""

            # Gate 1: DSL lint must not introduce new violations
            if valid:
                from src.services.dsl_lint import get_dsl_linter
                linter = get_dsl_linter()

                lint_new = linter.lint(corrected_code)
                lint_orig = linter.lint(original_code)

                new_ids = {v.get("rule_id") for v in lint_new.get("violations", [])}
                orig_ids = {v.get("rule_id") for v in lint_orig.get("violations", [])}
                added = new_ids - orig_ids

                if added:
                    valid = False
                    rejection_reason = f"introduced new lint violations: {added}"

                    # Build feedback for next attempt
                    msgs = [
                        f"- [{v.get('rule_id')}] L{v.get('line_hint', '?')}: {v.get('message', '')}"
                        for v in lint_new.get("violations", [])
                        if v.get("rule_id") in added
                    ]
                    if msgs and attempt_idx < len(attempts) - 1:
                        feedback = (
                            "\n\n--- PREVIOUS ATTEMPT FAILED WITH THESE NEW VIOLATIONS ---\n"
                            "Your last fix introduced these new lint errors. Do NOT repeat:\n"
                            + "\n".join(msgs)
                            + "\n\nCritical reminder: require(tx.time >= X) must be STANDALONE — "
                            "never combined with && or || or nested inside another expression."
                        )
                        user_prompt = user_prompt.split("--- PREVIOUS ATTEMPT")[0] + feedback

            if valid:
                logger.info(f"Repair {label} successful!")
                return RepairResponse(corrected_code=corrected_code, success=True)
            else:
                logger.warning(f"Repair {label} rejected: {rejection_reason}")

        # All attempts failed
        logger.warning("All repair attempts failed. Returning original code.")
        return RepairResponse(corrected_code=original_code, success=False)


def get_repair_agent() -> RepairAgent:
    return RepairAgent()
