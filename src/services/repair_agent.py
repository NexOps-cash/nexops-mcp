import re
import logging
from typing import Dict, Any, Optional

from src.models import RepairRequest, RepairResponse, AuditReport, AuditIssue
from src.services.audit_agent import get_audit_agent
from src.services.llm.factory import LLMFactory

logger = logging.getLogger("nexops.repair")

class RepairAgent:
    """
    Applies surgical LLM-based repairs for a specific Security Issue.
    Follows stringent invariants:
    1. Only edits the target vulnerability.
    2. Must NOT decrease the number of require() guards.
    3. The structural_score must not drop strictly below the original score.
    4. Must not introduce new HIGH/CRITICAL issues.
    """
    
    def __init__(self, anthropic_client=None):
        # We now use the LLMFactory which manages OpenRouter/Groq providers
        self.factory = LLMFactory()
        
    def _count_requires(self, code: str) -> int:
        return len(re.findall(r"\brequire\s*\(", code))

    async def _attempt_repair(self, provider, original_code: str, issue: AuditIssue, sys_prompt: str, user_prompt: str) -> Optional[str]:
        try:
            corrected_code = await provider.complete(
                prompt=user_prompt,
                system=sys_prompt
            )
            
            if not corrected_code:
                return None
                
            corrected_code = corrected_code.strip()
            # Remove backticks if LLM ignores instruction
            if corrected_code.startswith("```"):
                corrected_code = "\n".join(corrected_code.split("\n")[1:])
            if "```" in corrected_code:
                corrected_code = corrected_code.split("```")[0]
            
            return corrected_code.strip()
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            return None

    async def repair(self, request: RepairRequest) -> RepairResponse:
        original_code = request.original_code
        issue = request.issue
        
        # 1. Baseline the original code
        audit_agent = get_audit_agent()
        original_report = audit_agent.audit(original_code)
        original_require_count = self._count_requires(original_code)
        
        # 2. Build the strict prompt
        sys_prompt = f"""You are NexOps RepairAgent, an expert CashScript security engineer.
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

        # 3. TIERED ATTEMPTS: Haiku 4.5 (x2) -> Sonnet 4.6 (x1)
        repair_provider = self.factory.get_provider("repair") # Returns ResilientProvider([Haiku-4.5, Sonnet-4.6])
        
        # We explicitly manage the attempts to follow the (2x Haiku, 1x Sonnet) requirement
        haiku_config = repair_provider.primary
        sonnet_config = repair_provider.fallbacks[0] if repair_provider.fallbacks else haiku_config

        attempts = [
            ("Attempt 1: Haiku 4.5", haiku_config.provider),
            ("Attempt 2: Haiku 4.5 (Retry)", haiku_config.provider),
            ("Attempt 3: Sonnet 4.6 (Escalation)", sonnet_config.provider)
        ]

        for label, provider in attempts:
            logger.info(f"Running Repair {label}")
            corrected_code = await self._attempt_repair(provider, original_code, issue, sys_prompt, user_prompt)
            
            if not corrected_code:
                continue

            # 4. Immediate Verification
            new_require_count = self._count_requires(corrected_code)
            new_report = audit_agent.audit(corrected_code)
            
            # Constraint check logic
            valid = True
            rejection_reason = ""

            # Check: require() counts did not drop
            if new_require_count < original_require_count:
                valid = False
                rejection_reason = f"dropped require() guards ({original_require_count} -> {new_require_count})"
            
            # Check: Structural score must not drop strictly below original
            elif new_report.metadata.structural_score < original_report.metadata.structural_score:
                valid = False
                rejection_reason = "lowered overall structural score"
                
            # Check: The target issue should be gone
            else:
                target_issue_fixed = True
                for i in new_report.issues:
                    if i.rule_id == issue.rule_id:
                        target_issue_fixed = False
                        break
                if not target_issue_fixed:
                    valid = False
                    rejection_reason = f"issue {issue.rule_id} was not resolved"
                
            # Check: No *new* HIGH/CRITICAL issues introduced
            if valid:
                initial_highs = {i.rule_id for i in original_report.issues if i.severity in ["HIGH", "CRITICAL"]}
                new_highs = {i.rule_id for i in new_report.issues if i.severity in ["HIGH", "CRITICAL"]}
                added_highs = new_highs - initial_highs
                if added_highs:
                    valid = False
                    rejection_reason = f"introduced new HIGH/CRITICAL issues: {added_highs}"

            if valid:
                logger.info(f"Repair {label} successful!")
                return RepairResponse(
                    corrected_code=corrected_code,
                    new_report=new_report,
                    success=True
                )
            else:
                logger.warning(f"Repair {label} rejected: {rejection_reason}")

        # All attempts failed
        return RepairResponse(
            corrected_code=original_code,
            new_report=original_report,
            success=False
        )

def get_repair_agent() -> RepairAgent:
    return RepairAgent()
