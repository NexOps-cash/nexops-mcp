import re
import logging
from typing import Optional

from src.models import EditRequest, EditResponse, AuditReport
from src.services.audit_agent import get_audit_agent
from src.services.llm.factory import LLMFactory

logger = logging.getLogger("nexops.edit")


class EditAgent:
    """
    Applies user-directed edits to CashScript contracts using an LLM.
    Unlike RepairAgent (surgical, rule-targeted), EditAgent handles
    open-ended instructions like 'add an owner signature check' or
    'change the timeout to 50 blocks'.

    Model: Claude 4.6 Sonnet (primary) -> Claude 4.5 Haiku (fallback)
    """

    def __init__(self):
        self.factory = LLMFactory()

    async def edit(self, request: EditRequest) -> EditResponse:
        original_code = request.original_code
        instruction = request.instruction
        effective_mode = request.effective_mode
        
        # BYOK Extraction
        api_key = request.context.get("api_key") if request.context else None
        provider = request.context.get("provider") if request.context else None

        # ── 1. Build the strict system prompt ──
        sys_prompt = """You are NexOps EditAgent, an expert CashScript smart-contract engineer.
The user will give you a CashScript contract and an edit instruction.
Apply the requested change precisely while following these MANDATORY constraints:

You MUST:
- Preserve existing value anchoring (e.g., `tx.outputs[this.activeInputIndex].value == ...`)
- Preserve tokenCategory/tokenAmount checks
- Preserve tx.outputs.length guards
- Preserve this.activeBytecode checks
- Preserve constructor parameters unless the instruction explicitly says otherwise
- NOT introduce Solidity syntax (no `msg.sender`, no `mapping`, no `emit`)
- NOT introduce loops or mutation (CashScript is declarative/functional)
- Keep the contract syntactically valid CashScript (pragma, contract, function structure)
- Keep all existing `require()` guards unless the instruction explicitly asks to remove one

Output ONLY the complete, corrected CashScript code.
NO markdown formatting, NO explanations, NO backticks.
Start exactly with `pragma cashscript`."""

        user_prompt = f"""--- ORIGINAL CODE ---
{original_code}

--- EDIT INSTRUCTION ---
{instruction}

{f'--- CONTRACT MODE HINT: {effective_mode} ---' if effective_mode else ''}

Apply the edit according to the constraints and return the complete raw code."""

        # ── 2. Call the LLM ──
        logger.info(f"EditAgent processing instruction: {instruction[:80]}...")
        edit_provider = self.factory.get_provider("edit", api_key=api_key, provider_type=provider)

        try:
            edited_code = await edit_provider.complete(
                prompt=user_prompt,
                system=sys_prompt
            )
        except Exception as e:
            logger.error(f"EditAgent LLM call failed: {e}")
            # Return original code with a failure audit
            audit_agent = get_audit_agent()
            original_report = await audit_agent.audit(code=original_code, effective_mode=effective_mode, api_key=api_key, provider=provider)
            return EditResponse(
                edited_code=original_code,
                success=False,
                new_report=original_report
            )

        if not edited_code:
            logger.warning("EditAgent received empty response from LLM")
            audit_agent = get_audit_agent()
            original_report = await audit_agent.audit(code=original_code, effective_mode=effective_mode, api_key=api_key, provider=provider)
            return EditResponse(
                edited_code=original_code,
                success=False,
                new_report=original_report
            )

        # ── 3. Post-process: strip markdown fences ──
        edited_code = edited_code.strip()
        if edited_code.startswith("```"):
            edited_code = "\n".join(edited_code.split("\n")[1:])
        if "```" in edited_code:
            edited_code = edited_code.split("```")[0]
        edited_code = edited_code.strip()

        # ── 4. Run AuditAgent on the result ──
        logger.info("EditAgent running post-edit audit...")
        audit_agent = get_audit_agent()
        new_report = await audit_agent.audit(code=edited_code, effective_mode=effective_mode, api_key=api_key, provider=provider)

        logger.info(f"EditAgent complete. Audit score: {new_report.total_score}, Risk: {new_report.risk_level}")
        return EditResponse(
            edited_code=edited_code,
            success=True,
            new_report=new_report
        )


def get_edit_agent() -> EditAgent:
    return EditAgent()
