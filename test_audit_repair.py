import asyncio
import logging
from src.services.audit_agent import get_audit_agent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_audit")

# A deliberately flawed contract:
# 1. Unused variable (DSL Lint violation / Compile Error)
# 2. No transaction outputs length guard (MissingOutputLimitDetector)
# 3. Missing time bounds or fee arithmetic (if any added)
# 4. Implicit output ordering accessed without validations 

VULNERABLE_CONTRACT = """
pragma cashscript ^0.10.0;

contract VulnerableEscrow(pubkey arbiter) {
    function release(sig arbiterSig) {
        // Unused var
        int x = 10;
        
        // No tx.outputs.length check
        // Accessing outputs without locking bytecode check
        require(tx.outputs[0].value > 1000);
        require(checkSig(arbiterSig, arbiter));
    }
}
"""

async def test_audit():
    agent = get_audit_agent()
    
    print("--- RUNNING AUDIT AGENT ---")
    report = agent.audit(VULNERABLE_CONTRACT, effective_mode="escrow")
    
    print("\n--- AUDIT METADATA ---")
    print(f"Contract Hash:    {report.metadata.contract_hash}")
    print(f"Compile Success:  {report.metadata.compile_success}")
    print(f"DSL Passed:       {report.metadata.dsl_passed}")
    print(f"Structural Score: {report.metadata.structural_score:.2f}")

    print("\n--- FINAL SCORE & RISK ---")
    print(f"Score:      {report.score}/100")
    print(f"Risk Level: {report.risk_level}")
    
    print(f"\n--- ISSUES ({len(report.issues)} total, {report.total_high} High) ---")
    for issue in report.issues:
        print(f"[{issue.severity.value}] {issue.title}")
        print(f"      Rule: {issue.rule_id} | Line: {issue.line}")
        print(f"      {issue.description}")
        print(f"      Hint: {issue.recommendation}\n")

if __name__ == "__main__":
    asyncio.run(test_audit())
