
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.services.anti_pattern_enforcer import get_anti_pattern_enforcer

def test_tautology():
    code = """
    pragma cashscript ^0.10.0;
    contract Tautology(int x) {
        function spend() {
            require(tx.outputs.length == tx.outputs.length);
            require(checkSig(sig, pk));
        }
    }
    """
    enforcer = get_anti_pattern_enforcer()
    result = enforcer.validate_code(code)
    print(f"TEST Tautology: passed={result['valid']}, violations={[v['rule'] for v in result.get('violations', [])]}")
    assert any(v['rule'] == 'tautological_guard' for v in result.get('violations', []))

def test_self_comparison():
    code = """
    pragma cashscript ^0.10.0;
    contract SelfComp(pubkey pk) {
        function spend() {
            require(tx.outputs[0].lockingBytecode == tx.outputs[0].lockingBytecode);
            require(checkSig(sig, pk));
        }
    }
    """
    enforcer = get_anti_pattern_enforcer()
    result = enforcer.validate_code(code)
    print(f"TEST Self Comparison: passed={result['valid']}, violations={[v['rule'] for v in result.get('violations', [])]}")
    assert any(v['rule'] == 'locking_bytecode_self_comparison' for v in result.get('violations', []))

def test_sig_reuse():
    code = """
    pragma cashscript ^0.10.0;
    contract SigReuse(pubkey p1, pubkey p2) {
        function spend(sig s1) {
            require(checkSig(s1, p1));
            require(checkSig(s1, p2));
        }
    }
    """
    enforcer = get_anti_pattern_enforcer()
    result = enforcer.validate_code(code)
    print(f"TEST Signature Reuse: passed={result['valid']}, violations={[v['rule'] for v in result.get('violations', [])]}")
    assert any(v['rule'] == 'multisig_signature_reuse' for v in result.get('violations', []))

if __name__ == "__main__":
    print("--- STARTING ADVANCED GUARD VERIFICATION ---")
    try:
        test_tautology()
        test_self_comparison()
        test_sig_reuse()
        print("--- ADVANCED GUARD VERIFICATION COMPLETE: ALL PASSED ---")
    except Exception as e:
        print(f"--- ADVANCED GUARD VERIFICATION FAILED: {e} ---")
        sys.exit(1)
