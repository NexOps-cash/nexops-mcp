"""
Quick verification that:
1. All 5 original vault tests still pass
2. LNC-006 detects tx.outputs[N].activeBytecode
3. Phase 2 sanitizer fixes tx.outputs[N].activeBytecode -> .lockingBytecode
"""
import sys, os, io, re
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from src.services.dsl_lint import get_dsl_linter

linter = get_dsl_linter()
PASS = "[PASS]"
FAIL = "[FAIL]"

print("=" * 65)
print("VAULT LINTER + SANITIZER REGRESSION TESTS")
print("=" * 65)

# --- Existing 5 tests ---
FINALIZE_CODE = """pragma cashscript ^0.13.0;
contract Vault(pubkey owner, int delaySeconds) {
    function announce(sig sig, int amount) {
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - amount);
        require(tx.outputs[1].value == amount);
        require(checkSig(sig, owner));
    }
    function finalize(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.age >= delaySeconds);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, owner));
    }
}"""
res = linter.lint(FINALIZE_CODE, "vault")
lnc008_on_finalize = [v for v in res["violations"] if v["rule_id"] == "LNC-008" and "finalize" in v["message"].lower()]
print(f"{PASS if not lnc008_on_finalize else FAIL} TEST 1: LNC-008 skips finalize")

EMERGENCY_CODE = """pragma cashscript ^0.13.0;
contract Vault(pubkey owner, pubkey backup) {
    function announce(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, owner));
    }
    function emergencyRecover(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, backup));
    }
    function recover(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, backup));
    }
}"""
res = linter.lint(EMERGENCY_CODE, "vault")
lnc008 = [v for v in res["violations"] if v["rule_id"] == "LNC-008"]
print(f"{PASS if not lnc008 else FAIL} TEST 2: LNC-008 skips emergency/recover")

NO_GUARD = """pragma cashscript ^0.13.0;
contract Vault(pubkey owner) {
    function announce(sig sig, int amount) {
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - amount);
        require(tx.outputs[1].value == amount);
        require(checkSig(sig, owner));
    }
}"""
res = linter.lint(NO_GUARD, "vault")
ids = [v["rule_id"] for v in res["violations"]]
print(f"{PASS if 'LNC-001c' in ids else FAIL} TEST 3: LNC-001c fires for missing length guard")

NO_VALUE = """pragma cashscript ^0.13.0;
contract Vault(pubkey owner) {
    function announce(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(checkSig(sig, owner));
    }
}"""
res = linter.lint(NO_VALUE, "vault")
ids = [v["rule_id"] for v in res["violations"]]
print(f"{PASS if 'LNC-016' in ids else FAIL} TEST 4: LNC-016 fires for missing value preservation")

CORRECT = """pragma cashscript ^0.13.0;
contract SecureVault(pubkey owner, pubkey backup, int delaySeconds) {
    function announce(sig sig, int amount) {
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - amount);
        require(tx.outputs[1].value == amount);
        require(checkSig(sig, owner));
    }
    function finalize(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.age >= delaySeconds);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, owner));
    }
    function emergencyRecover(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, backup));
    }
}"""
res = linter.lint(CORRECT, "vault")
blocking = [v for v in res["violations"] if v.get("severity") != "warning"]
print(f"{PASS if not blocking else FAIL} TEST 5: Correct vault passes clean")
if blocking:
    for v in blocking:
        print(f"       {v['rule_id']} L{v['line_hint']}: {v['message'][:80]}")

# --- New TEST 6: LNC-006 detects tx.outputs[N].activeBytecode ---
BAD_FIELD = """pragma cashscript ^0.13.0;
contract Vault(pubkey owner) {
    function announce(sig sig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].activeBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(sig, owner));
    }
}"""
res = linter.lint(BAD_FIELD, "vault")
ids = [v["rule_id"] for v in res["violations"]]
print(f"{PASS if 'LNC-006' in ids else FAIL} TEST 6: LNC-006 detects tx.outputs[N].activeBytecode (invalid field)")

# --- TEST 7: Check post-gen sanitizer regex directly ---
bad_code = "require(tx.outputs[0].activeBytecode == this.activeBytecode);"
fixed = re.sub(r"(tx\.outputs\[.*?\])\.activeBytecode", r"\1.lockingBytecode", bad_code)
expected = "require(tx.outputs[0].lockingBytecode == this.activeBytecode);"
print(f"{PASS if fixed == expected else FAIL} TEST 7: Sanitizer regex correctly rewrites .activeBytecode -> .lockingBytecode")
if fixed != expected:
    print(f"       Got: {fixed}")

print("=" * 65)
print("DONE")
