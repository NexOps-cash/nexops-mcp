"""
test_lnc008_modes.py — Unit tests for LNC-008 Covenant Self-Anchor Guard
"""
import unittest
from src.services.dsl_lint import _check_covenant_self_anchor

class TestLNC008(unittest.TestCase):

    def test_distribution_forbids_self_anchor(self):
        code = """
        contract Distribute(bytes20 recipient) {
            function release(sig s) {
                require(tx.outputs[0].lockingBytecode == this.activeBytecode); // BAD
            }
        }
        """
        # Should flag a violation because distribution MUST NOT self-anchor
        violations = _check_covenant_self_anchor(code, "distribution")
        self.assertEqual(len(violations), 1)
        self.assertIn("MUST NOT use this.activeBytecode", violations[0]["message"])

    def test_distribution_allows_clean_exit(self):
        code = """
        contract Distribute(bytes20 recipient) {
            function release(sig s) {
                require(tx.outputs[0].lockingBytecode == recipient); // GOOD
            }
        }
        """
        violations = _check_covenant_self_anchor(code, "distribution")
        self.assertEqual(len(violations), 0)

    def test_burn_forbids_self_anchor(self):
        code = """
        contract Burn() {
            function burn(sig s) {
                require(tx.outputs[0].lockingBytecode == this.activeBytecode); // BAD
            }
        }
        """
        violations = _check_covenant_self_anchor(code, "burn")
        self.assertEqual(len(violations), 1)
        self.assertIn("MUST NOT use this.activeBytecode", violations[0]["message"])

    def test_vesting_requires_self_anchor(self):
        code = """
        contract Vesting(int cliff) {
            function claim(sig s) {
                require(tx.outputs[0].value == 1000);
                // Missing self-anchor!
            }
        }
        """
        violations = _check_covenant_self_anchor(code, "vesting")
        self.assertEqual(len(violations), 1)
        self.assertIn("has no self-anchor", violations[0]["message"])

    def test_token_does_not_require_self_anchor(self):
        code = """
        contract Token() {
            function transfer(sig s) {
                require(tx.outputs[0].tokenCategory == tx.inputs[0].tokenCategory);
                // Missing self-anchor is OK now!
            }
        }
        """
        # "token" mode NO LONGER implies continuation default
        violations = _check_covenant_self_anchor(code, "token")
        self.assertEqual(len(violations), 0)

    def test_covenant_requires_self_anchor(self):
        code = """
        contract Covenant() {
            function mutate(sig s) {
                require(tx.outputs[0].value == 1000);
                // Missing self-anchor!
            }
        }
        """
        violations = _check_covenant_self_anchor(code, "covenant")
        self.assertEqual(len(violations), 1)

    def test_vault_requires_self_anchor(self):
        code = """
        contract Vault() {
            function deposit(sig s) {
                 require(tx.outputs[0].value > 1000);
            }
        }
        """
        violations = _check_covenant_self_anchor(code, "vault")
        self.assertEqual(len(violations), 1)

    def test_multisig_skips_check(self):
        code = """
        contract Multisig() {
            function spend(sig s1, sig s2) {
                require(tx.outputs[0].value == 1000);
                // No self-anchor, but multisig is stateless/single-spend
            }
        }
        """
        violations = _check_covenant_self_anchor(code, "multisig")
        self.assertEqual(len(violations), 0)

if __name__ == "__main__":
    unittest.main()
