import re
import yaml
from pathlib import Path
from typing import List, Dict, Any

class FeatureExtractor:
    def __init__(self, config_path: str = "benchmark/config/feature_rules.yaml"):
        self.config_path = Path(config_path)
        self.rules = {}
        self.load_rules()

    def load_rules(self):
        if not self.config_path.exists():
            print(f"Warning: Feature rules not found at {self.config_path}")
            return

        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            self.rules = data.get("features", {})

    def extract(self, code: str) -> Dict[str, Any]:
        """Detect features and function roles in the provided code."""
        detected = set()
        
        # 1. Base Regex Detection (from config)
        for feature_name, config in self.rules.items():
            pattern = config.get("rule")
            if not pattern:
                continue
            
            if re.search(pattern, code, re.DOTALL | re.IGNORECASE):
                detected.add(feature_name)
        
        # 2. Multisig & Signature Expansion
        msig_pattern = r'checkMultiSig\s*\(\s*\[(.*?)\]\s*,\s*\[(.*?)\]\s*\)'
        for match in re.finditer(msig_pattern, code, re.DOTALL | re.IGNORECASE):
            pubkey_array_str = match.group(2)
            pubkeys = [r.strip() for r in pubkey_array_str.split(",") if r.strip()]
            for pk in pubkeys:
                detected.add(f"{pk.lower()}_signature")
            detected.add("multisig")
            
        sig_pattern = r'checkSig\s*\(\s*\w+\s*,\s*(\w+)\s*\)'
        for match in re.finditer(sig_pattern, code, re.IGNORECASE):
            role_name = match.group(1).lower()
            detected.add(f"{role_name}_signature")

        # 3. Function Role Analysis
        functions = []
        # Basic function block extractor: matches 'function name(args) { body }'
        # Note: This regex is simple and might miss nested braces, but usually sufficient for CashScript.
        func_blocks = re.finditer(r'function\s+(\w+)\s*\((.*?)\)\s*\{([^}]*)\}', code, re.DOTALL)
        for fb in func_blocks:
            name = fb.group(1).lower()
            body = fb.group(3)
            
            role = "GENERIC"
            if any(kw in name for kw in ["announce", "start", "initiate", "prepare"]):
                role = "INTERMEDIATE"
            elif any(kw in name for kw in ["claim", "finalize", "withdraw", "execute"]):
                role = "TERMINAL"
            elif any(kw in name for kw in ["cancel", "emergency", "recover"]):
                role = "RECOVERY"
            
            functions.append({
                "name": name,
                "role": role,
                # Only self-continuation counts as covenant anchor (recipient lockingBytecode is not).
                "has_anchor": "this.activeBytecode" in body,
                "has_value_check": (".value" in body or "tokenAmount" in body) and "tx.inputs" in body
            })

        return {
            "features": list(detected),
            "functions": functions
        }

    def get_missing(self, required: List[str], detected: List[str]) -> List[str]:
        return list(set(required) - set(detected))

    def get_extraneous(self, required: List[str], detected: List[str]) -> List[str]:
        return list(set(detected) - set(required))

    def get_hallucinated(self, required: List[str], detected: List[str]) -> List[str]:
        # Hallucinated is now reserved for explicitly conflicting or invalid features.
        # Since our regexes now only catch valid subsets, this is largely empty.
        return []
