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

    def extract(self, code: str) -> List[str]:
        """Detect features in the provided code using regex rules."""
        detected = set()
        
        # 1. Base Regex Detection (from config)
        for feature_name, config in self.rules.items():
            pattern = config.get("rule")
            if not pattern:
                continue
            
            # Skip static multisig rules if we're going to do dynamic expansion 
            # (avoid multisig_2of3 regex catching 2of2 logic incorrectly)
            if "multisig" in feature_name:
                continue

            if re.search(pattern, code, re.DOTALL | re.IGNORECASE):
                detected.add(feature_name)
        
        # 2. Multisig Feature Expansion (Dynamic)
        # Pattern: checkMultiSig([sig1, sig2], [buyer, seller, arbitrator])
        # Using [^)]* instead of [^\]]* to better handle nested structures or weird spacing
        msig_pattern = r'checkMultiSig\s*\(\s*\[(.*?)\]\s*,\s*\[(.*?)\]\s*\)'
        matches = list(re.finditer(msig_pattern, code, re.DOTALL | re.IGNORECASE))
        
        for match in matches:
            sig_array_str = match.group(1)
            pubkey_array_str = match.group(2)
            
            pubkeys = [r.strip() for r in pubkey_array_str.split(",") if r.strip()]
            for pk in pubkeys:
                detected.add(f"{pk}_signature")
                
            detected.add("multisig")
            
            sigs = [s.strip() for s in sig_array_str.split(",") if s.strip()]
            m = len(sigs)
            n = len(pubkeys)
            if n > 0:
                detected.add(f"multisig_{m}of{n}")

        # If no checkMultiSig found, fallback to static multisig regexes
        if not matches:
            for feature_name, config in self.rules.items():
                if "multisig" in feature_name:
                    pattern = config.get("rule")
                    if pattern and re.search(pattern, code, re.DOTALL | re.IGNORECASE):
                        detected.add(feature_name)
                        
        # 3. Dynamic Signature Detection (Role-Agnostic)
        sig_pattern = r'checkSig\s*\(\s*\w+\s*,\s*(\w+)\s*\)'
        for match in re.finditer(sig_pattern, code, re.IGNORECASE):
            role_name = match.group(1).lower()
            detected.add(f"{role_name}_signature")
        
        return list(detected)

    def get_missing(self, required: List[str], detected: List[str]) -> List[str]:
        return list(set(required) - set(detected))

    def get_hallucinated(self, required: List[str], detected: List[str]) -> List[str]:
        hallucinated = set(detected) - set(required)
        
        # Allowed additional capabilities that do not contradict intent
        allowed_features = {"stateful", "covenant", "multisig", "value_preservation"}
        hallucinated -= allowed_features
        
        # Suppress 'multisig' hallucination if any multisig threshold is required
        if "multisig" in hallucinated:
            if any(f.startswith("multisig_") for f in required):
                hallucinated.remove("multisig")
                
        return list(hallucinated)
