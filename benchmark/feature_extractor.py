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
        detected = []
        for feature_name, config in self.rules.items():
            pattern = config.get("rule")
            if not pattern:
                continue
            
            # Using re.DOTALL and re.IGNORECASE for maximum flexibility
            if re.search(pattern, code, re.DOTALL | re.IGNORECASE):
                detected.append(feature_name)
        
        return detected

    def get_missing(self, required: List[str], detected: List[str]) -> List[str]:
        return list(set(required) - set(detected))

    def get_hallucinated(self, required: List[str], detected: List[str]) -> List[str]:
        return list(set(detected) - set(required))
