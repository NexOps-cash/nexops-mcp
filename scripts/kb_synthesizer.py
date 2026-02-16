import os
import glob
import logging
from pathlib import Path
from typing import List
import google.generativeai as genai
from langextract import LangExtract
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nexops.synthesizer")

class SecurityInvariant(BaseModel):
    name: str = Field(description="Name of the security invariant or principle")
    description: str = Field(description="Description of why this principle is critical")
    rationale: str = Field(description="The underlying technical rationale in BCH contexts")

class GenerationRule(BaseModel):
    id: str = Field(description="Unique ID for the rule, e.g., AUTH-01")
    rule: str = Field(description="The concrete, actionable rule for the LLM engineer")
    severity: str = Field(description="Severity (Critical, High, Medium, Low)")
    check: str = Field(description="How to verify if this rule is followed in code")

class KBSynthesis(BaseModel):
    methodology_principles: List[SecurityInvariant] = Field(description="List of core methodologies found in the patterns")
    ruleset: List[GenerationRule] = Field(description="List of concrete engineering rules synthesized from the patterns")

def synthesize_kb(kb_dir: str, api_key: str):
    """
    Uses LangExtract to synthesize a Methodology and Ruleset from KB files.
    """
    genai.configure(api_key=api_key)
    
    # 1. Gather all relevant knowledge files
    kb_path = Path(kb_dir)
    files = []
    # Focus on patterns and anti-patterns as they contain the most logic
    for pattern_file in kb_path.glob("patterns/*.cash"):
        files.append(pattern_file)
    for anti_pattern_file in kb_path.glob("anti_pattern/*.cash"):
        files.append(anti_pattern_file)
        
    if not files:
        logger.error("No knowledge files found to analyze.")
        return

    logger.info(f"Analyzing {len(files)} files via LangExtract...")

    # 2. Initialize LangExtract with the desired schema
    extractor = LangExtract(
        model="gemini-1.5-pro", # Or another suitable model
        schema=KBSynthesis,
        prompt="""
        Analyze the provided CashScript code patterns and security documentation.
        Your goal is to synthesize a high-level technical methodology and a set of concrete engineering rules.
        
        Extraction Goals:
        1. Identify the recurring 'Methodology' principles (e.g., 'Explicit Validation over Implicit Assumptions', 'Consensus Anchor Binding').
        2. Synthesize 'Generation Rules' that an AI Engineer must follow to produce 100% safe code (e.g., 'Mandatory Output Bounding', 'No Raw Byte Destinations').
        
        Ensure every rule is grounded in the provided examples.
        """
    )

    # 3. Process files
    results = []
    for file_path in files:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            logger.info(f"Extracting from {file_path.name}...")
            # Note: LangExtract handles the structured extraction
            extracted = extractor.extract(content)
            results.append(extracted)

    # 4. Final Aggregation (Merge results)
    # In a real LangExtract flow, you might do a second pass to de-duplicate and refine
    final_principles = {}
    final_rules = {}
    
    for r in results:
        for p in r.methodology_principles:
            final_principles[p.name] = p
        for rule in r.ruleset:
            final_rules[rule.id] = rule

    # 5. Write to files
    output_dir = Path("docs")
    output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "KB_METHODOLOGY.md", "w", encoding="utf-8") as f:
        f.write("# NexOps KB Methodology\n\n")
        f.write("Synthesized from established security patterns.\n\n")
        for p in final_principles.values():
            f.write(f"## {p.name}\n")
            f.write(f"- **Description**: {p.description}\n")
            f.write(f"- **Rationale**: {p.rationale}\n\n")

    spec_dir = Path("specs")
    spec_dir.mkdir(exist_ok=True)
    with open(spec_dir / "GENERATION_RULESET.md", "w", encoding="utf-8") as f:
        f.write("# Engineering Generation Ruleset\n\n")
        f.write("Mandatory rules for the NexOps Engineer Phase.\n\n")
        for rule in final_rules.values():
            f.write(f"### [{rule.id}] {rule.rule}\n")
            f.write(f"- **Severity**: {rule.severity.upper()}\n")
            f.write(f"- **Verification**: {rule.check}\n\n")

    logger.info("Synthesis complete. Files generated in docs/ and specs/.")

if __name__ == "__main__":
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Please set GOOGLE_API_KEY environment variable.")
    else:
        synthesize_kb("knowledge", api_key)
