import pytest
from benchmark.feature_extractor import FeatureExtractor

@pytest.fixture
def extractor():
    return FeatureExtractor()

def test_multisig_2of2_separate_requires(extractor):
    code = """
    require(checkSig(a));
    require(checkSig(b));
    """
    detected = extractor.extract(code)
    assert "multisig_2of2" not in detected, "multisig_2of2 should NOT be detected for separate statements"

def test_multisig_2of2_inline_require(extractor):
    code = """
    require(checkSig(a) && checkSig(b));
    """
    detected = extractor.extract(code)
    assert "multisig_2of2" in detected, "multisig_2of2 SHOULD be detected for inline && check"

def test_extraneous_features_classification(extractor):
    required = ["owner_signature"]
    detected = ["owner_signature", "beneficiary_signature"]
    
    extraneous = extractor.get_extraneous(required, detected)
    
    assert "beneficiary_signature" in extraneous
    assert "owner_signature" not in extraneous

def test_hallucinated_features_classification(extractor):
    required = ["owner_signature"]
    detected = ["owner_signature", "beneficiary_signature", "timelock_refund"]
    
    extraneous = extractor.get_extraneous(required, detected)
    hallucinated = extractor.get_hallucinated(required, detected)
    
    # Based on our updated rules, all valid parsed features not in required are extraneous.
    # Hallucinated is kept logically empty for regex-validated features.
    assert "beneficiary_signature" in extraneous
    assert "timelock_refund" in extraneous
    assert len(hallucinated) == 0

