import pytest
from benchmark.feature_extractor import FeatureExtractor

@pytest.fixture
def extractor():
    return FeatureExtractor()

def test_multisig_expansion_standard(extractor):
    code = "checkMultiSig([sig1, sig2], [buyer, seller, arbitrator])"
    features = extractor.extract(code)
    
    assert "multisig" in features
    assert "multisig_2of3" in features
    assert "buyer_signature" in features
    # seller_signature might be caught by the general regex too, but extractor ensures it
    assert "seller_signature" in features
    assert "arbitrator_signature" in features

def test_multisig_expansion_single(extractor):
    code = "checkMultiSig([s1], [owner])"
    features = extractor.extract(code)
    
    assert "multisig" in features
    assert "multisig_1of1" in features
    assert "owner_signature" in features

def test_multisig_expansion_spacing(extractor):
    code = "checkMultiSig([sig1 ,sig2],[buyer , seller , arbitrator])"
    features = extractor.extract(code)
    
    assert "multisig_2of3" in features
    assert "buyer_signature" in features
    assert "seller_signature" in features
    assert "arbitrator_signature" in features

def test_no_multisig(extractor):
    code = "require(checkSig(sig, buyer));"
    features = extractor.extract(code)
    
    assert "multisig" not in features
    assert "buyer_signature" in features

def test_multisig_with_complex_params(extractor):
    # Testing that regex doesn't break with non-simple names (though roles are usually simple)
    code = "checkMultiSig([sig1, sig2], [tx.inputs[0].pubkey, seller])"
    features = extractor.extract(code)
    
    assert "multisig_2of2" in features
    assert "tx.inputs[0].pubkey_signature" in features
    assert "seller_signature" in features

def test_hallucination_suppression(extractor):
    code = "checkMultiSig([sig1, sig2], [buyer, seller, arbitrator])"
    detected = extractor.extract(code) # includes multisig, multisig_2of3, roles
    
    required = ["multisig_2of3", "buyer_signature"]
    hallucinated = extractor.get_hallucinated(required, detected)
    
    # 'multisig' should NOT be in hallucinated, even though it's in detected but not required
    assert "multisig" not in hallucinated
    # 'seller_signature' and 'arbitrator_signature' ARE hallucinated here (not required)
    assert "seller_signature" in hallucinated
    assert "arbitrator_signature" in hallucinated
