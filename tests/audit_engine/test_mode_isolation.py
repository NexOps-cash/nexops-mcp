import inspect

import src.services.audit_agent as audit_agent
import src.services.pipeline_engine as pipeline_engine


def test_generator_pipeline_unchanged():
    source = inspect.getsource(pipeline_engine)
    assert "from src.services.pipeline import Phase1, Phase2, Phase3" in source
    assert "from src.services.dsl_lint import get_dsl_linter" in source
    assert "Phase3.validate" in source
    assert "audit_phase" not in source


def test_audit_does_not_use_phase3():
    source = inspect.getsource(audit_agent)
    assert "from src.services.audit_engine.audit_phase import validate_audit" in source
    assert "validate_audit(code, effective_mode)" in source
    assert "Phase3.validate" not in source
