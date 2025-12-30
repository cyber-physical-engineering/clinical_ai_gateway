"""
Unit tests for output_rails.py (Phase 4)

Run: python -m pytest rails/test_output_rails.py -v
Or:  python rails/test_output_rails.py
"""

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from rails.output_rails import (
    validate_output_schema,
    validate_risk_score,
    validate_confidence,
    check_output_schema,
    check_hallucinations,
    run_canary_scan,
    run_output_rails,
)


def test_validate_output_schema_pass():
    """Test schema validation with all required keys present."""
    parsed = {
        "risk_score": "LOW",
        "findings": ["Normal"],
        "confidence": 0.95,
        "disclaimer": "AI-assisted"
    }
    valid, missing = validate_output_schema(parsed, ["risk_score", "findings", "confidence", "disclaimer"])
    assert valid is True
    assert missing == []
    print("✅ test_validate_output_schema_pass")


def test_validate_output_schema_missing_keys():
    """Test schema validation with missing keys."""
    parsed = {
        "risk_score": "LOW",
        "findings": ["Normal"],
    }
    valid, missing = validate_output_schema(parsed, ["risk_score", "findings", "confidence", "disclaimer"])
    assert valid is False
    assert "confidence" in missing
    assert "disclaimer" in missing
    print("✅ test_validate_output_schema_missing_keys")


def test_validate_output_schema_none():
    """Test schema validation with None input."""
    valid, missing = validate_output_schema(None, ["risk_score", "findings"])
    assert valid is False
    assert missing == ["risk_score", "findings"]
    print("✅ test_validate_output_schema_none")


def test_validate_risk_score_valid():
    """Test risk_score validation with valid values."""
    for value in ["LOW", "MEDIUM", "HIGH", "UNKNOWN"]:
        valid, reason = validate_risk_score({"risk_score": value})
        assert valid is True, f"Failed for {value}"
    print("✅ test_validate_risk_score_valid")


def test_validate_risk_score_invalid():
    """Test risk_score validation with invalid value."""
    valid, reason = validate_risk_score({"risk_score": "EXTREME"})
    assert valid is False
    assert "EXTREME" in reason
    print("✅ test_validate_risk_score_invalid")


def test_validate_confidence_valid():
    """Test confidence validation with valid values."""
    for value in [0.0, 0.5, 1.0, 0.95]:
        valid, reason = validate_confidence({"confidence": value})
        assert valid is True, f"Failed for {value}"
    print("✅ test_validate_confidence_valid")


def test_validate_confidence_out_of_range():
    """Test confidence validation with out-of-range values."""
    valid, reason = validate_confidence({"confidence": 1.5})
    assert valid is False
    assert "not in range" in reason
    
    valid, reason = validate_confidence({"confidence": -0.1})
    assert valid is False
    print("✅ test_validate_confidence_out_of_range")


def test_check_output_schema_full_pass():
    """Test full schema check with valid output."""
    parsed = {
        "risk_score": "MEDIUM",
        "findings": ["Opacity detected"],
        "confidence": 0.85,
        "disclaimer": "Requires radiologist review"
    }
    result = check_output_schema(parsed, ["risk_score", "findings", "confidence", "disclaimer"])
    assert result.passed is True
    assert result.reason_code is None
    print("✅ test_check_output_schema_full_pass")


def test_check_output_schema_missing_key():
    """Test schema check blocks on missing key."""
    parsed = {
        "risk_score": "LOW",
        "findings": [],
    }
    result = check_output_schema(parsed, ["risk_score", "findings", "confidence", "disclaimer"])
    assert result.passed is False
    assert result.reason_code == "INVALID_MODEL_OUTPUT"
    assert "confidence" in str(result.message)
    print("✅ test_check_output_schema_missing_key")


def test_hallucination_high_risk_no_findings():
    """Test hallucination check blocks HIGH risk with no findings."""
    parsed = {
        "risk_score": "HIGH",
        "findings": [],
        "confidence": 0.9,
        "disclaimer": ""
    }
    result = check_hallucinations(parsed, "radiology_summary_v1")
    assert result.passed is False
    assert result.reason_code == "HALLUCINATION_DETECTED"
    print("✅ test_hallucination_high_risk_no_findings")


def test_hallucination_medication_in_radiology():
    """Test hallucination check blocks medication language in radiology."""
    parsed = {
        "risk_score": "MEDIUM",
        "findings": ["Patient should be prescribed 500mg ibuprofen"],
        "confidence": 0.8,
        "disclaimer": ""
    }
    result = check_hallucinations(parsed, "radiology_summary_v1")
    assert result.passed is False
    assert result.reason_code == "OUT_OF_SCOPE_OUTPUT"
    print("✅ test_hallucination_medication_in_radiology")


def test_hallucination_pass():
    """Test hallucination check passes with valid radiology output."""
    parsed = {
        "risk_score": "MEDIUM",
        "findings": ["Opacity in left lower lobe", "No pleural effusion"],
        "confidence": 0.85,
        "disclaimer": "AI-assisted analysis"
    }
    result = check_hallucinations(parsed, "radiology_summary_v1")
    assert result.passed is True
    print("✅ test_hallucination_pass")


def test_canary_scan_ssn():
    """Test canary scan detects SSN."""
    raw = "Patient SSN is 123-45-6789"
    result = run_canary_scan(raw, None)
    assert result.passed is False
    assert result.reason_code == "CANARY_PHI_DETECTED"
    assert result.phi_detected is True
    print("✅ test_canary_scan_ssn")


def test_canary_scan_mrn():
    """Test canary scan detects MRN."""
    parsed = {
        "risk_score": "LOW",
        "findings": ["MRN: 12345678 shows normal results"],
        "confidence": 0.9,
        "disclaimer": ""
    }
    result = run_canary_scan(None, parsed)
    assert result.passed is False
    assert result.reason_code == "CANARY_PHI_DETECTED"
    print("✅ test_canary_scan_mrn")


def test_canary_scan_clean():
    """Test canary scan passes with clean output."""
    raw = "Normal chest x-ray with no acute findings."
    parsed = {
        "risk_score": "LOW",
        "findings": ["No acute cardiopulmonary process"],
        "confidence": 0.95,
        "disclaimer": "AI-assisted"
    }
    result = run_canary_scan(raw, parsed)
    assert result.passed is True
    assert result.phi_detected is False
    print("✅ test_canary_scan_clean")


def test_run_output_rails_full_pass():
    """Test full output rails pipeline passes."""
    raw = "Valid response"
    parsed = {
        "risk_score": "LOW",
        "findings": ["No acute findings"],
        "confidence": 0.92,
        "disclaimer": "Requires physician review"
    }
    result = run_output_rails(raw, parsed, "radiology_summary_v1")
    assert result.passed is True
    assert result.phi_detected is False
    assert "all_rails_passed" in result.details
    print("✅ test_run_output_rails_full_pass")


def test_run_output_rails_schema_block():
    """Test output rails blocks on schema failure."""
    parsed = {"risk_score": "LOW"}  # Missing required keys
    result = run_output_rails("response", parsed, "default_workflow")
    assert result.passed is False
    assert result.reason_code == "INVALID_MODEL_OUTPUT"
    assert result.details.get("blocked_by") == "schema_validation"
    print("✅ test_run_output_rails_schema_block")


def test_run_output_rails_canary_block():
    """Test output rails blocks on PHI detection."""
    raw = "Patient John Smith, SSN 123-45-6789"
    parsed = {
        "risk_score": "LOW",
        "findings": ["Normal"],
        "confidence": 0.9,
        "disclaimer": ""
    }
    result = run_output_rails(raw, parsed, "default_workflow")
    assert result.passed is False
    assert result.reason_code == "CANARY_PHI_DETECTED"
    assert result.phi_detected is True
    print("✅ test_run_output_rails_canary_block")


if __name__ == "__main__":
    print("\n=== Output Rails Unit Tests (Phase 4) ===\n")
    
    # Run all tests
    test_validate_output_schema_pass()
    test_validate_output_schema_missing_keys()
    test_validate_output_schema_none()
    test_validate_risk_score_valid()
    test_validate_risk_score_invalid()
    test_validate_confidence_valid()
    test_validate_confidence_out_of_range()
    test_check_output_schema_full_pass()
    test_check_output_schema_missing_key()
    test_hallucination_high_risk_no_findings()
    test_hallucination_medication_in_radiology()
    test_hallucination_pass()
    test_canary_scan_ssn()
    test_canary_scan_mrn()
    test_canary_scan_clean()
    test_run_output_rails_full_pass()
    test_run_output_rails_schema_block()
    test_run_output_rails_canary_block()
    
    print("\n=== All 18 tests passed! ===\n")

