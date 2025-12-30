"""
Unit tests for sanitizer.py (Phase 5 - Split-Stream Logging)

Run: python rails/test_sanitizer.py
"""

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from rails.sanitizer import (
    hash_value,
    redact_phi,
    sanitize_details,
    get_threat_type,
    get_severity,
    coarsen_timestamp,
    split_stream_event,
    verify_no_phi_in_public,
    PHI_PATTERNS,
)


def test_hash_value_deterministic():
    """Test that hashing is deterministic."""
    result1 = hash_value("patient_123")
    result2 = hash_value("patient_123")
    assert result1 == result2
    assert result1.startswith("sha256:")
    print("✅ test_hash_value_deterministic")


def test_hash_value_different_inputs():
    """Test that different inputs produce different hashes."""
    hash1 = hash_value("patient_123")
    hash2 = hash_value("patient_456")
    assert hash1 != hash2
    print("✅ test_hash_value_different_inputs")


def test_redact_phi_ssn():
    """Test SSN redaction."""
    text = "Patient SSN is 123-45-6789 on file."
    result = redact_phi(text)
    assert "123-45-6789" not in result
    assert "[REDACTED:ssn]" in result
    print("✅ test_redact_phi_ssn")


def test_redact_phi_mrn():
    """Test MRN redaction."""
    text = "MRN: 12345678 shows normal results."
    result = redact_phi(text)
    assert "12345678" not in result
    assert "[REDACTED:mrn]" in result
    print("✅ test_redact_phi_mrn")


def test_redact_phi_email():
    """Test email redaction."""
    text = "Contact: patient@hospital.com for results."
    result = redact_phi(text)
    assert "patient@hospital.com" not in result
    assert "[REDACTED:email]" in result
    print("✅ test_redact_phi_email")


def test_redact_phi_multiple():
    """Test multiple PHI types in one string."""
    text = "Patient John Smith (SSN: 123-45-6789, MRN: 12345678)"
    result = redact_phi(text)
    assert "123-45-6789" not in result
    assert "12345678" not in result
    # Patient name pattern should match "Patient John Smith"
    print("✅ test_redact_phi_multiple")


def test_redact_phi_clean_text():
    """Test that clean text is unchanged."""
    text = "Normal chest x-ray with no acute findings."
    result = redact_phi(text)
    assert result == text
    print("✅ test_redact_phi_clean_text")


def test_sanitize_details_hashes_ids():
    """Test that IDs are hashed, not redacted."""
    details = {
        "patient_id": "PT-12345",
        "request_id": "req_abc123",
        "message": "Request processed"
    }
    result = sanitize_details(details)
    
    # Original IDs should not be present
    assert "PT-12345" not in str(result)
    assert "req_abc123" not in str(result)
    
    # Hashed versions should exist
    assert "patient_id_hash" in result
    assert "request_id_hash" in result
    assert result["patient_id_hash"].startswith("sha256:")
    
    # Non-sensitive fields preserved
    assert result["message"] == "Request processed"
    print("✅ test_sanitize_details_hashes_ids")


def test_sanitize_details_redacts_text():
    """Test that text fields are fully redacted."""
    details = {
        "prompt": "What is wrong with patient John Smith?",
        "findings": ["Finding 1", "Finding 2"],
    }
    result = sanitize_details(details)
    
    assert result["prompt"] == "[REDACTED]"
    assert "[2 items redacted]" in result["findings"]
    print("✅ test_sanitize_details_redacts_text")


def test_get_threat_type():
    """Test threat type mapping."""
    assert get_threat_type("INJECTION_DETECTED") == "injection"
    assert get_threat_type("CANARY_PHI_DETECTED") == "phi_leak"
    assert get_threat_type("NO_BAA_DESTINATION") == "policy_violation"
    assert get_threat_type("UNKNOWN_CODE") == "unknown"
    print("✅ test_get_threat_type")


def test_get_severity():
    """Test severity mapping."""
    assert get_severity("CANARY_PHI_DETECTED") == "CRITICAL"
    assert get_severity("INJECTION_DETECTED") == "HIGH"
    assert get_severity("POLICY_DENY") == "MEDIUM"
    assert get_severity("TOOL_NOT_ALLOWED") == "LOW"
    print("✅ test_get_severity")


def test_coarsen_timestamp():
    """Test timestamp coarsening to hour-level."""
    result = coarsen_timestamp("2024-12-27T10:35:42Z")
    assert result == "2024-12-27T10:00:00Z"
    print("✅ test_coarsen_timestamp")


def test_split_stream_creates_both_events():
    """Test that split_stream creates private and public events."""
    private, public = split_stream_event(
        request_id="req_test123",
        timestamp="2024-12-27T10:30:00Z",
        phase="OUTPUT",
        status="BLOCK",
        reason_code="CANARY_PHI_DETECTED",
        guardrail="PHI Kill-Switch",
        details={"patient_id": "PT-SECRET", "phi_types": ["ssn"]},
        workflow="radiology_summary_v1",
        destination="vertex_gemini",
    )
    
    # Private event should have full details
    assert private.request_id == "req_test123"
    assert private.status == "BLOCK"
    assert private.reason_code == "CANARY_PHI_DETECTED"
    assert "PT-SECRET" in str(private.details)  # PHI preserved in private
    
    # Public event should be sanitized
    assert public is not None
    assert public.request_hash.startswith("sha256:")
    assert "req_test123" not in public.request_hash  # Original ID hidden
    assert public.threat_type == "phi_leak"
    assert public.severity == "CRITICAL"
    assert public.workflow_category == "radiology"
    assert public.destination_type == "cloud_provider"
    
    print("✅ test_split_stream_creates_both_events")


def test_split_stream_pass_no_public():
    """Test that PASS events don't create public threat events."""
    private, public = split_stream_event(
        request_id="req_test456",
        timestamp="2024-12-27T10:30:00Z",
        phase="OUTPUT",
        status="PASS",
        reason_code=None,
        guardrail=None,
        details={},
    )
    
    assert private is not None
    assert public is None  # No threat intel for passing requests
    print("✅ test_split_stream_pass_no_public")


def test_verify_no_phi_clean():
    """Test PHI verification on clean public event."""
    _, public = split_stream_event(
        request_id="req_clean",
        timestamp="2024-12-27T10:30:00Z",
        phase="INTERCEPTOR",
        status="BLOCK",
        reason_code="INJECTION_DETECTED",
        guardrail="Prompt Injection Detection",
        details={"pattern": "ignore previous instructions"},
    )
    
    assert verify_no_phi_in_public(public) is True
    print("✅ test_verify_no_phi_clean")


def test_private_event_has_audit_hash():
    """Test that private events have tamper-detection hash."""
    private, _ = split_stream_event(
        request_id="req_audit",
        timestamp="2024-12-27T10:30:00Z",
        phase="POLICY",
        status="BLOCK",
        reason_code="POLICY_DENY",
        guardrail="Role-Based Access",
        details={},
    )
    
    assert private.audit_hash.startswith("sha256:")
    assert len(private.audit_hash) > 20
    print("✅ test_private_event_has_audit_hash")


def test_private_event_retention():
    """Test that private events have HIPAA-compliant retention."""
    private, _ = split_stream_event(
        request_id="req_hipaa",
        timestamp="2024-12-27T10:30:00Z",
        phase="OUTPUT",
        status="PASS",
        details={},
    )
    
    # 7 years = 2555 days
    assert private.retention_days == 2555
    print("✅ test_private_event_retention")


if __name__ == "__main__":
    print("\n=== Sanitizer Unit Tests (Phase 5) ===\n")
    
    test_hash_value_deterministic()
    test_hash_value_different_inputs()
    test_redact_phi_ssn()
    test_redact_phi_mrn()
    test_redact_phi_email()
    test_redact_phi_multiple()
    test_redact_phi_clean_text()
    test_sanitize_details_hashes_ids()
    test_sanitize_details_redacts_text()
    test_get_threat_type()
    test_get_severity()
    test_coarsen_timestamp()
    test_split_stream_creates_both_events()
    test_split_stream_pass_no_public()
    test_verify_no_phi_clean()
    test_private_event_has_audit_hash()
    test_private_event_retention()
    
    print("\n=== All 17 tests passed! ===\n")

