"""
Output Rails (Phase 4 - Output Validation)

Post-LLM validation that runs AFTER the LLM returns a response:
- Output schema validation (Phase 4.1)
- Hallucination / consistency checks (Phase 4.2)
- Canary PHI scan / kill-switch (Phase 4.3)

These rails can block responses from reaching the client.

See: devlog/gateway_build.md Phase 4
"""

import json
import re
from typing import Optional, Dict, Any, List, Tuple
from pydantic import BaseModel


# =============================================================================
# Output Rail Result
# =============================================================================

class OutputRailResult(BaseModel):
    """Result of running output rails."""
    passed: bool
    reason_code: Optional[str] = None
    guardrail: Optional[str] = None
    message: Optional[str] = None
    sanitized_output: Optional[str] = None
    phi_detected: bool = False
    details: Dict[str, Any] = {}


# =============================================================================
# Phase 4.1: Output Schema Validation
# =============================================================================

def validate_output_schema(
    parsed_output: Optional[Dict[str, Any]],
    required_keys: List[str]
) -> Tuple[bool, List[str]]:
    """
    Validate that the LLM output contains all required keys.
    
    Args:
        parsed_output: Parsed JSON output from LLM (or None if parse failed)
        required_keys: List of keys that must be present (from template)
    
    Returns:
        Tuple of (is_valid, missing_keys)
    """
    if parsed_output is None:
        return False, required_keys  # All keys missing if no valid JSON
    
    missing_keys = [key for key in required_keys if key not in parsed_output]
    return len(missing_keys) == 0, missing_keys


def validate_risk_score(parsed_output: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """
    Validate risk_score has an acceptable value.
    
    Returns:
        Tuple of (is_valid, reason)
    """
    if parsed_output is None:
        return False, "No parsed output"
    
    risk_score = parsed_output.get("risk_score")
    if risk_score is None:
        return False, "risk_score is missing"
    
    valid_values = ["LOW", "MEDIUM", "HIGH", "UNKNOWN"]
    if risk_score not in valid_values:
        return False, f"risk_score '{risk_score}' not in {valid_values}"
    
    return True, "valid"


def validate_confidence(parsed_output: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """
    Validate confidence is a float between 0.0 and 1.0.
    
    Returns:
        Tuple of (is_valid, reason)
    """
    if parsed_output is None:
        return False, "No parsed output"
    
    confidence = parsed_output.get("confidence")
    if confidence is None:
        return False, "confidence is missing"
    
    try:
        conf_float = float(confidence)
        if not (0.0 <= conf_float <= 1.0):
            return False, f"confidence {conf_float} not in range [0.0, 1.0]"
    except (TypeError, ValueError):
        return False, f"confidence '{confidence}' is not a valid number"
    
    return True, "valid"


def check_output_schema(
    parsed_output: Optional[Dict[str, Any]],
    required_keys: List[str]
) -> OutputRailResult:
    """
    Run full output schema validation (Phase 4.1).
    
    Checks:
    1. All required keys are present
    2. risk_score has valid value
    3. confidence is valid float in range
    
    Returns OutputRailResult with pass/fail and details.
    """
    details = {
        "schema_check": "executed",
        "required_keys": required_keys,
    }
    
    # Check 1: Required keys
    keys_valid, missing_keys = validate_output_schema(parsed_output, required_keys)
    details["missing_keys"] = missing_keys
    
    if not keys_valid:
        return OutputRailResult(
            passed=False,
            reason_code="INVALID_MODEL_OUTPUT",
            guardrail="Output Schema Validation",
            message=f"LLM output missing required keys: {missing_keys}",
            details=details
        )
    
    # Check 2: risk_score value
    risk_valid, risk_reason = validate_risk_score(parsed_output)
    details["risk_score_check"] = risk_reason
    
    if not risk_valid:
        return OutputRailResult(
            passed=False,
            reason_code="INVALID_MODEL_OUTPUT",
            guardrail="Output Schema Validation",
            message=f"Invalid risk_score: {risk_reason}",
            details=details
        )
    
    # Check 3: confidence value
    conf_valid, conf_reason = validate_confidence(parsed_output)
    details["confidence_check"] = conf_reason
    
    if not conf_valid:
        return OutputRailResult(
            passed=False,
            reason_code="INVALID_MODEL_OUTPUT",
            guardrail="Output Schema Validation",
            message=f"Invalid confidence: {conf_reason}",
            details=details
        )
    
    # All schema checks passed
    details["schema_valid"] = True
    return OutputRailResult(
        passed=True,
        details=details
    )


# =============================================================================
# Phase 4.2: Hallucination / Consistency Checks (Placeholder)
# =============================================================================

def check_hallucinations(
    parsed_output: Optional[Dict[str, Any]],
    workflow: str
) -> OutputRailResult:
    """
    Run hallucination / consistency checks (Phase 4.2).
    
    P0 Deterministic checks:
    - "no medication recommendations" for radiology workflows
    - "findings must not be empty if risk_score is HIGH"
    
    Returns OutputRailResult with pass/fail and details.
    """
    details = {
        "hallucination_check": "executed",
        "workflow": workflow,
    }
    
    if parsed_output is None:
        details["hallucination_check"] = "skipped_no_output"
        return OutputRailResult(passed=True, details=details)
    
    findings = parsed_output.get("findings", [])
    risk_score = parsed_output.get("risk_score", "UNKNOWN")
    
    # Check 1: HIGH risk must have findings
    if risk_score == "HIGH" and len(findings) == 0:
        details["violation"] = "HIGH risk with no findings"
        return OutputRailResult(
            passed=False,
            reason_code="HALLUCINATION_DETECTED",
            guardrail="Consistency Check",
            message="HIGH risk score requires at least one finding",
            details=details
        )
    
    # Check 2: Radiology workflows should not have medication recommendations
    if "radiology" in workflow.lower():
        medication_patterns = [
            r'\b(prescrib\w*|administer\w*|dosage|medication|drug)\b',  # prescribe, prescribed, prescription
            r'\b\d+\s*(mg|ml|mcg)\b',  # 500mg, 10 ml
        ]
        
        findings_text = " ".join(str(f) for f in findings).lower()
        for pattern in medication_patterns:
            if re.search(pattern, findings_text):
                details["violation"] = f"Medication language detected in radiology workflow"
                details["pattern_matched"] = pattern
                return OutputRailResult(
                    passed=False,
                    reason_code="OUT_OF_SCOPE_OUTPUT",
                    guardrail="Scope Enforcement",
                    message="Radiology workflow output contains medication recommendations (out of scope)",
                    details=details
                )
    
    details["consistency_valid"] = True
    return OutputRailResult(passed=True, details=details)


# =============================================================================
# Phase 4.3: Canary PHI Scan (Placeholder - will be expanded)
# =============================================================================

# Common PHI patterns (P0 - simple regex, Presidio integration later)
PHI_PATTERNS = {
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',  # SSN: 123-45-6789
    "mrn": r'\b(MRN|mrn)[:\s]*\d{6,10}\b',  # MRN: 12345678
    "dob": r'\b(DOB|dob|Date of Birth)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
    "phone": r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone numbers
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
}

# Common patient name patterns (simple heuristic)
PATIENT_NAME_INDICATORS = [
    r'\bpatient\s+name[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b',
    r'\b(Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+\b',
]


def run_canary_scan(
    raw_output: Optional[str],
    parsed_output: Optional[Dict[str, Any]]
) -> OutputRailResult:
    """
    Run PHI/PII canary scan on LLM output (Phase 4.3).
    
    Scans both raw text and findings for PHI patterns.
    This is the "kill-switch" that prevents PHI exfiltration.
    
    Returns OutputRailResult with pass/fail and PHI detection details.
    """
    details = {
        "canary_scan": "executed",
        "patterns_checked": list(PHI_PATTERNS.keys()),
    }
    
    if raw_output is None and parsed_output is None:
        details["canary_scan"] = "skipped_no_output"
        return OutputRailResult(passed=True, phi_detected=False, details=details)
    
    # Combine all text to scan
    text_to_scan = raw_output or ""
    if parsed_output:
        findings = parsed_output.get("findings", [])
        if isinstance(findings, list):
            text_to_scan += " " + " ".join(str(f) for f in findings)
        disclaimer = parsed_output.get("disclaimer", "")
        if disclaimer:
            text_to_scan += " " + str(disclaimer)
    
    detected_phi = []
    
    # Check PHI patterns
    for phi_type, pattern in PHI_PATTERNS.items():
        if re.search(pattern, text_to_scan, re.IGNORECASE):
            detected_phi.append(phi_type)
    
    # Check patient name indicators
    for pattern in PATIENT_NAME_INDICATORS:
        if re.search(pattern, text_to_scan, re.IGNORECASE):
            detected_phi.append("patient_name")
            break
    
    if detected_phi:
        details["phi_types_detected"] = detected_phi
        details["phi_count"] = len(detected_phi)
        return OutputRailResult(
            passed=False,
            reason_code="CANARY_PHI_DETECTED",
            guardrail="PHI Kill-Switch",
            message=f"PHI detected in output: {detected_phi}. Output blocked.",
            phi_detected=True,
            details=details
        )
    
    details["phi_detected"] = False
    return OutputRailResult(passed=True, phi_detected=False, details=details)


# =============================================================================
# Main Entry Point: Run All Output Rails
# =============================================================================

def run_output_rails(
    llm_output: Optional[str],
    parsed_output: Optional[Dict[str, Any]] = None,
    workflow: str = "default_workflow",
    required_keys: Optional[List[str]] = None
) -> OutputRailResult:
    """
    Run all output rails in sequence (Phase 4).
    
    Order:
    1. Schema validation (4.1) - required keys present
    2. Hallucination checks (4.2) - consistency rules  
    3. Canary PHI scan (4.3) - PHI kill-switch
    
    Args:
        llm_output: Raw text output from LLM
        parsed_output: Parsed JSON from LLM (if available)
        workflow: Workflow identifier for context-specific rules
        required_keys: Required output keys (from template)
    
    Returns:
        OutputRailResult with aggregated pass/fail status
    """
    # Default required keys if not provided
    if required_keys is None:
        required_keys = ["risk_score", "findings", "confidence", "disclaimer"]
    
    all_details = {
        "workflow": workflow,
        "rails_executed": [],
    }
    
    # Rail 1: Schema validation (4.1)
    schema_result = check_output_schema(parsed_output, required_keys)
    all_details["rails_executed"].append("schema_validation")
    all_details["schema_validation"] = schema_result.details
    
    if not schema_result.passed:
        all_details["blocked_by"] = "schema_validation"
        return OutputRailResult(
            passed=False,
            reason_code=schema_result.reason_code,
            guardrail=schema_result.guardrail,
            message=schema_result.message,
            details=all_details
        )
    
    # Rail 2: Hallucination checks (4.2)
    hallucination_result = check_hallucinations(parsed_output, workflow)
    all_details["rails_executed"].append("hallucination_check")
    all_details["hallucination_check"] = hallucination_result.details
    
    if not hallucination_result.passed:
        all_details["blocked_by"] = "hallucination_check"
        return OutputRailResult(
            passed=False,
            reason_code=hallucination_result.reason_code,
            guardrail=hallucination_result.guardrail,
            message=hallucination_result.message,
            details=all_details
        )
    
    # Rail 3: Canary PHI scan (4.3)
    canary_result = run_canary_scan(llm_output, parsed_output)
    all_details["rails_executed"].append("canary_scan")
    all_details["canary_scan"] = canary_result.details
    
    if not canary_result.passed:
        all_details["blocked_by"] = "canary_scan"
        return OutputRailResult(
            passed=False,
            reason_code=canary_result.reason_code,
            guardrail=canary_result.guardrail,
            message=canary_result.message,
            phi_detected=True,
            details=all_details
        )
    
    # All rails passed
    all_details["all_rails_passed"] = True
    return OutputRailResult(
        passed=True,
        sanitized_output=llm_output,
        phi_detected=False,
        details=all_details
    )

