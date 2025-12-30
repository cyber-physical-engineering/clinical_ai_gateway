"""
Sanitizer Module (Phase 5 - Split-Stream Logging)

Implements the dual-stream event model:
- Private Audit Events: May contain PHI (for hospital compliance evidence)
- Public Threat Events: Fully sanitized (for threat intelligence sharing)

The sanitizer ensures PHI NEVER appears in the public stream.

See: devlog/gateway_build.md Phase 5
"""

import hashlib
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Configuration
# =============================================================================

# Salt for hashing (in production, load from env/secrets)
HASH_SALT = "healthsec_demo_salt_2024"

# PHI patterns to redact (same as canary scan)
PHI_PATTERNS = {
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "mrn": r'\b(MRN|mrn)[:\s]*\d{6,10}\b',
    "dob": r'\b(DOB|dob|Date of Birth)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
    "phone": r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "patient_name": r'\b(patient|Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)?\b',
}

# Fields that should be hashed (not redacted) for correlation
HASHABLE_FIELDS = ["patient_id", "study_uid", "correlation_id", "request_id"]

# Fields that should be fully redacted (replaced with [REDACTED])
REDACTABLE_FIELDS = ["prompt", "findings", "raw_text", "user_context"]


# =============================================================================
# Event Models
# =============================================================================

class PrivateAuditEvent(BaseModel):
    """
    Private audit event for hospital compliance evidence.
    
    May contain PHI - stored in secure, retention-locked audit logs.
    Never leaves the hospital's control boundary.
    """
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    request_id: str = Field(..., description="Original request correlation ID")
    
    # Event classification
    event_type: str = Field(..., description="Type: request | decision | response | error")
    phase: str = Field(..., description="Pipeline phase: INTERCEPTOR | POLICY | EXECUTION | OUTPUT")
    status: str = Field(..., description="PASS | BLOCK | WARN | ERROR")
    
    # Decision details (may contain PHI for evidence)
    reason_code: Optional[str] = Field(None, description="Deterministic reason code")
    guardrail: Optional[str] = Field(None, description="Business-facing guardrail name")
    details: Dict[str, Any] = Field(default_factory=dict, description="Full decision details")
    
    # Audit metadata
    retention_days: int = Field(default=2555, description="7 years for HIPAA")
    audit_hash: str = Field(..., description="SHA256 hash for tamper detection")
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "priv_20241227_abc123",
                "timestamp": "2024-12-27T10:30:00Z",
                "request_id": "req_abc123def456",
                "event_type": "decision",
                "phase": "OUTPUT",
                "status": "BLOCK",
                "reason_code": "CANARY_PHI_DETECTED",
                "guardrail": "PHI Kill-Switch",
                "details": {"phi_types": ["ssn", "mrn"], "patient_id": "PT-12345"},
                "retention_days": 2555,
                "audit_hash": "sha256:abcdef..."
            }
        }


class PublicThreatEvent(BaseModel):
    """
    Public threat intelligence event (fully sanitized).
    
    NEVER contains PHI - safe to share with HealthSec Threat Cloud
    or aggregate for industry threat intelligence.
    
    All identifiers are hashed, all text is redacted.
    """
    event_id: str = Field(..., description="Unique event identifier (different from private)")
    timestamp: str = Field(..., description="Coarse timestamp (hour-level)")
    
    # Anonymized request reference
    request_hash: str = Field(..., description="Hashed request ID for correlation")
    
    # Threat classification
    threat_type: str = Field(..., description="Category: injection | exfiltration | policy_violation | phi_leak")
    reason_code: str = Field(..., description="Deterministic reason code")
    guardrail: str = Field(..., description="Guardrail that triggered")
    
    # Sanitized metadata (no PHI)
    pattern_hash: Optional[str] = Field(None, description="Hash of detected pattern")
    severity: str = Field(default="MEDIUM", description="LOW | MEDIUM | HIGH | CRITICAL")
    
    # Coarse metadata only
    workflow_category: Optional[str] = Field(None, description="Category only: radiology | cardiology | general")
    destination_type: Optional[str] = Field(None, description="Type only: cloud | local | unknown")
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "pub_20241227_xyz789",
                "timestamp": "2024-12-27T10:00:00Z",
                "request_hash": "sha256:fedcba...",
                "threat_type": "phi_leak",
                "reason_code": "CANARY_PHI_DETECTED",
                "guardrail": "PHI Kill-Switch",
                "pattern_hash": "sha256:112233...",
                "severity": "CRITICAL",
                "workflow_category": "radiology",
                "destination_type": "cloud"
            }
        }


# =============================================================================
# Sanitization Functions
# =============================================================================

def hash_value(value: str, salt: str = HASH_SALT) -> str:
    """
    Create a deterministic hash of a value for correlation.
    
    Uses SHA256 with salt. Full 64-character hash for demo display.
    """
    salted = f"{salt}:{value}"
    return f"sha256:{hashlib.sha256(salted.encode()).hexdigest()}"


def redact_phi(text: str) -> str:
    """
    Redact all PHI patterns from text.
    
    Replaces matches with [REDACTED:type] placeholders.
    """
    if not text:
        return text
    
    result = text
    for phi_type, pattern in PHI_PATTERNS.items():
        result = re.sub(pattern, f"[REDACTED:{phi_type}]", result, flags=re.IGNORECASE)
    
    return result


def sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize a details dict for public consumption.
    
    - Hashes hashable fields (IDs)
    - Redacts redactable fields (text content)
    - Removes any remaining PHI patterns
    """
    sanitized = {}
    
    for key, value in details.items():
        if key in HASHABLE_FIELDS and isinstance(value, str):
            sanitized[f"{key}_hash"] = hash_value(value)
        elif key in REDACTABLE_FIELDS:
            if isinstance(value, str):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, list):
                sanitized[key] = f"[{len(value)} items redacted]"
            else:
                sanitized[key] = "[REDACTED]"
        elif isinstance(value, str):
            # Check for PHI in any string value
            sanitized[key] = redact_phi(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_details(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_details(item) if isinstance(item, dict)
                else redact_phi(str(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitized[key] = value
    
    return sanitized


def get_threat_type(reason_code: str) -> str:
    """Map reason codes to threat categories."""
    threat_map = {
        "INJECTION_DETECTED": "injection",
        "TOOL_MANIFEST_INVALID": "injection",
        "CANARY_PHI_DETECTED": "phi_leak",
        "INVALID_MODEL_OUTPUT": "model_failure",
        "HALLUCINATION_DETECTED": "model_failure",
        "OUT_OF_SCOPE_OUTPUT": "model_failure",
        "NO_BAA_DESTINATION": "policy_violation",
        "POLICY_DENY": "policy_violation",
        "TOOL_NOT_ALLOWED": "policy_violation",
    }
    return threat_map.get(reason_code, "unknown")


def get_severity(reason_code: str) -> str:
    """Map reason codes to severity levels."""
    severity_map = {
        "CANARY_PHI_DETECTED": "CRITICAL",
        "INJECTION_DETECTED": "HIGH",
        "TOOL_MANIFEST_INVALID": "HIGH",
        "NO_BAA_DESTINATION": "HIGH",
        "HALLUCINATION_DETECTED": "MEDIUM",
        "OUT_OF_SCOPE_OUTPUT": "MEDIUM",
        "INVALID_MODEL_OUTPUT": "MEDIUM",
        "POLICY_DENY": "MEDIUM",
        "TOOL_NOT_ALLOWED": "LOW",
    }
    return severity_map.get(reason_code, "MEDIUM")


def coarsen_timestamp(iso_timestamp: str) -> str:
    """
    Coarsen timestamp to hour-level for privacy.
    
    "2024-12-27T10:35:42Z" -> "2024-12-27T10:00:00Z"
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.replace(minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return iso_timestamp


def extract_workflow_category(workflow: str) -> str:
    """Extract category from workflow name (no specific identifiers)."""
    workflow_lower = workflow.lower()
    if "radiology" in workflow_lower:
        return "radiology"
    elif "cardio" in workflow_lower:
        return "cardiology"
    elif "path" in workflow_lower:
        return "pathology"
    else:
        return "general"


def extract_destination_type(destination: str) -> str:
    """Extract destination type (no vendor names)."""
    dest_lower = destination.lower()
    if "vertex" in dest_lower or "bedrock" in dest_lower or "azure" in dest_lower:
        return "cloud_provider"
    elif "ollama" in dest_lower or "local" in dest_lower:
        return "local"
    elif "huggingface" in dest_lower:
        return "public_hub"
    else:
        return "unknown"


# =============================================================================
# Main Split-Stream Function
# =============================================================================

def create_audit_hash(event_data: Dict[str, Any]) -> str:
    """Create tamper-detection hash for audit event."""
    import json
    canonical = json.dumps(event_data, sort_keys=True)
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def split_stream_event(
    request_id: str,
    timestamp: str,
    phase: str,
    status: str,
    reason_code: Optional[str] = None,
    guardrail: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    workflow: Optional[str] = None,
    destination: Optional[str] = None,
) -> tuple[PrivateAuditEvent, Optional[PublicThreatEvent]]:
    """
    Create both private and public event streams from a single event.
    
    Returns:
        Tuple of (PrivateAuditEvent, PublicThreatEvent or None)
        PublicThreatEvent is only created for BLOCK/WARN events (threat intel).
    """
    details = details or {}
    
    # Generate event IDs
    event_suffix = hashlib.sha256(f"{request_id}:{timestamp}".encode()).hexdigest()[:8]
    private_id = f"priv_{datetime.utcnow().strftime('%Y%m%d')}_{event_suffix}"
    
    # Create private audit event (full details preserved)
    private_event_data = {
        "event_id": private_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "event_type": "decision",
        "phase": phase,
        "status": status,
        "reason_code": reason_code,
        "guardrail": guardrail,
        "details": details,
    }
    
    private_event = PrivateAuditEvent(
        **private_event_data,
        retention_days=2555,  # 7 years for HIPAA
        audit_hash=create_audit_hash(private_event_data)
    )
    
    # Only create public threat event for blocks/warnings
    public_event = None
    if status in ["BLOCK", "WARN"] and reason_code:
        public_id = f"pub_{datetime.utcnow().strftime('%Y%m%d')}_{event_suffix}"
        
        public_event = PublicThreatEvent(
            event_id=public_id,
            timestamp=coarsen_timestamp(timestamp),
            request_hash=hash_value(request_id),
            threat_type=get_threat_type(reason_code),
            reason_code=reason_code,
            guardrail=guardrail or "Unknown",
            pattern_hash=hash_value(str(details)) if details else None,
            severity=get_severity(reason_code),
            workflow_category=extract_workflow_category(workflow) if workflow else None,
            destination_type=extract_destination_type(destination) if destination else None,
        )
    
    return private_event, public_event


# =============================================================================
# Convenience Functions
# =============================================================================

def verify_no_phi_in_public(public_event: PublicThreatEvent) -> bool:
    """
    Verify that a public event contains no PHI.
    
    Returns True if clean, False if PHI detected (should never happen).
    """
    # Convert to string and check all PHI patterns
    event_str = public_event.model_dump_json()
    
    for phi_type, pattern in PHI_PATTERNS.items():
        if re.search(pattern, event_str, re.IGNORECASE):
            return False
    
    return True

