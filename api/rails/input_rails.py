"""
Input Rails (Phase 2.3 - NeMo Guardrails Scaffolding)

Pre-LLM checks that run in the INTERCEPTOR phase:
- BAA Enforcement (Phase 1.5)
- Prompt Injection Detection (Phase 1.6)
- Tool Manifest Validation (Phase 2.4)
- Tool/Action Allowlist Enforcement (Phase 2.4)

These rails run BEFORE any LLM call and can block requests deterministically.

See: devlog/gateway_build.md Phase 2.3
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel


# =============================================================================
# Input Rail Result
# =============================================================================

class InputRailResult(BaseModel):
    """Result of running input rails."""
    passed: bool
    reason_code: Optional[str] = None
    guardrail: Optional[str] = None
    message: Optional[str] = None
    http_status: int = 200
    details: Dict[str, Any] = {}


# =============================================================================
# Constants (imported from main at runtime to avoid circular deps)
# =============================================================================

INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all prior",
    "disregard your instructions",
    "forget your instructions",
    "you are now",
    "pretend you are",
    "act as if",
    "bypass",
    "jailbreak",
    "DAN mode",
]

SUSPICIOUS_TOOL_TERMS = ["ignore", "bypass", "override", "important:", "note:"]


# =============================================================================
# Individual Rail Functions
# =============================================================================

def check_baa_enforcement(
    destination: str,
    destinations_registry: Dict[str, Any]
) -> InputRailResult:
    """
    BAA Enforcement Rail (Phase 1.5).
    
    Blocks requests to destinations without a valid BAA.
    """
    destination_info = destinations_registry.get(destination)
    
    if not destination_info:
        return InputRailResult(
            passed=False,
            reason_code="UNKNOWN_DESTINATION",
            guardrail="Endpoint Control",
            message=f"Destination '{destination}' is not in the approved registry.",
            http_status=403,
            details={"destination": destination}
        )
    
    if not destination_info.get("baa_status", False):
        return InputRailResult(
            passed=False,
            reason_code="NO_BAA_DESTINATION",
            guardrail="BAA Enforcement",
            message="Blocked by gateway policy. Destination has no BAA.",
            http_status=403,
            details={"destination": destination, "vendor": destination_info.get("vendor")}
        )
    
    return InputRailResult(
        passed=True,
        details={"destination": destination, "vendor": destination_info.get("vendor")}
    )


def check_prompt_injection(
    prompt: Optional[str],
    tool_manifest_description: Optional[str]
) -> InputRailResult:
    """
    Prompt Injection Detection Rail (Phase 1.6).
    
    Scans prompt and tool manifest description for injection patterns.
    """
    text_to_check = ""
    if prompt:
        text_to_check += prompt.lower()
    if tool_manifest_description:
        text_to_check += " " + tool_manifest_description.lower()
    
    for pattern in INJECTION_PATTERNS:
        if pattern.lower() in text_to_check:
            return InputRailResult(
                passed=False,
                reason_code="INJECTION_DETECTED",
                guardrail="Endpoint Control",
                message="Request blocked. Suspicious instruction pattern detected.",
                http_status=400,
                details={"pattern_detected": True}  # Don't log actual pattern
            )
    
    return InputRailResult(passed=True)


def check_tool_manifest_validity(
    tool_manifest: Optional[Dict[str, Any]]
) -> InputRailResult:
    """
    Tool Manifest Validation Rail (Phase 2.4).
    
    Blocks poisoned tool manifests with suspicious instructions.
    """
    if not tool_manifest:
        return InputRailResult(passed=True)
    
    description = tool_manifest.get("description", "").lower()
    
    for term in SUSPICIOUS_TOOL_TERMS:
        if term in description:
            return InputRailResult(
                passed=False,
                reason_code="TOOL_MANIFEST_INVALID",
                guardrail="Model Integrity Check",
                message="Tool manifest rejected. Contains suspicious instructions.",
                http_status=400,
                details={"tool_name": tool_manifest.get("name")}
            )
    
    return InputRailResult(passed=True)


def check_tool_action_allowlist(
    workflow: str,
    action: str,
    tool_manifest: Optional[Dict[str, Any]],
    workflow_allowlists: Dict[str, Dict[str, Any]]
) -> InputRailResult:
    """
    Tool/Action Allowlist Enforcement Rail (Phase 2.4).
    
    Blocks requests with unapproved actions or tools for the workflow.
    """
    workflow_key = workflow.strip().lower()
    allowlist = workflow_allowlists.get(workflow_key, workflow_allowlists.get("default_workflow", {}))
    
    allowed_actions = allowlist.get("allowed_actions", [])
    allowed_tools = allowlist.get("allowed_tools", [])
    
    # Check action allowlist
    if action not in allowed_actions:
        return InputRailResult(
            passed=False,
            reason_code="TOOL_NOT_ALLOWED",
            guardrail="Endpoint Control",
            message="Blocked by gateway policy. Action not allowlisted.",
            http_status=403,
            details={"action": action, "workflow": workflow_key}
        )
    
    # Check tool allowlist (if tool_manifest is present)
    if tool_manifest:
        tool_name = tool_manifest.get("name", "")
        if tool_name not in allowed_tools:
            return InputRailResult(
                passed=False,
                reason_code="TOOL_NOT_ALLOWED",
                guardrail="Endpoint Control",
                message="Blocked by gateway policy. Tool not allowlisted.",
                http_status=403,
                details={"tool_name": tool_name, "workflow": workflow_key}
            )
    
    return InputRailResult(passed=True)


# =============================================================================
# Main Entry Point
# =============================================================================

def run_input_rails(
    destination: str,
    prompt: Optional[str],
    tool_manifest: Optional[Dict[str, Any]],
    workflow: str,
    action: str,
    destinations_registry: Dict[str, Any],
    workflow_allowlists: Dict[str, Dict[str, Any]]
) -> InputRailResult:
    """
    Run all input rails in sequence.
    
    Returns the first blocking result, or a passing result if all pass.
    
    Rail execution order:
    1. BAA Enforcement
    2. Prompt Injection Detection
    3. Tool Manifest Validation
    4. Tool/Action Allowlist Enforcement
    """
    # Rail 1: BAA Enforcement
    result = check_baa_enforcement(destination, destinations_registry)
    if not result.passed:
        return result
    
    # Rail 2: Prompt Injection
    tool_desc = tool_manifest.get("description") if tool_manifest else None
    result = check_prompt_injection(prompt, tool_desc)
    if not result.passed:
        return result
    
    # Rail 3: Tool Manifest Validation
    result = check_tool_manifest_validity(tool_manifest)
    if not result.passed:
        return result
    
    # Rail 4: Tool/Action Allowlist
    result = check_tool_action_allowlist(workflow, action, tool_manifest, workflow_allowlists)
    if not result.passed:
        return result
    
    # All rails passed
    return InputRailResult(
        passed=True,
        details={"checks_passed": ["baa", "injection", "tool_manifest", "allowlist"]}
    )

