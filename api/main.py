"""
Clinical AI Gateway - Phase 0 (Bootstrap)

This is the core "Choke Chain" gateway that enforces guardrails on all AI requests.
It provides real-time event streaming to the Inspector UI via SSE.

Source of truth: devlog/gateway_build.md, mermaid/ai_gateway.mmd
Contract: devlog/gateway_demo_contract.md
"""

import asyncio
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, List, Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Rails module (Phase 2.3 - NeMo Guardrails Scaffolding + Phase 5 Split-Stream)
from rails import (
    run_input_rails,
    run_dialog_rails,
    run_output_rails,
    InputRailResult,
    # Phase 5: Split-Stream Logging
    split_stream_event,
    PrivateAuditEvent,
    PublicThreatEvent,
    verify_no_phi_in_public,
    hash_value,  # SHA-256 hashing for identifiers
)

# Providers module (Phase 3 - LLM Provider Abstraction)
from providers import (
    get_provider,
    get_prompt_manager,
    check_provider_health,
    LLMResponse,
    ProviderType,
)

# =============================================================================
# Event Schema (Phase 0.2) - Shared by all phases
# =============================================================================

class GatewayEvent(BaseModel):
    """
    Core event record for the Inspector timeline.
    Every phase emits events in this format.
    
    Maps to: gateway_build.md Phase 0.2
    """
    request_id: str = Field(..., description="Correlation ID for the request")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    phase: str = Field(..., description="Pipeline phase: RECEIVED | INTERCEPTOR | POLICY | EXECUTION | OUTPUT | SANITIZER | RESPONDED")
    status: str = Field(..., description="PASS | BLOCK | WARN")
    reason_code: Optional[str] = Field(None, description="Deterministic reason code (e.g., NO_BAA_DESTINATION)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Phase-specific details (redacted, no PHI)")
    guardrail: Optional[str] = Field(None, description="Business-facing guardrail label for UI")


class LiveEvent(BaseModel):
    """
    Demo UI-facing event format (from gateway_demo_contract.md).
    GatewayEvents are converted to this shape for the Live Feed.
    """
    id: str
    timestamp: str
    type: str  # allowed | blocked | flagged
    message: str
    details: str
    source: str = "AI Gateway"
    guardrail: Optional[str] = None
    reason_code: Optional[str] = None
    request_id: str


# =============================================================================
# Request/Response Models (from gateway_demo_contract.md)
# =============================================================================

class UserInfo(BaseModel):
    name: str
    role: str


class ToolManifest(BaseModel):
    name: str
    version: str
    description: str
    schema_version: str


class AnalyzeRequest(BaseModel):
    """
    Minimal request schema for demo compatibility.
    Future: add study_uid, dicom_ref, workflow, data_level per gateway_build.md Phase 1.
    """
    patient_id: str
    modality: str
    action: str
    destination: str = "vertex_gemini"
    user: Optional[UserInfo] = None
    correlation_id: Optional[str] = None
    prompt: Optional[str] = None  # For injection detection testing
    tool_manifest: Optional[ToolManifest] = None  # For tool validation testing
    workflow: Optional[str] = None  # e.g., "radiology_summary_v1"
    data_level: Optional[str] = None  # PHI | DE_ID | PUBLIC


class AnalyzeResponse(BaseModel):
    status: str  # ALLOWED | BLOCKED | FLAGGED
    risk: str  # LOW | MEDIUM | HIGH
    message: str
    policy: str
    findings: Optional[List[str]] = None
    request_id: str


class ErrorResponse(BaseModel):
    status: str = "BLOCKED"
    message: str
    reason_code: str
    guardrail: str
    request_id: str


# =============================================================================
# Policy Engine Models (Phase 2.1)
# =============================================================================

class PolicyInput(BaseModel):
    """
    Policy evaluation input object (Phase 2.1).
    
    This object is built from the AnalyzeRequest and passed to the policy engine.
    It contains all the context needed to make allow/deny decisions.
    
    Maps to: gateway_build.md Phase 2.1
    """
    user_role: str = Field(..., description="User's role (e.g., 'radiologist', 'guest', 'admin')")
    workflow: str = Field(..., description="Workflow identifier (e.g., 'radiology_summary_v1')")
    action: str = Field(..., description="Action being performed (e.g., 'Analyze Study')")
    data_level: str = Field(..., description="Data sensitivity level: PHI | DE_ID | PUBLIC")
    destination: str = Field(..., description="Target destination/model")
    destination_vendor: str = Field(..., description="Destination vendor name")
    destination_baa: bool = Field(..., description="Whether destination has BAA")
    threat_signals: Dict[str, Any] = Field(default_factory=dict, description="Detected threat indicators")
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_role": "radiologist",
                "workflow": "radiology_summary_v1",
                "action": "Analyze Study",
                "data_level": "PHI",
                "destination": "vertex_gemini",
                "destination_vendor": "Google",
                "destination_baa": True,
                "threat_signals": {
                    "injection_detected": False,
                    "tool_manifest_suspicious": False
                }
            }
        }


class PolicyDecision(BaseModel):
    """
    Policy evaluation result (Phase 2.1).
    
    The policy engine returns this decision object with deterministic reasoning.
    """
    decision: str = Field(..., description="ALLOW | DENY")
    reason_code: Optional[str] = Field(None, description="Deterministic reason code (e.g., 'POLICY_DENY')")
    guardrail: Optional[str] = Field(None, description="Business-facing guardrail label for UI")
    message: str = Field(..., description="Human-readable decision message")
    policy_version: str = Field(..., description="Policy bundle version used")
    policy_id: Optional[str] = Field(None, description="Policy rule id that produced this decision (if any)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Decision details for audit")


# =============================================================================
# Policy Bundle Loading + Evaluation (Phase 2.2 - Mock OPA, OPA-shaped)
# =============================================================================

GATEWAY_ROOT = Path(__file__).resolve().parents[1]  # gateway/
POLICY_DIR = GATEWAY_ROOT / "policy"
DEFAULT_POLICY_BUNDLE_FILE = "policy_bundle_v0_1_0.json"
POLICY_ENGINE_NAME = "mock_opa_inprocess"


def get_policy_bundle_path() -> Path:
    """
    Resolve the active policy bundle path.
    Configure with env var: GATEWAY_POLICY_BUNDLE_FILE
    """
    bundle_file = os.getenv("GATEWAY_POLICY_BUNDLE_FILE", DEFAULT_POLICY_BUNDLE_FILE)
    return POLICY_DIR / bundle_file


def load_policy_bundle() -> Dict[str, Any]:
    """
    Load the policy bundle from disk (OPA-shaped JSON).
    Phase 2.2: In-process evaluator loads a versioned bundle file.
    """
    bundle_path = get_policy_bundle_path()
    if not bundle_path.exists():
        raise RuntimeError(f"Policy bundle not found at {bundle_path}")

    with bundle_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    # Minimal validation
    if "version" not in bundle or "rules" not in bundle or "defaults" not in bundle:
        raise RuntimeError(f"Invalid policy bundle schema in {bundle_path}")

    return bundle


def _normalize_policy_value(field: str, value: Any) -> Any:
    """Normalize values for matching (keeps evaluation deterministic)."""
    if value is None:
        return None
    if field in ("user_role", "workflow"):
        return str(value).strip().lower()
    if field == "data_level":
        return str(value).strip().upper()
    return value


def _rule_matches(match_obj: Dict[str, Any], normalized_input: Dict[str, Any]) -> bool:
    """Return True if all match conditions are satisfied."""
    for field, allowed in (match_obj or {}).items():
        actual = normalized_input.get(field)
        if isinstance(allowed, list):
            allowed_norm = [_normalize_policy_value(field, x) for x in allowed]
            if _normalize_policy_value(field, actual) not in allowed_norm:
                return False
        else:
            if _normalize_policy_value(field, actual) != _normalize_policy_value(field, allowed):
                return False
    return True


def evaluate_policy(policy_input: PolicyInput) -> PolicyDecision:
    """
    Evaluate policy decisions in-process (Phase 2.2).
    OPA-shaped: reads a versioned bundle on disk and evaluates deterministic match rules.
    """
    bundle = load_policy_bundle()
    bundle_path = get_policy_bundle_path()

    normalized_input: Dict[str, Any] = {
        "user_role": _normalize_policy_value("user_role", policy_input.user_role),
        "workflow": _normalize_policy_value("workflow", policy_input.workflow),
        "action": policy_input.action,
        "data_level": _normalize_policy_value("data_level", policy_input.data_level),
        "destination": policy_input.destination,
        "destination_vendor": policy_input.destination_vendor,
        "destination_baa": policy_input.destination_baa,
        "threat_signals": policy_input.threat_signals,
    }

    for rule in bundle.get("rules", []):
        if _rule_matches(rule.get("match", {}), normalized_input):
            decision = str(rule.get("effect", "DENY")).upper()
            reason_code = rule.get("reason_code") or ("POLICY_DENY" if decision == "DENY" else "POLICY_ALLOW")
            guardrail = rule.get("guardrail")
            message = rule.get("message") or "Policy decision applied."
            policy_id = rule.get("id")

            return PolicyDecision(
                decision=decision,
                reason_code=reason_code,
                guardrail=guardrail,
                message=message,
                policy_version=bundle.get("version", "unknown"),
                policy_id=policy_id,
                details={
                    "matched_rule": policy_id,
                    "bundle_path": str(bundle_path),
                    "bundle_type": bundle.get("bundle_type", "unknown"),
                },
            )

    defaults = bundle.get("defaults", {})
    return PolicyDecision(
        decision=str(defaults.get("decision", "ALLOW")).upper(),
        reason_code=defaults.get("reason_code", "POLICY_ALLOW"),
        guardrail=defaults.get("guardrail", "FDA Audit Trail"),
        message=defaults.get("message", "Allowed by default policy."),
        policy_version=bundle.get("version", "unknown"),
        policy_id=None,
        details={
            "matched_rule": None,
            "bundle_path": str(bundle_path),
            "bundle_type": bundle.get("bundle_type", "unknown"),
        },
    )


# =============================================================================
# In-Memory Event Store (Phase 0 + Phase 5 Split-Stream)
# =============================================================================

class EventStore:
    """
    In-memory event store with SSE broadcast capability.
    
    Phase 5: Added split-stream storage for private/public events.
    - Private events: Full audit trail (may contain PHI)
    - Public events: Sanitized threat intel (never contains PHI)
    """
    
    def __init__(self, max_events: int = 100):
        self.events: List[GatewayEvent] = []
        self.live_events: List[LiveEvent] = []
        # Phase 5: Split-stream storage
        self.private_events: List[PrivateAuditEvent] = []
        self.public_events: List[PublicThreatEvent] = []
        self.max_events = max_events
        self._subscribers: List[asyncio.Queue] = []
    
    def add_event(self, event: GatewayEvent) -> None:
        """Add a gateway event and notify subscribers."""
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        
        # Broadcast to SSE subscribers
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # Drop event if subscriber is slow
    
    def add_live_event(self, event: LiveEvent) -> None:
        """Add a demo UI-compatible live event."""
        self.live_events.append(event)
        if len(self.live_events) > self.max_events:
            self.live_events.pop(0)
    
    def add_private_event(self, event: PrivateAuditEvent) -> None:
        """Add a private audit event (Phase 5)."""
        self.private_events.append(event)
        if len(self.private_events) > self.max_events:
            self.private_events.pop(0)
    
    def add_public_event(self, event: PublicThreatEvent) -> None:
        """Add a public threat event (Phase 5)."""
        self.public_events.append(event)
        if len(self.public_events) > self.max_events:
            self.public_events.pop(0)
    
    def get_live_events(self) -> List[LiveEvent]:
        """Get all live events, newest first."""
        return list(reversed(self.live_events))
    
    def get_private_events(self) -> List[PrivateAuditEvent]:
        """Get private audit events, newest first (Phase 5)."""
        return list(reversed(self.private_events))
    
    def get_public_events(self) -> List[PublicThreatEvent]:
        """Get public threat events, newest first (Phase 5)."""
        return list(reversed(self.public_events))
    
    def subscribe(self) -> asyncio.Queue:
        """Subscribe to real-time event stream."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=50)
        self._subscribers.append(queue)
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Unsubscribe from event stream."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)


# Global event store
event_store = EventStore()


# =============================================================================
# Destination Registry (Phase 1.5 - BAA Enforcement)
# =============================================================================

# Simple in-memory destination registry (will be YAML/JSON file later)
DESTINATIONS = {
    "vertex_gemini": {
        "vendor": "Google",
        "baa_status": True,
        "allowed_data_levels": ["PHI", "DE_ID", "PUBLIC"],
        "notes": "Covered under GCP BAA"
    },
    "vertex_medlm": {
        "vendor": "Google",
        "baa_status": True,
        "allowed_data_levels": ["PHI", "DE_ID", "PUBLIC"],
        "notes": "MedLM covered under GCP BAA"
    },
    "public_huggingface": {
        "vendor": "HuggingFace",
        "baa_status": False,
        "allowed_data_levels": ["PUBLIC"],
        "notes": "No BAA - public models only"
    },
    "local_ollama": {
        "vendor": "Self-hosted",
        "baa_status": True,  # Local = no exfiltration
        "allowed_data_levels": ["PHI", "DE_ID", "PUBLIC"],
        "notes": "On-premise, no external transmission"
    }
}

# Injection patterns (Phase 1.6)
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


# =============================================================================
# Tool/Action Allowlisting (Phase 2.4 - "LLM says, app decides")
# =============================================================================

# Deterministic allowlists per workflow.
# Later phases can move these to versioned files alongside policy bundles.
WORKFLOW_ALLOWLISTS: Dict[str, Dict[str, Any]] = {
    "radiology_summary_v1": {
        "allowed_actions": [
            "Analyze Study",
        ],
        "allowed_tools": [
            # Keep tight by default; add as needed for demos/workflows.
            "radiology_measurement_tool",
            "clinical_reference_lookup",
        ],
    },
    "default_workflow": {
        "allowed_actions": ["Analyze Study"],
        "allowed_tools": [],
    },
}


# =============================================================================
# Application Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    # Startup: seed some demo events
    seed_demo_events()
    yield
    # Shutdown: cleanup if needed


def seed_demo_events():
    """Seed initial demo events for the Live Feed."""
    demo_events = [
        LiveEvent(
            id="evt_seed_001",
            timestamp="10:42:15",
            type="allowed",
            message="ALLOWED: Chest CT Analysis",
            details="Clinical consistency check passed. Model confidence 98.4%.",
            guardrail="FDA Audit Trail",
            reason_code="POLICY_ALLOW",
            request_id="req_seed_001"
        ),
        LiveEvent(
            id="evt_seed_002",
            timestamp="10:45:30",
            type="allowed",
            message="ALLOWED: Draft Report",
            details="Standard template usage. No anomalies detected.",
            guardrail="Model Integrity Check",
            reason_code="POLICY_ALLOW",
            request_id="req_seed_002"
        ),
        LiveEvent(
            id="evt_seed_003",
            timestamp="10:48:12",
            type="blocked",
            message="BLOCKED: PHI Leak Prevention (No BAA)",
            details="Attempted route to huggingface.co blocked. Destination has no BAA.",
            guardrail="BAA Enforcement",
            reason_code="NO_BAA_DESTINATION",
            request_id="req_seed_003"
        ),
    ]
    for evt in demo_events:
        event_store.add_live_event(evt)


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Clinical AI Gateway",
    description="The 'Choke Chain' - Deterministic guardrails for clinical AI",
    version="0.1.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permissive for local dev; tighten in production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health & Status Endpoints
# =============================================================================

@app.get("/healthz")
async def health_check():
    """Health check endpoint (Phase 0.1)."""
    return {
        "status": "ok",
        "service": "clinical-ai-gateway",
        "version": "0.1.0",
        "phase": "3 - Safe Execution"
    }


@app.get("/v1/provider/status")
async def provider_status():
    """
    Get current LLM provider status (Phase 3.2).
    
    Returns provider type, model, and health status.
    """
    status = await check_provider_health()
    prompt_manager = get_prompt_manager()
    templates = prompt_manager.list_templates()
    
    return {
        "provider": status["provider"],
        "model": status["model"],
        "healthy": status["healthy"],
        "available_templates": templates,
        "config": {
            "env_var": "GATEWAY_LLM_PROVIDER",
            "current_value": status["provider"],
            "options": ["mock", "ollama", "vertex"],
        }
    }


@app.get("/")
async def root():
    """Root endpoint - service info."""
    return {
        "status": "ok",
        "service": "clinical-ai-gateway",
        "version": "0.1.0",
        "endpoints": {
            "health": "/healthz",
            "events": "/events",
            "analyze": "/v1/analyze",
            "inspect_stream": "/v1/inspect/stream"
        }
    }


# =============================================================================
# Live Feed Endpoints (Demo UI Compatibility)
# =============================================================================

@app.get("/events")
async def get_events() -> List[LiveEvent]:
    """
    Get recent events for the Live Feed (gateway_demo_contract.md).
    Returns newest first.
    """
    return event_store.get_live_events()


# =============================================================================
# Split-Stream Logging Endpoints (Phase 5)
# =============================================================================

@app.get("/v1/audit/private")
async def get_private_audit_events() -> List[Dict[str, Any]]:
    """
    Get private audit events (Phase 5).
    
    These events contain full details for compliance evidence.
    In production, this endpoint would require elevated permissions.
    
    NOTE: May contain PHI - for hospital audit use only.
    """
    return [e.model_dump() for e in event_store.get_private_events()]


@app.get("/v1/audit/public")
async def get_public_threat_events() -> List[Dict[str, Any]]:
    """
    Get public threat intelligence events (Phase 5).
    
    These events are fully sanitized and safe to share.
    All identifiers are hashed, all PHI is redacted.
    
    NOTE: Never contains PHI - safe for threat intel sharing.
    """
    return [e.model_dump() for e in event_store.get_public_events()]


@app.get("/v1/audit/stats")
async def get_audit_stats() -> Dict[str, Any]:
    """
    Get split-stream audit statistics (Phase 5).
    
    Shows counts and breakdown of private vs public events.
    """
    private_events = event_store.get_private_events()
    public_events = event_store.get_public_events()
    
    # Count by threat type in public stream
    threat_breakdown = {}
    for event in public_events:
        threat_type = event.threat_type
        threat_breakdown[threat_type] = threat_breakdown.get(threat_type, 0) + 1
    
    # Count by severity
    severity_breakdown = {}
    for event in public_events:
        severity = event.severity
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
    
    return {
        "private_event_count": len(private_events),
        "public_event_count": len(public_events),
        "threat_breakdown": threat_breakdown,
        "severity_breakdown": severity_breakdown,
        "phi_in_private": True,  # By design
        "phi_in_public": False,  # Verified by sanitizer
    }


# =============================================================================
# Inspector SSE Stream (Phase 0.2)
# =============================================================================

async def event_generator(queue: asyncio.Queue) -> AsyncGenerator[str, None]:
    """Generate SSE events from the subscription queue."""
    try:
        while True:
            try:
                # Wait for events with timeout to send keepalives
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {event.model_dump_json()}\n\n"
            except asyncio.TimeoutError:
                # Send keepalive comment
                yield ": keepalive\n\n"
    except asyncio.CancelledError:
        pass


@app.get("/v1/inspect/stream")
async def inspect_stream(request: Request):
    """
    SSE endpoint for real-time Inspector events (Phase 0.2).
    
    The Inspector UI connects here to see each phase decision in real-time.
    
    Decision: Using SSE over WebSocket for Phase 0 because:
    - Simpler implementation (unidirectional)
    - Native browser EventSource support
    - Sufficient for read-only event display
    - Can upgrade to WebSocket in Phase 2 if bidirectional control needed
    
    See: devlog/gateway_build.md for rationale.
    """
    queue = event_store.subscribe()
    
    async def cleanup():
        event_store.unsubscribe(queue)
    
    # Register cleanup on disconnect
    request.state.cleanup = cleanup
    
    return StreamingResponse(
        event_generator(queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


# =============================================================================
# Analyze Endpoint (Phase 0.1 + Phase 1 Guardrails)
# =============================================================================

def generate_request_id() -> str:
    """Generate a unique request ID."""
    return f"req_{uuid.uuid4().hex[:12]}"


def emit_gateway_event(
    request_id: str,
    phase: str,
    status: str,
    reason_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    guardrail: Optional[str] = None,
    workflow: Optional[str] = None,
    destination: Optional[str] = None,
) -> GatewayEvent:
    """
    Helper to emit a gateway event.
    
    Phase 5: Also emits split-stream events (private + public) for audit.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    event = GatewayEvent(
        request_id=request_id,
        timestamp=timestamp,
        phase=phase,
        status=status,
        reason_code=reason_code,
        details=details or {},
        guardrail=guardrail
    )
    event_store.add_event(event)
    
    # Phase 5: Emit split-stream events for audit
    private_event, public_event = split_stream_event(
        request_id=request_id,
        timestamp=timestamp,
        phase=phase,
        status=status,
        reason_code=reason_code,
        guardrail=guardrail,
        details=details,
        workflow=workflow,
        destination=destination,
    )
    
    event_store.add_private_event(private_event)
    if public_event:
        # Verify no PHI leaked into public event
        if verify_no_phi_in_public(public_event):
            event_store.add_public_event(public_event)
        else:
            # This should never happen - log a critical error
            import logging
            logging.critical(f"PHI detected in public event! Blocking: {public_event.event_id}")
    
    return event


def emit_live_event(
    request_id: str,
    event_type: str,
    message: str,
    details: str,
    guardrail: Optional[str] = None,
    reason_code: Optional[str] = None
) -> LiveEvent:
    """Helper to emit a demo UI-compatible live event."""
    event = LiveEvent(
        id=f"evt_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:4]}",
        timestamp=datetime.now().strftime("%H:%M:%S"),
        type=event_type,
        message=message,
        details=details,
        guardrail=guardrail,
        reason_code=reason_code,
        request_id=request_id
    )
    event_store.add_live_event(event)
    return event


def check_injection(prompt: Optional[str], tool_manifest: Optional[ToolManifest]) -> Optional[str]:
    """
    Check for prompt injection patterns (Phase 1.6).
    Returns the detected pattern if found, None otherwise.
    """
    text_to_check = ""
    if prompt:
        text_to_check += prompt.lower()
    if tool_manifest and tool_manifest.description:
        text_to_check += " " + tool_manifest.description.lower()
    
    for pattern in INJECTION_PATTERNS:
        if pattern.lower() in text_to_check:
            return pattern
    return None


def normalize_workflow(workflow: Optional[str]) -> str:
    return (workflow or "default_workflow").strip().lower()


def normalize_action(action: str) -> str:
    # Keep case as provided, but normalize whitespace deterministically.
    return " ".join(action.strip().split())


def normalize_tool_name(tool_name: str) -> str:
    return tool_name.strip().lower()


def is_action_allowed(workflow: str, action: str) -> bool:
    wl = WORKFLOW_ALLOWLISTS.get(workflow, WORKFLOW_ALLOWLISTS["default_workflow"])
    allowed_actions = [normalize_action(a) for a in wl.get("allowed_actions", [])]
    return normalize_action(action) in allowed_actions


def is_tool_allowed(workflow: str, tool_name: str) -> bool:
    wl = WORKFLOW_ALLOWLISTS.get(workflow, WORKFLOW_ALLOWLISTS["default_workflow"])
    allowed_tools = [normalize_tool_name(t) for t in wl.get("allowed_tools", [])]
    return normalize_tool_name(tool_name) in allowed_tools


def classify_data_level(request: AnalyzeRequest) -> str:
    """
    Classify the data sensitivity level (Phase 2.1).
    
    For Phase 0/1: Simple classification based on patient_id presence.
    For Phase 2+: Will use DICOM header analysis and PHI detection.
    
    Returns: PHI | DE_ID | PUBLIC
    """
    # If explicitly provided, use it
    if request.data_level:
        return request.data_level.upper()
    
    # Otherwise, classify based on patient_id
    # Real patient IDs suggest PHI
    if request.patient_id and not request.patient_id.startswith("TEST-"):
        return "PHI"
    
    # Test patient IDs are de-identified
    if request.patient_id and request.patient_id.startswith("TEST-"):
        return "DE_ID"
    
    # Default to PHI to be safe
    return "PHI"


def build_policy_input(
    request: AnalyzeRequest,
    destination_info: Dict[str, Any],
    threat_signals: Dict[str, Any]
) -> PolicyInput:
    """
    Build the policy input object from the request (Phase 2.1).
    
    This is the core data structure passed to the policy engine.
    All policy decisions are based on this input.
    """
    return PolicyInput(
        user_role=(request.user.role if request.user else "guest").strip().lower(),
        workflow=normalize_workflow(request.workflow),
        action=normalize_action(request.action),
        data_level=classify_data_level(request),
        destination=request.destination,
        destination_vendor=destination_info["vendor"],
        destination_baa=destination_info["baa_status"],
        threat_signals=threat_signals
    )


@app.post("/v1/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Main gateway analysis endpoint (Phase 0.1 + Phase 1 guardrails).
    
    Pipeline phases:
    1. RECEIVED - Request accepted
    2. INTERCEPTOR - Input validation (BAA, injection, tool manifest)
    3. POLICY - Policy evaluation (mock for Phase 0)
    4. EXECUTION - LLM call (mock for Phase 0)
    5. OUTPUT - Output validation (mock for Phase 0)
    6. RESPONDED - Final response
    """
    request_id = request.correlation_id or generate_request_id()
    
    # Phase: RECEIVED
    emit_gateway_event(
        request_id=request_id,
        phase="RECEIVED",
        status="PASS",
        details={
            "patient_id_hash": hash_value(request.patient_id),  # SHA-256 hash, never log real patient ID
            "modality": request.modality,
            "destination": request.destination
        }
    )
    
    # Phase: INTERCEPTOR - Input Guardrails (Phase 2.3: Using Rails Module)
    
    # Normalize workflow/action once (used by allowlisting + policy input)
    workflow = normalize_workflow(request.workflow)
    action = normalize_action(request.action)
    
    # Prepare tool_manifest dict for rails (or None)
    tool_manifest_dict = request.tool_manifest.model_dump() if request.tool_manifest else None
    
    # Run input rails (Phase 2.3 - NeMo-compatible structure)
    input_rail_result: InputRailResult = run_input_rails(
        destination=request.destination,
        prompt=request.prompt,
        tool_manifest=tool_manifest_dict,
        workflow=workflow,
        action=action,
        destinations_registry=DESTINATIONS,
        workflow_allowlists=WORKFLOW_ALLOWLISTS
    )
    
    # Get destination_info for later use (needed for policy input)
    destination_info = DESTINATIONS.get(request.destination)
    
    # Handle rail block
    if not input_rail_result.passed:
        # Emit INTERCEPTOR block event
        emit_gateway_event(
            request_id=request_id,
            phase="INTERCEPTOR",
            status="BLOCK",
            reason_code=input_rail_result.reason_code,
            guardrail=input_rail_result.guardrail,
            details=input_rail_result.details
        )
        
        # Generate appropriate UI message based on reason code
        reason_code = input_rail_result.reason_code
        if reason_code == "UNKNOWN_DESTINATION":
            ui_message = "BLOCKED: Unknown Destination"
            ui_details = f"Destination '{request.destination}' is not in the approved registry."
        elif reason_code == "NO_BAA_DESTINATION":
            ui_message = "BLOCKED: PHI Leak Prevention (No BAA)"
            vendor = input_rail_result.details.get("vendor", "unknown")
            ui_details = f"Attempted route to {vendor} blocked. Destination has no BAA."
        elif reason_code == "INJECTION_DETECTED":
            ui_message = "BLOCKED: Prompt Injection Detected"
            ui_details = "Suspicious instruction pattern detected in request."
        elif reason_code == "TOOL_MANIFEST_INVALID":
            ui_message = "BLOCKED: Tool Definition Rejected"
            tool_name = input_rail_result.details.get("tool_name", "unknown")
            ui_details = f"Tool manifest '{tool_name}' contains suspicious instructions."
        elif reason_code == "TOOL_NOT_ALLOWED":
            ui_message = "BLOCKED: Unapproved Action"
            if "tool_name" in input_rail_result.details:
                ui_details = f"Tool '{input_rail_result.details['tool_name']}' is not allowlisted for workflow '{workflow}'."
            else:
                ui_details = f"Action '{action}' is not allowlisted for workflow '{workflow}'."
        else:
            ui_message = f"BLOCKED: {reason_code}"
            ui_details = input_rail_result.message or "Request blocked by input guardrails."
        
        emit_live_event(
            request_id=request_id,
            event_type="blocked",
            message=ui_message,
            details=ui_details,
            guardrail=input_rail_result.guardrail,
            reason_code=reason_code
        )
        
        raise HTTPException(
            status_code=input_rail_result.http_status,
            detail=ErrorResponse(
                message=input_rail_result.message,
                reason_code=reason_code,
                guardrail=input_rail_result.guardrail,
                request_id=request_id
            ).model_dump()
        )
    
    # Interceptor passed
    emit_gateway_event(
        request_id=request_id,
        phase="INTERCEPTOR",
        status="PASS",
        details={"checks_passed": ["baa", "injection", "tool_manifest", "allowlist"], "workflow": workflow, "action": action}
    )
    
    # Phase: POLICY (Phase 2.1 - Build policy input)
    
    # Build threat signals from interceptor checks
    threat_signals = {
        "injection_detected": False,  # We already blocked if true
        "tool_manifest_suspicious": False,  # We already blocked if true
        "destination_unknown": False  # We already blocked if true
    }
    
    # Build policy input
    policy_input = build_policy_input(request, destination_info, threat_signals)

    # Phase 2.2: Evaluate policy (Mock OPA, OPA-shaped bundle)
    try:
        policy_decision = evaluate_policy(policy_input)
    except Exception:
        # Deterministic fail-closed behavior: policy engine error blocks the request
        emit_gateway_event(
            request_id=request_id,
            phase="POLICY",
            status="BLOCK",
            reason_code="POLICY_ENGINE_ERROR",
            guardrail="Endpoint Control",
            details={
                "policy_engine": POLICY_ENGINE_NAME,
                "policy_version": "unknown",
                "policy_input": policy_input.model_dump(),
                "error": "Policy bundle load/evaluation failed."
            }
        )
        emit_live_event(
            request_id=request_id,
            event_type="blocked",
            message="BLOCKED: Policy Engine Error",
            details="Policy engine failed to load/evaluate policy bundle.",
            guardrail="Endpoint Control",
            reason_code="POLICY_ENGINE_ERROR"
        )
        raise HTTPException(
            status_code=500,
            detail=ErrorResponse(
                message="Blocked by gateway policy. Policy engine error.",
                reason_code="POLICY_ENGINE_ERROR",
                guardrail="Endpoint Control",
                request_id=request_id
            ).model_dump()
        )

    # Emit POLICY decision event (Inspector must show input + outcome)
    emit_gateway_event(
        request_id=request_id,
        phase="POLICY",
        status="BLOCK" if policy_decision.decision == "DENY" else "PASS",
        reason_code=policy_decision.reason_code,
        guardrail=policy_decision.guardrail,
        details={
            "policy_engine": POLICY_ENGINE_NAME,
            "policy_version": policy_decision.policy_version,
            "policy_input": policy_input.model_dump(),
            "policy_decision": policy_decision.model_dump()
        }
    )

    # Enforce policy decision
    if policy_decision.decision == "DENY":
        guardrail = policy_decision.guardrail or "Endpoint Control"
        reason_code = policy_decision.reason_code or "POLICY_DENY"

        emit_live_event(
            request_id=request_id,
            event_type="blocked",
            message="BLOCKED: Policy Enforcement",
            details=policy_decision.message,
            guardrail=guardrail,
            reason_code=reason_code
        )
        raise HTTPException(
            status_code=403,
            detail=ErrorResponse(
                message=policy_decision.message,
                reason_code=reason_code,
                guardrail=guardrail,
                request_id=request_id
            ).model_dump()
        )
    
    # Phase: EXECUTION (Phase 3 - LLM Provider Abstraction)
    
    # Step 1: Compose prompt using template manager (Phase 3.1)
    prompt_manager = get_prompt_manager()
    composed = prompt_manager.compose_prompt(
        workflow=workflow,
        user_context=request.prompt,  # User-provided context (untrusted)
        action=action,
        modality=request.modality,
    )
    
    # Emit PROMPT_COMPOSED event (Phase 3.1)
    emit_gateway_event(
        request_id=request_id,
        phase="EXECUTION",
        status="PASS",
        reason_code="PROMPT_COMPOSED",
        details={
            "event_type": "PROMPT_COMPOSED",
            **composed.to_audit_dict()  # Hash + metadata, no raw prompt
        }
    )
    
    # Step 2: Get LLM provider and generate response (Phase 3.2)
    provider = get_provider()
    llm_response: LLMResponse = await provider.generate(
        prompt=composed.full_prompt,
        max_tokens=1024,
        temperature=0.1,
        json_mode=True,
    )
    
    # Check for LLM errors
    if not llm_response.success:
        emit_gateway_event(
            request_id=request_id,
            phase="EXECUTION",
            status="BLOCK",
            reason_code="LLM_ERROR",
            guardrail="Model Integrity Check",
            details={
                "provider": llm_response.provider,
                "model": llm_response.model,
                "error": llm_response.error_message,
                "latency_ms": llm_response.latency_ms,
            }
        )
        emit_live_event(
            request_id=request_id,
            event_type="blocked",
            message="BLOCKED: LLM Execution Error",
            details=f"LLM provider error: {llm_response.error_message}",
            guardrail="Model Integrity Check",
            reason_code="LLM_ERROR"
        )
        raise HTTPException(
            status_code=503,
            detail=ErrorResponse(
                message="LLM execution failed. Please try again.",
                reason_code="LLM_ERROR",
                guardrail="Model Integrity Check",
                request_id=request_id
            ).model_dump()
        )
    
    # Emit LLM_RESPONSE event
    emit_gateway_event(
        request_id=request_id,
        phase="EXECUTION",
        status="PASS",
        reason_code="LLM_RESPONSE",
        details={
            "event_type": "LLM_RESPONSE",
            **llm_response.to_audit_dict()  # Provider metadata, no raw response
        }
    )
    
    # Phase: OUTPUT (Phase 4 - Output Validation)
    # Get required output keys from template
    template = prompt_manager.get_template(workflow)
    required_keys = template.required_output_keys
    
    # Run output rails (schema validation, hallucination check, canary scan)
    output_result = run_output_rails(
        llm_output=llm_response.raw_text,
        parsed_output=llm_response.parsed_json,
        workflow=workflow,
        required_keys=required_keys
    )
    
    if not output_result.passed:
        # Output validation failed - block the response
        emit_gateway_event(
            request_id=request_id,
            phase="OUTPUT",
            status="BLOCK",
            reason_code=output_result.reason_code,
            guardrail=output_result.guardrail,
            details={
                **output_result.details,
                "llm_risk_score": llm_response.risk_score,
                "llm_confidence": llm_response.confidence,
            }
        )
        emit_live_event(
            request_id=request_id,
            event_type="blocked",
            message=f"BLOCKED: {output_result.guardrail}",
            details=output_result.message,
            guardrail=output_result.guardrail,
            reason_code=output_result.reason_code
        )
        raise HTTPException(
            status_code=400 if output_result.reason_code == "INVALID_MODEL_OUTPUT" else 403,
            detail=ErrorResponse(
                message=output_result.message,
                reason_code=output_result.reason_code,
                guardrail=output_result.guardrail,
                request_id=request_id
            ).model_dump()
        )
    
    # Output validation passed
    emit_gateway_event(
        request_id=request_id,
        phase="OUTPUT",
        status="PASS",
        details={
            "schema_validation": "passed",
            "hallucination_check": "passed",
            "canary_scan": "passed",
            "phi_detected": output_result.phi_detected,
            "llm_risk_score": llm_response.risk_score,
            "llm_confidence": llm_response.confidence,
            **output_result.details
        }
    )
    
    # Phase: RESPONDED
    emit_gateway_event(
        request_id=request_id,
        phase="RESPONDED",
        status="PASS",
        details={
            "response_type": "allowed",
            "provider": llm_response.provider,
            "model": llm_response.model,
        }
    )
    
    # Emit Live Event for demo UI
    emit_live_event(
        request_id=request_id,
        event_type="allowed",
        message=f"ALLOWED: {request.modality} Analysis",
        details=f"Request to {destination_info['vendor']} approved. All guardrails passed. Risk: {llm_response.risk_score}",
        guardrail=policy_decision.guardrail or "FDA Audit Trail",
        reason_code=policy_decision.reason_code or "POLICY_ALLOW"
    )
    
    # Build response with LLM findings (Phase 3)
    return AnalyzeResponse(
        status="ALLOWED",
        risk=llm_response.risk_score,
        message=f"Analysis request approved. Routed to {destination_info['vendor']}.",
        policy="CLINICAL-GEN-04",
        findings=llm_response.findings if llm_response.findings else [
            "Request validated against BAA registry.",
            "No injection patterns detected.",
            "Destination approved for PHI transmission."
        ],
        request_id=request_id
    )


# =============================================================================
# Backwards Compatibility with demo/api/main.py
# =============================================================================

@app.post("/analyze")
async def analyze_compat(request: AnalyzeRequest):
    """
    Backwards-compatible /analyze endpoint (matches demo/api/main.py).
    Redirects to /v1/analyze internally.
    """
    return await analyze(request)


# =============================================================================
# Scanner Endpoints (Phase 4.2)
# =============================================================================

# Import scanner module (relative import from gateway package)
import sys
from pathlib import Path

# Add gateway root to path for scanner import
_gateway_root = Path(__file__).resolve().parents[1]
if str(_gateway_root) not in sys.path:
    sys.path.insert(0, str(_gateway_root))

try:
    from scanner import (
        NetworkScanner,
        MockScanner,
        ScannerConfig,
        ScanTarget,
        ScanResult,
        DetectedNode,
        # Persistence
        init_db as init_scanner_db,
        save_scan_result,
        load_latest_scan_result,
        save_isolated_nodes,
        load_isolated_nodes,
        clear_isolated_nodes,
        get_db_stats,
    )
    from scanner.mock_scanner import get_scanner
    SCANNER_AVAILABLE = True
except ImportError as e:
    SCANNER_AVAILABLE = False
    logger_msg = f"Scanner module not available: {e}"


class ScanRequest(BaseModel):
    """Request to initiate a network scan."""
    use_mock: bool = Field(
        default=True,
        description="Use mock scanner (True for demo, False for real scan)"
    )
    subnets: Optional[List[str]] = Field(
        default=None,
        description="CIDR subnets to scan (default: 192.168.1.0/24)"
    )
    include_dns: bool = Field(
        default=True,
        description="Include DNS analysis for public AI traffic"
    )
    include_ports: bool = Field(
        default=True,
        description="Include port scanning for local LLMs"
    )


class IsolateRequest(BaseModel):
    """Request to isolate (mark as blocked) specific nodes."""
    node_ids: List[str] = Field(
        ...,
        description="List of node IDs to isolate"
    )


# In-memory storage for scan results and isolated nodes
# These are loaded from SQLite on startup (persistence across restarts)
_last_scan_result: Optional[ScanResult] = None
_isolated_node_ids: List[str] = []


def _init_scanner_persistence():
    """
    Initialize scanner persistence on startup.
    
    Loads the last scan result and isolated nodes from SQLite.
    """
    global _last_scan_result, _isolated_node_ids
    
    if not SCANNER_AVAILABLE:
        return
    
    try:
        # Initialize the database schema
        init_scanner_db()
        
        # Load persisted state
        _last_scan_result = load_latest_scan_result()
        _isolated_node_ids = load_isolated_nodes()
        
        # Apply isolations to loaded scan result
        if _last_scan_result and _isolated_node_ids:
            from scanner.models import RiskLevel
            for node in _last_scan_result.nodes:
                if node.id in _isolated_node_ids:
                    node.risk_level = RiskLevel.BLOCKED
                    node.risk_reasons = ["ISOLATED by administrator action"]
            _last_scan_result.compute_summary()
        
        import logging
        logging.info(f"Scanner persistence loaded: scan={_last_scan_result.scan_id if _last_scan_result else None}, isolated={len(_isolated_node_ids)}")
        
    except Exception as e:
        import logging
        logging.error(f"Failed to initialize scanner persistence: {e}")


# Initialize persistence on module load
_init_scanner_persistence()


@app.get("/v1/scanner/status")
async def scanner_status():
    """Check if scanner module is available."""
    # Get persistence stats if available
    persistence_stats = {}
    if SCANNER_AVAILABLE:
        try:
            persistence_stats = get_db_stats()
        except Exception:
            persistence_stats = {"error": "Could not read persistence stats"}
    
    return {
        "available": SCANNER_AVAILABLE,
        "mock_available": True,
        "real_scan_available": SCANNER_AVAILABLE,
        "last_scan": _last_scan_result.scan_id if _last_scan_result else None,
        "isolated_nodes": len(_isolated_node_ids),
        "persistence": persistence_stats,
    }


@app.post("/v1/scanner/scan", response_model=ScanResult)
async def run_scan(request: ScanRequest):
    """
    Run a network scan to detect Shadow AI infrastructure.
    
    Detects:
    - Local LLM servers (Port 11434 = Ollama, etc.)
    - Public AI API traffic (OpenAI, HuggingFace, etc.)
    
    Use mock=True for demo, mock=False for real network scanning.
    """
    global _last_scan_result
    
    if not SCANNER_AVAILABLE and not request.use_mock:
        raise HTTPException(
            status_code=503,
            detail="Scanner module not available. Use mock=True for demo."
        )
    
    # Build config
    config = ScannerConfig(
        use_mock=request.use_mock,
        target_subnets=request.subnets or ["192.168.1.0/24"],
    )
    
    # Get appropriate scanner
    scanner = get_scanner(config) if SCANNER_AVAILABLE else MockScanner(config)
    
    # Build scan target
    target = ScanTarget(
        scan_id=f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        subnets=config.target_subnets,
        include_dns_analysis=request.include_dns,
        include_port_scan=request.include_ports,
    )
    
    # Run scan
    result = await scanner.scan(target)
    
    # Apply any existing isolations
    for node in result.nodes:
        if node.id in _isolated_node_ids:
            from scanner.models import RiskLevel
            node.risk_level = RiskLevel.BLOCKED
            node.risk_reasons = ["ISOLATED by administrator action"]
    
    # Recompute summary after applying isolations
    result.compute_summary()
    
    # Store result (in-memory and persistent)
    _last_scan_result = result
    
    # Persist to SQLite
    if SCANNER_AVAILABLE:
        try:
            save_scan_result(result)
        except Exception as e:
            import logging
            logging.error(f"Failed to persist scan result: {e}")
    
    # Emit live event
    emit_live_event(
        request_id=f"scan_{result.scan_id}",
        event_type="allowed" if result.critical_count == 0 else "flagged",
        message=f"Network Scan Complete: {result.total_nodes} nodes detected",
        details=f"Found {result.critical_count} critical, {result.warning_count} warning, {result.trusted_count} trusted nodes.",
        guardrail="Shadow AI Detection",
        reason_code="SCAN_COMPLETE"
    )
    
    return result


@app.get("/v1/scanner/results", response_model=Optional[ScanResult])
async def get_scan_results():
    """Get the most recent scan results."""
    if not _last_scan_result:
        raise HTTPException(
            status_code=404,
            detail="No scan results available. Run a scan first."
        )
    return _last_scan_result


@app.get("/v1/scanner/nodes", response_model=List[DetectedNode])
async def get_detected_nodes():
    """
    Get all detected nodes from the last scan.
    
    This endpoint is designed for the demo UI's network map.
    """
    if not _last_scan_result:
        # Return mock data if no scan has been run yet
        if SCANNER_AVAILABLE:
            mock = MockScanner()
            return mock._get_demo_nodes()
        else:
            return []
    
    return _last_scan_result.nodes


@app.post("/v1/scanner/isolate")
async def isolate_nodes(request: IsolateRequest):
    """
    Mark nodes as isolated/blocked.
    
    This is the backend for the demo UI's "Isolate" button.
    In production, this would trigger actual network isolation
    (firewall rules, ACLs, etc.).
    """
    global _isolated_node_ids
    
    # Add to isolated list
    for node_id in request.node_ids:
        if node_id not in _isolated_node_ids:
            _isolated_node_ids.append(node_id)
    
    # Persist isolated nodes to SQLite
    if SCANNER_AVAILABLE:
        try:
            save_isolated_nodes(request.node_ids)
        except Exception as e:
            import logging
            logging.error(f"Failed to persist isolated nodes: {e}")
    
    # Update last scan result if available
    isolated_count = 0
    if _last_scan_result:
        for node in _last_scan_result.nodes:
            if node.id in request.node_ids:
                from scanner.models import RiskLevel
                node.risk_level = RiskLevel.BLOCKED
                node.risk_reasons = ["ISOLATED by administrator action"]
                isolated_count += 1
        _last_scan_result.compute_summary()
    
    # Emit live event
    emit_live_event(
        request_id=f"isolate_{datetime.utcnow().strftime('%H%M%S')}",
        event_type="blocked",
        message=f"ISOLATED: {isolated_count} Shadow AI nodes blocked",
        details=f"Administrator isolated nodes: {', '.join(request.node_ids)}",
        guardrail="Shadow AI Isolation",
        reason_code="NODE_ISOLATED"
    )
    
    return {
        "status": "success",
        "isolated_count": isolated_count,
        "total_isolated": len(_isolated_node_ids),
        "node_ids": _isolated_node_ids,
    }


@app.post("/v1/scanner/reset")
async def reset_scanner():
    """
    Reset scanner state (clear isolations and scan results).
    
    Useful for demo reset.
    """
    global _last_scan_result, _isolated_node_ids
    
    _last_scan_result = None
    _isolated_node_ids = []
    
    # Clear persistence
    if SCANNER_AVAILABLE:
        try:
            clear_isolated_nodes()
        except Exception as e:
            import logging
            logging.error(f"Failed to clear isolated nodes from persistence: {e}")
    
    return {
        "status": "success",
        "message": "Scanner state reset. Run a new scan to detect nodes.",
    }


@app.get("/v1/scanner/quick/{host}")
async def quick_scan_host(host: str):
    """
    Quick scan a single host for LLM ports.
    
    Args:
        host: IP address or hostname to scan
    """
    if not SCANNER_AVAILABLE:
        # Use mock scanner
        mock = MockScanner()
        nodes = await mock.quick_scan_host(host)
    else:
        config = ScannerConfig(use_mock=False)
        scanner = NetworkScanner(config)
        nodes = await scanner.quick_scan_host(host)
    
    return {
        "host": host,
        "nodes_found": len(nodes),
        "nodes": [n.model_dump() for n in nodes],
    }


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

