"""
Gateway Rails Module (Phase 2.3 + Phase 5)

NeMo Guardrails-compatible rail structure:
- input_rails: Pre-LLM checks (BAA, injection, allowlist)
- dialog_rails: LLM interaction controls (Phase 3+)
- output_rails: Post-LLM validation (Phase 4)
- sanitizer: Split-stream logging (Phase 5)

See: devlog/gateway_build.md Phase 2.3, 4, 5
"""

from .input_rails import run_input_rails, InputRailResult
from .dialog_rails import run_dialog_rails, DialogRailResult
from .output_rails import run_output_rails, OutputRailResult
from .sanitizer import (
    split_stream_event,
    PrivateAuditEvent,
    PublicThreatEvent,
    verify_no_phi_in_public,
    hash_value,
    redact_phi,
)

__all__ = [
    # Input Rails
    "run_input_rails",
    "InputRailResult",
    # Dialog Rails
    "run_dialog_rails",
    "DialogRailResult",
    # Output Rails
    "run_output_rails",
    "OutputRailResult",
    # Sanitizer (Phase 5)
    "split_stream_event",
    "PrivateAuditEvent",
    "PublicThreatEvent",
    "verify_no_phi_in_public",
    "hash_value",
    "redact_phi",
]

