"""
Dialog Rails (Phase 2.3 - NeMo Guardrails Scaffolding)

LLM interaction controls that run DURING the LLM call:
- Prompt composition with strict delimiters (Phase 3.1)
- Context filtering and injection of system instructions (Phase 3+)
- Real-time token filtering (future)

These rails shape the LLM interaction but do not block requests outright.

See: devlog/gateway_build.md Phase 2.3, Phase 3
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel


# =============================================================================
# Dialog Rail Result
# =============================================================================

class DialogRailResult(BaseModel):
    """Result of running dialog rails."""
    passed: bool
    composed_prompt: Optional[str] = None
    system_prompt: Optional[str] = None
    prompt_hash: Optional[str] = None
    template_version: Optional[str] = None
    details: Dict[str, Any] = {}


# =============================================================================
# Stub Implementation (Phase 3+)
# =============================================================================

def run_dialog_rails(
    user_prompt: Optional[str],
    context: Optional[Dict[str, Any]] = None,
    workflow: str = "default_workflow"
) -> DialogRailResult:
    """
    Run dialog rails (stub for Phase 3+).
    
    Phase 3 will implement:
    - Prompt template loading
    - Context injection with strict delimiters
    - Prompt hashing for audit
    
    For now, returns a passing result with the raw prompt.
    """
    return DialogRailResult(
        passed=True,
        composed_prompt=user_prompt,
        system_prompt=None,  # Phase 3 will add system prompt templates
        prompt_hash=None,    # Phase 3 will add hashing
        template_version="stub_v0",
        details={
            "rail_status": "stub",
            "phase": "Phase 3 pending",
            "workflow": workflow
        }
    )

