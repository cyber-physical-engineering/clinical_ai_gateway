"""
LLM Provider Base Interface (Phase 3.2)

Defines the abstract interface for all LLM providers.
Supports Mock, Ollama (local), and Vertex (cloud) providers.

Source: devlog/gateway_build.md Phase 3.2
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class ProviderType(str, Enum):
    """Available LLM provider types."""
    MOCK = "mock"
    OLLAMA = "ollama"
    VERTEX = "vertex"


@dataclass
class LLMResponse:
    """
    Standardized response from any LLM provider.
    
    Includes both the structured output and metadata for auditing.
    """
    # Core response
    raw_text: str  # Raw text from LLM
    parsed_json: Optional[Dict[str, Any]]  # Parsed JSON if valid
    
    # Structured output (from parsed_json)
    risk_score: str = "UNKNOWN"
    findings: List[str] = field(default_factory=list)
    confidence: float = 0.0
    disclaimer: str = ""
    requires_review: bool = True
    
    # Provider metadata
    provider: str = "unknown"
    model: str = "unknown"
    latency_ms: float = 0.0
    tokens_input: int = 0
    tokens_output: int = 0
    
    # Explainability stub (Phase 3.4)
    explain_artifact: Optional[Dict[str, Any]] = None
    
    # Error handling
    success: bool = True
    error_message: Optional[str] = None
    
    def to_audit_dict(self) -> Dict[str, Any]:
        """Return audit-safe representation (no raw response content)."""
        return {
            "provider": self.provider,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "tokens_input": self.tokens_input,
            "tokens_output": self.tokens_output,
            "risk_score": self.risk_score,
            "findings_count": len(self.findings),
            "confidence": self.confidence,
            "requires_review": self.requires_review,
            "success": self.success,
            "has_explain_artifact": self.explain_artifact is not None,
        }


class BaseProvider(ABC):
    """
    Abstract base class for LLM providers.
    
    All providers must implement:
    - generate(): Send prompt and get response
    - health_check(): Verify provider is available
    """
    
    provider_type: ProviderType = ProviderType.MOCK
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1024,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: Full prompt (system + context + user)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (lower = more deterministic)
            json_mode: If True, expect JSON output
        
        Returns:
            LLMResponse with structured output and metadata
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is available and ready."""
        pass
    
    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model name/identifier."""
        pass
    
    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse JSON from response text."""
        import json
        
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code block
        if "```json" in text:
            try:
                start = text.index("```json") + 7
                end = text.index("```", start)
                return json.loads(text[start:end].strip())
            except (ValueError, json.JSONDecodeError):
                pass
        
        # Try to extract JSON from plain code block
        if "```" in text:
            try:
                start = text.index("```") + 3
                end = text.index("```", start)
                return json.loads(text[start:end].strip())
            except (ValueError, json.JSONDecodeError):
                pass
        
        return None
    
    def _build_response_from_json(
        self,
        parsed: Dict[str, Any],
        raw_text: str,
        latency_ms: float,
        tokens_input: int = 0,
        tokens_output: int = 0,
    ) -> LLMResponse:
        """Build LLMResponse from parsed JSON."""
        return LLMResponse(
            raw_text=raw_text,
            parsed_json=parsed,
            risk_score=parsed.get("risk_score", "UNKNOWN"),
            findings=parsed.get("findings", []),
            confidence=float(parsed.get("confidence", 0.0)),
            disclaimer=parsed.get("disclaimer", ""),
            requires_review=parsed.get("requires_review", True),
            provider=self.provider_type.value,
            model=self.model_name,
            latency_ms=latency_ms,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            explain_artifact=self._generate_explain_stub(parsed),
            success=True,
        )
    
    def _generate_explain_stub(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate explainability artifact stub (Phase 3.4).
        
        In production, this would include:
        - Token attribution/heatmap
        - Confidence breakdown per finding
        - Source citations
        """
        return {
            "type": "stub",
            "version": "0.1.0",
            "rationale": "Explainability artifact (stub for Phase 3.4)",
            "findings_breakdown": [
                {"finding": f, "confidence": parsed.get("confidence", 0.0)}
                for f in parsed.get("findings", [])
            ],
            "attribution_method": "none (stub)",
        }

