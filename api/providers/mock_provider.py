"""
Mock LLM Provider (Phase 3.2)

Fastest provider for development and testing.
Returns deterministic responses based on input patterns.

Source: devlog/gateway_build.md Phase 3.2
"""

import asyncio
import time
from typing import Any, Dict, List

from .base import BaseProvider, LLMResponse, ProviderType


class MockProvider(BaseProvider):
    """
    Mock provider for fast development iteration.
    
    Returns deterministic responses:
    - Normal requests: LOW risk, standard findings
    - High-risk keywords: HIGH risk, flagged findings
    - Configurable latency for realistic timing
    """
    
    provider_type = ProviderType.MOCK
    
    def __init__(self, simulated_latency_ms: float = 100):
        """
        Initialize mock provider.
        
        Args:
            simulated_latency_ms: Artificial delay to simulate LLM latency
        """
        self.simulated_latency_ms = simulated_latency_ms
    
    @property
    def model_name(self) -> str:
        return "mock-v1"
    
    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1024,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> LLMResponse:
        """Generate a mock response based on prompt content."""
        start_time = time.time()
        
        # Simulate latency
        await asyncio.sleep(self.simulated_latency_ms / 1000)
        
        # Determine response based on prompt content
        response_data = self._determine_response(prompt)
        
        latency_ms = (time.time() - start_time) * 1000
        
        return self._build_response_from_json(
            parsed=response_data,
            raw_text=str(response_data),
            latency_ms=latency_ms,
            tokens_input=len(prompt) // 4,  # Rough estimate
            tokens_output=len(str(response_data)) // 4,
        )
    
    async def health_check(self) -> bool:
        """Mock provider is always healthy."""
        return True
    
    def _determine_response(self, prompt: str) -> Dict[str, Any]:
        """
        Determine mock response based on prompt content.
        
        Uses keyword detection for deterministic behavior:
        - "FORCE_SCHEMA_FAIL" → Missing required keys (Phase 4.1 test)
        - "FORCE_PHI_LEAK" → Contains PHI in output (Phase 4.3 test)
        - "urgent", "emergency", "critical" → HIGH risk
        - "routine", "normal", "standard" → LOW risk
        - Default → MEDIUM risk
        """
        prompt_lower = prompt.lower()
        
        # Phase 4 test triggers (case-sensitive for explicit testing)
        if "FORCE_SCHEMA_FAIL" in prompt:
            return self._schema_fail_response()
        if "FORCE_PHI_LEAK" in prompt:
            return self._phi_leak_response()
        
        # High-risk keywords
        high_risk_keywords = ["urgent", "emergency", "critical", "severe", "acute"]
        # Low-risk keywords
        low_risk_keywords = ["routine", "normal", "standard", "stable", "unremarkable"]
        
        if any(kw in prompt_lower for kw in high_risk_keywords):
            return self._high_risk_response()
        elif any(kw in prompt_lower for kw in low_risk_keywords):
            return self._low_risk_response()
        else:
            return self._medium_risk_response()
    
    def _low_risk_response(self) -> Dict[str, Any]:
        return {
            "risk_score": "LOW",
            "findings": [
                "No significant abnormalities detected.",
                "Image quality adequate for interpretation.",
                "Comparison with prior studies shows stability."
            ],
            "confidence": 0.92,
            "disclaimer": "This AI-generated summary is for clinical decision support only. Final interpretation must be made by a qualified radiologist.",
            "requires_review": False
        }
    
    def _medium_risk_response(self) -> Dict[str, Any]:
        return {
            "risk_score": "MEDIUM",
            "findings": [
                "Minor findings noted, recommend follow-up.",
                "Image quality adequate for interpretation.",
                "Consider clinical correlation."
            ],
            "confidence": 0.78,
            "disclaimer": "This AI-generated summary is for clinical decision support only. Final interpretation must be made by a qualified radiologist.",
            "requires_review": True
        }
    
    def _high_risk_response(self) -> Dict[str, Any]:
        return {
            "risk_score": "HIGH",
            "findings": [
                "Significant findings require immediate attention.",
                "Recommend urgent clinical review.",
                "Consider additional imaging or intervention."
            ],
            "confidence": 0.85,
            "disclaimer": "This AI-generated summary is for clinical decision support only. Final interpretation must be made by a qualified radiologist. URGENT: Please review immediately.",
            "requires_review": True
        }
    
    # ==========================================================================
    # Phase 4 Test Triggers
    # ==========================================================================
    
    def _schema_fail_response(self) -> Dict[str, Any]:
        """
        Return malformed output missing required keys (Phase 4.1 test).
        Missing: confidence, disclaimer
        """
        return {
            "risk_score": "MEDIUM",
            "findings": ["Some finding"]
            # Missing: confidence, disclaimer
        }
    
    def _phi_leak_response(self) -> Dict[str, Any]:
        """
        Return output containing PHI (Phase 4.3 canary test).
        Contains SSN and MRN that should trigger the canary scan.
        """
        return {
            "risk_score": "LOW",
            "findings": [
                "Patient John Smith (MRN: 12345678) shows normal findings.",
                "SSN 123-45-6789 on record.",
                "No acute abnormalities."
            ],
            "confidence": 0.9,
            "disclaimer": "AI-assisted analysis for patient review.",
            "requires_review": False
        }

