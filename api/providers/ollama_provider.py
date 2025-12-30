"""
Ollama LLM Provider (Phase 3.2 + 3.3)

Local LLM provider using Ollama for on-device inference.
Recommended models: Llama 3.2 1B or 3B for M1 Mac.

Source: devlog/gateway_build.md Phase 3.2, 3.3
"""

import asyncio
import json
import time
from typing import Any, Dict, Optional

import httpx

from .base import BaseProvider, LLMResponse, ProviderType


class OllamaProvider(BaseProvider):
    """
    Ollama provider for local LLM inference.
    
    Connects to Ollama running on localhost.
    Optimized for Llama 3.2 1B/3B models.
    """
    
    provider_type = ProviderType.OLLAMA
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2:1b",
        timeout_seconds: float = 60.0,
    ):
        """
        Initialize Ollama provider.
        
        Args:
            base_url: Ollama API base URL
            model: Model name (e.g., "llama3.2:1b", "llama3.2:3b")
            timeout_seconds: Request timeout
        """
        self.base_url = base_url
        self.model = model
        self.timeout_seconds = timeout_seconds
    
    @property
    def model_name(self) -> str:
        return self.model
    
    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1024,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> LLMResponse:
        """Generate response using Ollama API."""
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                # Build request payload
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    }
                }
                
                # Add JSON format hint if requested
                if json_mode:
                    payload["format"] = "json"
                
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
                response.raise_for_status()
                
                data = response.json()
                raw_text = data.get("response", "")
                
                latency_ms = (time.time() - start_time) * 1000
                
                # Parse JSON from response
                parsed = self._parse_json_response(raw_text)
                
                if parsed:
                    return self._build_response_from_json(
                        parsed=parsed,
                        raw_text=raw_text,
                        latency_ms=latency_ms,
                        tokens_input=data.get("prompt_eval_count", 0),
                        tokens_output=data.get("eval_count", 0),
                    )
                else:
                    # Failed to parse JSON - return error response
                    return LLMResponse(
                        raw_text=raw_text,
                        parsed_json=None,
                        provider=self.provider_type.value,
                        model=self.model_name,
                        latency_ms=latency_ms,
                        tokens_input=data.get("prompt_eval_count", 0),
                        tokens_output=data.get("eval_count", 0),
                        success=False,
                        error_message="Failed to parse JSON from LLM response",
                    )
                    
        except httpx.HTTPStatusError as e:
            latency_ms = (time.time() - start_time) * 1000
            return LLMResponse(
                raw_text="",
                parsed_json=None,
                provider=self.provider_type.value,
                model=self.model_name,
                latency_ms=latency_ms,
                success=False,
                error_message=f"Ollama API error: {e.response.status_code}",
            )
        except httpx.RequestError as e:
            latency_ms = (time.time() - start_time) * 1000
            return LLMResponse(
                raw_text="",
                parsed_json=None,
                provider=self.provider_type.value,
                model=self.model_name,
                latency_ms=latency_ms,
                success=False,
                error_message=f"Ollama connection error: {str(e)}",
            )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return LLMResponse(
                raw_text="",
                parsed_json=None,
                provider=self.provider_type.value,
                model=self.model_name,
                latency_ms=latency_ms,
                success=False,
                error_message=f"Unexpected error: {str(e)}",
            )
    
    async def health_check(self) -> bool:
        """Check if Ollama is running and the model is available."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Check if Ollama is running
                response = await client.get(f"{self.base_url}/api/tags")
                if response.status_code != 200:
                    return False
                
                # Check if our model is available
                data = response.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                
                # Check for exact match or partial match (e.g., "llama3.2:1b" in "llama3.2:1b-instruct")
                return any(self.model in m or m in self.model for m in models)
                
        except Exception:
            return False
    
    async def list_models(self) -> list:
        """List available models in Ollama."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                if response.status_code == 200:
                    data = response.json()
                    return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            pass
        return []

