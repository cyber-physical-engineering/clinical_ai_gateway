"""
LLM Providers Module (Phase 3)

Provides a unified interface for LLM providers:
- MockProvider: Fast development iteration
- OllamaProvider: Local LLM via Ollama
- VertexProvider: Cloud LLM via Google Vertex AI (stub)

Source: devlog/gateway_build.md Phase 3
"""

import os
from typing import Optional

from .base import BaseProvider, LLMResponse, ProviderType
from .mock_provider import MockProvider
from .ollama_provider import OllamaProvider
from .vertex_provider import VertexProvider
from .prompt_manager import (
    PromptTemplateManager,
    PromptTemplate,
    ComposedPrompt,
    get_prompt_manager,
)

__all__ = [
    # Base types
    "BaseProvider",
    "LLMResponse",
    "ProviderType",
    # Providers
    "MockProvider",
    "OllamaProvider",
    "VertexProvider",
    # Prompt management
    "PromptTemplateManager",
    "PromptTemplate",
    "ComposedPrompt",
    "get_prompt_manager",
    # Factory
    "get_provider",
]


# Provider configuration from environment
DEFAULT_PROVIDER = os.getenv("GATEWAY_LLM_PROVIDER", "mock")
OLLAMA_MODEL = os.getenv("GATEWAY_OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_URL = os.getenv("GATEWAY_OLLAMA_URL", "http://localhost:11434")
VERTEX_PROJECT = os.getenv("GATEWAY_VERTEX_PROJECT", "healthsec-demo")
VERTEX_LOCATION = os.getenv("GATEWAY_VERTEX_LOCATION", "us-central1")
VERTEX_MODEL = os.getenv("GATEWAY_VERTEX_MODEL", "gemini-1.5-flash")


# Cached provider instance
_provider: Optional[BaseProvider] = None


def get_provider(provider_type: Optional[str] = None) -> BaseProvider:
    """
    Get or create an LLM provider instance.
    
    Provider selection priority:
    1. Explicit provider_type argument
    2. GATEWAY_LLM_PROVIDER environment variable
    3. Default: "mock"
    
    Args:
        provider_type: Optional provider type ("mock", "ollama", "vertex")
    
    Returns:
        Configured LLM provider instance
    """
    global _provider
    
    provider_str = provider_type or DEFAULT_PROVIDER
    
    # Check if we need a new provider
    if _provider is not None:
        if _provider.provider_type.value == provider_str:
            return _provider
    
    # Create new provider
    if provider_str == "ollama":
        _provider = OllamaProvider(
            base_url=OLLAMA_URL,
            model=OLLAMA_MODEL,
        )
    elif provider_str == "vertex":
        _provider = VertexProvider(
            project_id=VERTEX_PROJECT,
            location=VERTEX_LOCATION,
            model=VERTEX_MODEL,
        )
    else:
        # Default to mock
        _provider = MockProvider()
    
    return _provider


async def check_provider_health(provider_type: Optional[str] = None) -> dict:
    """
    Check health of the specified provider.
    
    Returns:
        Dict with provider status and details
    """
    provider = get_provider(provider_type)
    healthy = await provider.health_check()
    
    return {
        "provider": provider.provider_type.value,
        "model": provider.model_name,
        "healthy": healthy,
    }

