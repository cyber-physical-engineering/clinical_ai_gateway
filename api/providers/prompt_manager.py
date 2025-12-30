"""
Prompt Template Manager (Phase 3.1)

Manages versioned system prompts stored as JSON templates.
Constructs final prompts with strict delimiters for untrusted context.

Source: devlog/gateway_build.md Phase 3.1
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Template directory (relative to gateway/api/)
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


@dataclass
class PromptTemplate:
    """Represents a loaded prompt template."""
    template_id: str
    version: str
    description: str
    workflow: str
    system_prompt: str
    context_delimiter: str
    max_context_tokens: int
    required_output_keys: List[str]
    created_at: str
    updated_at: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PromptTemplate":
        return cls(
            template_id=data["template_id"],
            version=data["version"],
            description=data["description"],
            workflow=data["workflow"],
            system_prompt=data["system_prompt"],
            context_delimiter=data["context_delimiter"],
            max_context_tokens=data["max_context_tokens"],
            required_output_keys=data["required_output_keys"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


@dataclass
class ComposedPrompt:
    """Result of prompt composition with metadata for auditing."""
    template_id: str
    template_version: str
    system_prompt: str
    user_prompt: str
    full_prompt: str
    prompt_hash: str  # SHA256 hash of full prompt (for audit, no PHI)
    context_included: bool
    truncated: bool
    
    def to_audit_dict(self) -> Dict[str, Any]:
        """Return audit-safe representation (no raw prompt content)."""
        return {
            "template_id": self.template_id,
            "template_version": self.template_version,
            "prompt_hash": self.prompt_hash,
            "context_included": self.context_included,
            "truncated": self.truncated,
            "system_prompt_length": len(self.system_prompt),
            "user_prompt_length": len(self.user_prompt),
            "full_prompt_length": len(self.full_prompt),
        }


class PromptTemplateManager:
    """
    Manages prompt templates and composes final prompts.
    
    Features:
    - Loads versioned templates from JSON files
    - Wraps untrusted context with strict delimiters
    - Provides hash for audit without leaking PHI
    """
    
    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self._cache: Dict[str, PromptTemplate] = {}
        self._load_all_templates()
    
    def _load_all_templates(self) -> None:
        """Load all templates from the templates directory."""
        if not self.templates_dir.exists():
            return
        
        for template_file in self.templates_dir.glob("*.json"):
            try:
                with open(template_file) as f:
                    data = json.load(f)
                template = PromptTemplate.from_dict(data)
                self._cache[template.workflow] = template
            except Exception as e:
                # Log error but don't crash - fallback to default
                print(f"Warning: Failed to load template {template_file}: {e}")
    
    def get_template(self, workflow: str) -> PromptTemplate:
        """Get template by workflow name, fallback to default if not found."""
        if workflow in self._cache:
            return self._cache[workflow]
        
        # Fallback to default_workflow
        if "default_workflow" in self._cache:
            return self._cache["default_workflow"]
        
        # Ultimate fallback - inline minimal template
        return PromptTemplate(
            template_id="fallback",
            version="0.0.0",
            description="Inline fallback template",
            workflow="fallback",
            system_prompt="You are a clinical AI assistant. Respond with valid JSON only.",
            context_delimiter="\n\nContext: {context}\n\n",
            max_context_tokens=1024,
            required_output_keys=["risk_score", "findings"],
            created_at="2024-12-27",
            updated_at="2024-12-27",
        )
    
    def compose_prompt(
        self,
        workflow: str,
        user_context: Optional[str] = None,
        action: Optional[str] = None,
        modality: Optional[str] = None,
    ) -> ComposedPrompt:
        """
        Compose a final prompt from template + context.
        
        Args:
            workflow: Workflow identifier to select template
            user_context: Optional untrusted user context (will be delimited)
            action: Action being performed (e.g., "Analyze Study")
            modality: Imaging modality (e.g., "Chest X-ray")
        
        Returns:
            ComposedPrompt with full prompt and audit metadata
        """
        template = self.get_template(workflow)
        
        # Build user prompt from action/modality
        user_parts = []
        if action:
            user_parts.append(f"Action: {action}")
        if modality:
            user_parts.append(f"Modality: {modality}")
        
        user_prompt = "\n".join(user_parts) if user_parts else "Analyze the provided data."
        
        # Handle context with strict delimiters
        context_included = False
        truncated = False
        context_section = ""
        
        if user_context:
            context_included = True
            # Simple truncation (in production, use proper tokenizer)
            max_chars = template.max_context_tokens * 4  # ~4 chars per token estimate
            if len(user_context) > max_chars:
                user_context = user_context[:max_chars] + "... [TRUNCATED]"
                truncated = True
            
            context_section = template.context_delimiter.replace("{context}", user_context)
        
        # Compose full prompt
        full_prompt = f"{template.system_prompt}{context_section}\n\n{user_prompt}"
        
        # Generate hash for audit (no PHI in hash)
        prompt_hash = hashlib.sha256(full_prompt.encode()).hexdigest()[:16]
        
        return ComposedPrompt(
            template_id=template.template_id,
            template_version=template.version,
            system_prompt=template.system_prompt,
            user_prompt=user_prompt,
            full_prompt=full_prompt,
            prompt_hash=prompt_hash,
            context_included=context_included,
            truncated=truncated,
        )
    
    def list_templates(self) -> List[Dict[str, str]]:
        """List all available templates (for UI/debugging)."""
        return [
            {
                "template_id": t.template_id,
                "version": t.version,
                "workflow": t.workflow,
                "description": t.description,
            }
            for t in self._cache.values()
        ]


# Global instance for easy import
_manager: Optional[PromptTemplateManager] = None


def get_prompt_manager() -> PromptTemplateManager:
    """Get or create the global prompt template manager."""
    global _manager
    if _manager is None:
        _manager = PromptTemplateManager()
    return _manager

