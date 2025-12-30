"""
Scanner Data Models - Phase 4.2
Pydantic models for network scanning results.

These models define the structure for:
- Scan targets (what to scan)
- Detected nodes (what we found)
- Scan results (aggregated findings)

Production Notes:
- Add scan_id for correlation with audit logs
- Add timestamp_started/timestamp_completed for SLA tracking
- Add scanner_version for reproducibility
- Consider adding geolocation for external endpoints
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Classification of detected network nodes."""
    
    # Internal infrastructure
    PACS_SERVER = "pacs_server"
    AI_ORCHESTRATOR = "ai_orchestrator"
    LOCAL_LLM = "local_llm"  # Port 11434 (Ollama) or similar
    WORKSTATION = "workstation"
    UNKNOWN_INTERNAL = "unknown_internal"
    
    # External services
    PUBLIC_AI_API = "public_ai_api"  # OpenAI, HuggingFace, etc.
    CLOUD_PROVIDER = "cloud_provider"  # AWS, GCP, Azure with BAA potential
    UNKNOWN_EXTERNAL = "unknown_external"


class RiskLevel(str, Enum):
    """Risk classification for detected nodes."""
    
    TRUSTED = "trusted"       # Green - Known, approved, BAA in place
    WARNING = "warning"       # Yellow - Known but needs review
    CRITICAL = "critical"     # Red - Uncontrolled, no BAA, shadow AI
    BLOCKED = "blocked"       # Grey - Isolated by admin action


class ScannerConfig(BaseModel):
    """Configuration for network scanning."""
    
    # Network scope
    target_subnets: List[str] = Field(
        default=["192.168.1.0/24"],
        description="CIDR notation subnets to scan"
    )
    
    # Port detection
    llm_ports: List[int] = Field(
        default=[11434, 8080, 8000, 3000, 5000],
        description="Ports commonly used by LLM servers (Ollama=11434)"
    )
    
    # DNS/Traffic patterns to detect (public AI endpoints)
    ai_traffic_patterns: List[str] = Field(
        default=[
            "api.openai.com",
            "huggingface.co",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
            "bedrock.*.amazonaws.com",
            "api.cohere.ai",
            "api.replicate.com",
        ],
        description="DNS patterns indicating public AI API traffic"
    )
    
    # Trusted endpoints (won't be flagged as critical)
    trusted_endpoints: List[str] = Field(
        default=[
            "*.googleapis.com",  # GCP (assume BAA if configured)
            "*.azure.com",       # Azure (assume BAA if configured)
        ],
        description="Endpoints with potential BAA coverage"
    )
    
    # Scan behavior
    timeout_seconds: int = Field(default=30, description="Per-host scan timeout")
    max_concurrent: int = Field(default=10, description="Max concurrent scans")
    
    # Mode
    use_mock: bool = Field(
        default=False,
        description="Use mock scanner instead of real network scan"
    )


class DetectedNode(BaseModel):
    """A detected network node (host/endpoint)."""
    
    id: str = Field(..., description="Unique node identifier")
    
    # Network info
    ip_address: Optional[str] = Field(None, description="IP address if internal")
    hostname: Optional[str] = Field(None, description="Hostname if resolvable")
    fqdn: Optional[str] = Field(None, description="External FQDN if applicable")
    
    # Classification
    node_type: NodeType = Field(..., description="Type of node detected")
    risk_level: RiskLevel = Field(..., description="Risk classification")
    
    # Detection details
    detected_ports: List[int] = Field(
        default_factory=list,
        description="Open ports detected"
    )
    detection_method: str = Field(
        ...,
        description="How this node was detected (port_scan, dns_query, traffic_analysis)"
    )
    
    # Risk context
    risk_reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable risk explanations"
    )
    baa_status: Optional[bool] = Field(
        None,
        description="True if BAA exists, False if no BAA, None if unknown"
    )
    
    # UI display
    display_label: str = Field(..., description="Label for network map UI")
    
    # Metadata
    first_seen: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this node was first detected"
    )
    last_seen: datetime = Field(
        default_factory=datetime.utcnow,
        description="Most recent detection"
    )
    scan_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional scan-specific metadata"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "node_ollama_192_168_1_50",
                "ip_address": "192.168.1.50",
                "hostname": "dr-smith-laptop",
                "node_type": "local_llm",
                "risk_level": "critical",
                "detected_ports": [11434],
                "detection_method": "port_scan",
                "risk_reasons": [
                    "Ollama LLM server detected on port 11434",
                    "No BAA coverage for local model",
                    "Potential uncontrolled PHI processing"
                ],
                "baa_status": False,
                "display_label": "Dr. Smith's Laptop (Ollama)"
            }
        }


class ScanTarget(BaseModel):
    """Definition of what to scan."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    
    # Scope
    subnets: List[str] = Field(
        default_factory=list,
        description="CIDR subnets to scan"
    )
    specific_hosts: List[str] = Field(
        default_factory=list,
        description="Specific IPs/hostnames to scan"
    )
    
    # Options
    include_dns_analysis: bool = Field(
        default=True,
        description="Analyze DNS queries for AI traffic patterns"
    )
    include_port_scan: bool = Field(
        default=True,
        description="Scan for LLM-related open ports"
    )
    
    # Metadata
    requested_by: Optional[str] = Field(
        None,
        description="User/system that requested the scan"
    )
    requested_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When scan was requested"
    )


class ScanResult(BaseModel):
    """Complete scan result with all detected nodes."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    
    # Timing
    started_at: datetime = Field(..., description="Scan start time")
    completed_at: datetime = Field(..., description="Scan completion time")
    duration_seconds: float = Field(..., description="Total scan duration")
    
    # Results
    nodes: List[DetectedNode] = Field(
        default_factory=list,
        description="All detected nodes"
    )
    
    # Summary counts
    total_nodes: int = Field(0, description="Total nodes detected")
    trusted_count: int = Field(0, description="Green/trusted nodes")
    warning_count: int = Field(0, description="Yellow/warning nodes")
    critical_count: int = Field(0, description="Red/critical nodes")
    blocked_count: int = Field(0, description="Grey/blocked nodes")
    
    # Scan metadata
    config_used: ScannerConfig = Field(..., description="Scanner config used")
    scanner_version: str = Field(
        default="0.1.0",
        description="Scanner version for reproducibility"
    )
    scan_type: str = Field(
        default="full",
        description="Scan type: full | quick | targeted"
    )
    
    # Errors (if any)
    errors: List[str] = Field(
        default_factory=list,
        description="Non-fatal errors during scan"
    )
    
    def compute_summary(self) -> None:
        """Recompute summary counts from nodes list."""
        self.total_nodes = len(self.nodes)
        self.trusted_count = sum(1 for n in self.nodes if n.risk_level == RiskLevel.TRUSTED)
        self.warning_count = sum(1 for n in self.nodes if n.risk_level == RiskLevel.WARNING)
        self.critical_count = sum(1 for n in self.nodes if n.risk_level == RiskLevel.CRITICAL)
        self.blocked_count = sum(1 for n in self.nodes if n.risk_level == RiskLevel.BLOCKED)
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan_20251227_143022",
                "total_nodes": 5,
                "trusted_count": 2,
                "warning_count": 1,
                "critical_count": 2,
                "blocked_count": 0
            }
        }

