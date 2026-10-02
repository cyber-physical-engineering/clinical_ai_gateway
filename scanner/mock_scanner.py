"""
Mock Network Scanner - Phase 4.2
Provides realistic demo data without requiring actual network scanning.

This scanner returns the same data structure as the real scanner,
allowing the demo to work without Nmap or network access.

The mock data matches the demo narrative:
- PACS Server (Trusted/Green)
- AI Orchestrator (Trusted/Green) 
- Local Tuning Model (Warning/Yellow)
- Dr. Smith's Laptop with Ollama (Critical/Red)
- Unknown Cloud API - HuggingFace (Critical/Red)

Usage:
    scanner = MockScanner()
    result = await scanner.scan()
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
import random

from .models import (
    ScannerConfig,
    ScanTarget,
    ScanResult,
    DetectedNode,
    NodeType,
    RiskLevel,
)


class MockScanner:
    """
    Mock scanner for demo purposes.
    
    Returns realistic-looking scan results that match the demo UI's
    network map visualization.
    """
    
    VERSION = "0.1.0-mock"
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """Initialize mock scanner."""
        self.config = config or ScannerConfig(use_mock=True)
    
    async def scan(self, target: Optional[ScanTarget] = None) -> ScanResult:
        """
        Return mock scan results.
        
        Simulates a 1-2 second scan delay for realism.
        """
        scan_id = (target.scan_id if target 
                   else f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_mock")
        started_at = datetime.utcnow()
        
        # Simulate scan delay (feels more realistic in demo)
        await asyncio.sleep(random.uniform(1.0, 2.0))
        
        # Get mock nodes
        nodes = self._get_demo_nodes()
        
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()
        
        result = ScanResult(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            nodes=nodes,
            config_used=self.config,
            scanner_version=self.VERSION,
            scan_type="mock",
            errors=[],
        )
        result.compute_summary()
        
        return result
    
    def _get_demo_nodes(self) -> List[DetectedNode]:
        """
        Return the demo network nodes.
        
        These match the demo UI's network map from Phase 1.1:
        - Node A: "PACS Server" (Green/Trusted)
        - Node B: "AI Orchestrator" (Green/Trusted) 
        - Node C: "Local Tuning Model" (Yellow/Warning)
        - Node D: "Dr. Smith's Laptop" (Red/Critical) - Ollama on 11434
        - Node E: "Unknown Cloud API" (Red/Critical) - HuggingFace traffic
        - Node F: "Radiology Workstation 3" (Green/Trusted)
        - Node G: "Research Server" (Yellow/Warning)
        - Node H: "Guest WiFi Laptop" (Red/Critical)
        - Node I: "Shadow API Proxy" (Red/Critical)
        """
        now = datetime.utcnow()
        
        return [
            # Node A: PACS Server (Trusted)
            DetectedNode(
                id="node_pacs_server",
                ip_address="192.168.1.10",
                hostname="pacs-primary",
                fqdn="pacs-primary.hospital.local",
                node_type=NodeType.PACS_SERVER,
                risk_level=RiskLevel.TRUSTED,
                detected_ports=[104, 4242],  # DICOM ports
                detection_method="port_scan",
                risk_reasons=[],
                baa_status=True,
                display_label="PACS Server",
                first_seen=now - timedelta(days=30),
                last_seen=now,
                scan_metadata={
                    "vendor": "Internal",
                    "dicom_compliant": True,
                    "encrypted": True,
                }
            ),
            
            # Node B: AI Orchestrator (trusted; the demo orchestrator)
            DetectedNode(
                id="node_ai_orchestrator",
                ip_address="192.168.1.20",
                hostname="ai-gateway-01",
                fqdn="ai-gateway-01.hospital.local",
                node_type=NodeType.AI_ORCHESTRATOR,
                risk_level=RiskLevel.TRUSTED,
                detected_ports=[8001, 443],
                detection_method="port_scan",
                risk_reasons=[],
                baa_status=True,
                display_label="AI Orchestrator (demo)",
                first_seen=now - timedelta(days=7),
                last_seen=now,
                scan_metadata={
                    "vendor": "Demo",
                    "version": "0.1.0",
                    "gateway_active": True,
                }
            ),
            
            # Node C: Local Tuning Model (Warning - needs review)
            DetectedNode(
                id="node_local_tuning",
                ip_address="192.168.1.21",
                hostname="ml-training-01",
                fqdn="ml-training-01.hospital.local",
                node_type=NodeType.LOCAL_LLM,
                risk_level=RiskLevel.WARNING,
                detected_ports=[8080, 5000],
                detection_method="port_scan",
                risk_reasons=[
                    "Local ML training server detected",
                    "Attached to AI Orchestrator (controlled)",
                    "Needs formal BAA documentation review",
                ],
                baa_status=None,  # Unknown - needs verification
                display_label="Local Tuning Model",
                first_seen=now - timedelta(days=14),
                last_seen=now,
                scan_metadata={
                    "vendor": "Internal",
                    "purpose": "Model fine-tuning",
                    "attached_to": "ai-gateway-01",
                }
            ),
            
            # Node D: Dr. Smith's Laptop (CRITICAL - Shadow AI!)
            DetectedNode(
                id="node_dr_smith_laptop",
                ip_address="192.168.1.50",
                hostname="DR-SMITH-MBP",
                node_type=NodeType.LOCAL_LLM,
                risk_level=RiskLevel.CRITICAL,
                detected_ports=[11434],  # Ollama!
                detection_method="port_scan",
                risk_reasons=[
                    "Ollama LLM server detected on port 11434",
                    "No BAA coverage for local model",
                    "Potential uncontrolled PHI processing",
                    "Not connected to AI Gateway",
                ],
                baa_status=False,
                display_label="Dr. Smith's Laptop (Ollama)",
                first_seen=now - timedelta(hours=6),
                last_seen=now,
                scan_metadata={
                    "vendor": "Ollama",
                    "port": 11434,
                    "shadow_ai": True,
                    "risk": "PHI exposure via uncontrolled LLM",
                }
            ),
            
            # Node E: Unknown Cloud API (CRITICAL - No BAA!)
            DetectedNode(
                id="node_huggingface_api",
                fqdn="huggingface.co",
                node_type=NodeType.PUBLIC_AI_API,
                risk_level=RiskLevel.CRITICAL,
                detected_ports=[443],
                detection_method="dns_analysis",
                risk_reasons=[
                    "Traffic to huggingface.co detected",
                    "No BAA with HuggingFace",
                    "Public model - PHI exposure risk",
                ],
                baa_status=False,
                display_label="Unknown Cloud API (HuggingFace)",
                first_seen=now - timedelta(hours=2),
                last_seen=now,
                scan_metadata={
                    "vendor": "HuggingFace",
                    "domain": "huggingface.co",
                    "traffic_detected": True,
                    "bytes_transferred": 245000,
                }
            ),

            # Node F: Radiology Workstation 3 (Trusted)
            DetectedNode(
                id="node_rad_workstation_3",
                ip_address="192.168.1.15",
                hostname="rad-workstation-03",
                fqdn="rad-ws-03.hospital.local",
                node_type=NodeType.WORKSTATION,
                risk_level=RiskLevel.TRUSTED,
                detected_ports=[445, 3389],
                detection_method="port_scan",
                risk_reasons=[],
                baa_status=True,
                display_label="Radiology Workstation 3",
                first_seen=now - timedelta(days=60),
                last_seen=now,
                scan_metadata={
                    "vendor": "Internal",
                    "os": "Windows 11 Enterprise",
                    "patch_level": "Latest",
                }
            ),

            # Node G: Research Server (Warning)
            DetectedNode(
                id="node_research_server",
                ip_address="192.168.1.25",
                hostname="research-lab-01",
                node_type=NodeType.UNKNOWN_INTERNAL,
                risk_level=RiskLevel.WARNING,
                detected_ports=[8888, 22], # Jupyter Notebook
                detection_method="port_scan",
                risk_reasons=[
                    "Jupyter Notebook detected on port 8888",
                    "High data egress detected",
                    "Unregistered research device"
                ],
                baa_status=None,
                display_label="Research Server (Jupyter)",
                first_seen=now - timedelta(hours=12),
                last_seen=now,
                scan_metadata={
                    "service": "Jupyter",
                    "owner": "Research Dept",
                }
            ),

            # Node H: Guest WiFi Laptop (Critical)
            DetectedNode(
                id="node_guest_laptop",
                ip_address="10.0.0.45",
                hostname="unknown-guest-host",
                node_type=NodeType.UNKNOWN_INTERNAL,
                risk_level=RiskLevel.CRITICAL,
                detected_ports=[],
                detection_method="traffic_analysis",
                risk_reasons=[
                    "Device on Guest WiFi attempting to access Internal PACS",
                    "Port scanning behavior detected",
                    "Unauthorized network segment crossing"
                ],
                baa_status=False,
                display_label="Guest WiFi Laptop",
                first_seen=now - timedelta(minutes=15),
                last_seen=now,
                scan_metadata={
                    "network": "Guest-WiFi",
                    "mac_vendor": "Apple",
                }
            ),

            # Node I: Shadow API Proxy (Critical)
            DetectedNode(
                id="node_shadow_proxy",
                fqdn="proxy.shadow-api.com",
                node_type=NodeType.PUBLIC_AI_API,
                risk_level=RiskLevel.CRITICAL,
                detected_ports=[443, 80],
                detection_method="dns_analysis",
                risk_reasons=[
                    "Known shadow API proxy domain detected",
                    "Bypassing corporate firewall rules",
                    "Potential data exfiltration channel"
                ],
                baa_status=False,
                display_label="Shadow API Proxy",
                first_seen=now - timedelta(days=1),
                last_seen=now,
                scan_metadata={
                    "domain": "shadow-api.com",
                    "reputation": "Poor",
                }
            ),
        ]
    
    async def quick_scan_host(self, host: str) -> List[DetectedNode]:
        """
        Mock quick scan for a single host.
        
        Returns a mock critical node if the host looks like
        it could be a shadow AI instance.
        """
        await asyncio.sleep(0.5)  # Simulate scan delay
        
        # For demo, return a critical node for any scanned host
        return [
            DetectedNode(
                id=f"node_quick_{host.replace('.', '_')}",
                ip_address=host,
                node_type=NodeType.LOCAL_LLM,
                risk_level=RiskLevel.CRITICAL,
                detected_ports=[11434],
                detection_method="quick_scan_mock",
                risk_reasons=[
                    "Potential LLM server detected",
                    "Requires investigation",
                ],
                baa_status=None,
                display_label=f"Unknown Host ({host})",
            )
        ]
    
    def get_isolated_view(self, isolated_node_ids: List[str]) -> List[DetectedNode]:
        """
        Return nodes with specified IDs marked as BLOCKED.
        
        Used for the demo's "Isolate" button functionality.
        """
        nodes = self._get_demo_nodes()
        
        for node in nodes:
            if node.id in isolated_node_ids:
                node.risk_level = RiskLevel.BLOCKED
                node.risk_reasons = ["ISOLATED by administrator action"]
        
        return nodes


# Convenience function to get scanner based on config
def get_scanner(config: Optional[ScannerConfig] = None):
    """
    Factory function to get the appropriate scanner.
    
    Returns MockScanner if use_mock=True, otherwise NetworkScanner.
    """
    from .network_scanner import NetworkScanner
    
    cfg = config or ScannerConfig()
    
    if cfg.use_mock:
        return MockScanner(cfg)
    else:
        return NetworkScanner(cfg)

