"""
Network Scanner Module - Phase 4.2
Detects Shadow AI infrastructure on local networks.

Real Scanner: Uses Nmap for port scanning + DNS/traffic analysis
Mock Scanner: Provides demo data without network access
Persistence: SQLite storage for scan results and isolated nodes

Source of truth: devlog/demo_build.md Phase 4.2
"""

from .models import (
    ScanTarget,
    ScanResult,
    DetectedNode,
    NodeType,
    RiskLevel,
    ScannerConfig,
)
from .network_scanner import NetworkScanner
from .mock_scanner import MockScanner
from .persistence import (
    init_db,
    save_scan_result,
    load_latest_scan_result,
    save_isolated_nodes,
    load_isolated_nodes,
    clear_isolated_nodes,
    get_db_stats,
)

__all__ = [
    "ScanTarget",
    "ScanResult",
    "DetectedNode",
    "NodeType",
    "RiskLevel",
    "ScannerConfig",
    "NetworkScanner",
    "MockScanner",
    # Persistence
    "init_db",
    "save_scan_result",
    "load_latest_scan_result",
    "save_isolated_nodes",
    "load_isolated_nodes",
    "clear_isolated_nodes",
    "get_db_stats",
]

