#!/usr/bin/env python3
"""
Scanner Test Script - Phase 4.2
Tests both real and mock scanners locally.

Run: python -m scanner.test_scanner
From: gateway/ directory
"""

import asyncio
import sys
from pathlib import Path

# Ensure scanner module is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import (
    NetworkScanner,
    MockScanner,
    ScannerConfig,
    ScanTarget,
    ScanResult,
    DetectedNode,
    NodeType,
    RiskLevel,
)


def print_header(title: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_node(node: DetectedNode) -> None:
    """Print a formatted node summary."""
    risk_emoji = {
        RiskLevel.TRUSTED: "🟢",
        RiskLevel.WARNING: "🟡",
        RiskLevel.CRITICAL: "🔴",
        RiskLevel.BLOCKED: "⬜",
    }
    emoji = risk_emoji.get(node.risk_level, "❓")
    
    print(f"\n  {emoji} {node.display_label}")
    print(f"     ID: {node.id}")
    print(f"     Type: {node.node_type.value}")
    print(f"     Risk: {node.risk_level.value}")
    if node.ip_address:
        print(f"     IP: {node.ip_address}")
    if node.fqdn:
        print(f"     FQDN: {node.fqdn}")
    if node.detected_ports:
        print(f"     Ports: {node.detected_ports}")
    if node.risk_reasons:
        print(f"     Reasons:")
        for reason in node.risk_reasons:
            print(f"       - {reason}")


def print_result(result: ScanResult) -> None:
    """Print a formatted scan result."""
    print(f"\n  Scan ID: {result.scan_id}")
    print(f"  Duration: {result.duration_seconds:.2f}s")
    print(f"  Scanner: {result.scanner_version}")
    print(f"\n  Summary:")
    print(f"    🟢 Trusted:  {result.trusted_count}")
    print(f"    🟡 Warning:  {result.warning_count}")
    print(f"    🔴 Critical: {result.critical_count}")
    print(f"    ⬜ Blocked:  {result.blocked_count}")
    print(f"    📊 Total:    {result.total_nodes}")
    
    if result.errors:
        print(f"\n  ⚠️  Errors:")
        for error in result.errors:
            print(f"    - {error}")
    
    print("\n  Detected Nodes:")
    for node in result.nodes:
        print_node(node)


async def test_mock_scanner() -> bool:
    """Test the mock scanner."""
    print_header("Testing Mock Scanner")
    
    try:
        scanner = MockScanner()
        result = await scanner.scan()
        print_result(result)
        
        # Validate expected nodes
        assert result.total_nodes == 9, f"Expected 9 nodes, got {result.total_nodes}"
        assert result.trusted_count == 3, f"Expected 3 trusted, got {result.trusted_count}"
        assert result.warning_count == 2, f"Expected 2 warning, got {result.warning_count}"
        assert result.critical_count == 4, f"Expected 4 critical, got {result.critical_count}"
        
        print("\n  ✅ Mock scanner test PASSED")
        return True
        
    except Exception as e:
        print(f"\n  ❌ Mock scanner test FAILED: {e}")
        return False


async def test_real_scanner_local() -> bool:
    """Test the real scanner on localhost only."""
    print_header("Testing Real Scanner (localhost only)")
    
    try:
        # Configure for minimal local scan
        config = ScannerConfig(
            target_subnets=["127.0.0.1/32"],  # Only localhost
            llm_ports=[11434, 8080, 8000],
            timeout_seconds=10,
        )
        
        scanner = NetworkScanner(config)
        
        # Check if nmap is available
        nmap_available = await scanner._check_nmap()
        print(f"\n  Nmap available: {nmap_available}")
        
        # Run scan
        result = await scanner.scan()
        print_result(result)
        
        # Validate scan completed
        assert result.scan_id is not None
        assert result.duration_seconds > 0
        
        print("\n  ✅ Real scanner test PASSED")
        return True
        
    except Exception as e:
        print(f"\n  ❌ Real scanner test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_quick_scan() -> bool:
    """Test quick scan of a single host."""
    print_header("Testing Quick Scan")
    
    try:
        scanner = MockScanner()
        nodes = await scanner.quick_scan_host("192.168.1.100")
        
        print(f"\n  Quick scan returned {len(nodes)} nodes:")
        for node in nodes:
            print_node(node)
        
        assert len(nodes) > 0, "Expected at least one node from quick scan"
        
        print("\n  ✅ Quick scan test PASSED")
        return True
        
    except Exception as e:
        print(f"\n  ❌ Quick scan test FAILED: {e}")
        return False


async def test_isolation() -> bool:
    """Test node isolation functionality."""
    print_header("Testing Node Isolation")
    
    try:
        scanner = MockScanner()
        
        # Get original nodes
        nodes = scanner.get_isolated_view([])
        critical_before = sum(1 for n in nodes if n.risk_level == RiskLevel.CRITICAL)
        print(f"\n  Before isolation: {critical_before} critical nodes")
        
        # Isolate the critical nodes
        critical_ids = [n.id for n in nodes if n.risk_level == RiskLevel.CRITICAL]
        nodes = scanner.get_isolated_view(critical_ids)
        
        blocked_after = sum(1 for n in nodes if n.risk_level == RiskLevel.BLOCKED)
        critical_after = sum(1 for n in nodes if n.risk_level == RiskLevel.CRITICAL)
        
        print(f"  After isolation: {blocked_after} blocked, {critical_after} critical")
        
        assert blocked_after == critical_before, "Isolation should have blocked all critical nodes"
        assert critical_after == 0, "No critical nodes should remain after isolation"
        
        print("\n  ✅ Isolation test PASSED")
        return True
        
    except Exception as e:
        print(f"\n  ❌ Isolation test FAILED: {e}")
        return False


async def test_dns_analysis() -> bool:
    """Test DNS analysis for public AI endpoints."""
    print_header("Testing DNS Analysis")
    
    try:
        config = ScannerConfig(
            target_subnets=[],  # No port scanning
        )
        
        scanner = NetworkScanner(config)
        nodes = await scanner._analyze_dns()
        
        print(f"\n  DNS analysis found {len(nodes)} reachable AI endpoints:")
        for node in nodes:
            print_node(node)
        
        # Note: We don't assert on count since it depends on network
        print("\n  ✅ DNS analysis test PASSED")
        return True
        
    except Exception as e:
        print(f"\n  ❌ DNS analysis test FAILED: {e}")
        return False


async def main():
    """Run all tests."""
    print("\n" + "🔍 " * 20)
    print("   AI TrustStack - Network Scanner Tests")
    print("   Phase 4.2: Shadow AI Detection")
    print("🔍 " * 20)
    
    results = []
    
    # Run tests
    results.append(("Mock Scanner", await test_mock_scanner()))
    results.append(("Quick Scan", await test_quick_scan()))
    results.append(("Isolation", await test_isolation()))
    results.append(("DNS Analysis", await test_dns_analysis()))
    results.append(("Real Scanner (local)", await test_real_scanner_local()))
    
    # Summary
    print_header("Test Summary")
    
    passed = sum(1 for _, r in results if r)
    failed = sum(1 for _, r in results if not r)
    
    for name, result in results:
        emoji = "✅" if result else "❌"
        print(f"  {emoji} {name}")
    
    print(f"\n  Total: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n  🎉 All tests passed!")
        return 0
    else:
        print(f"\n  ⚠️  {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

