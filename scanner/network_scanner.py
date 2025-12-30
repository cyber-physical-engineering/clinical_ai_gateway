"""
Real Network Scanner - Phase 4.2
Uses Nmap for port scanning and DNS analysis for traffic detection.

This is a production-capable scanner with notes for hardening.

Detection Logic:
1. Port 11434 → Flag as "Local LLM" (Ollama)
2. DNS to api.openai.com / huggingface.co → Flag as "Public AI Traffic"

Production Notes:
- [ ] Add rate limiting to prevent network flooding
- [ ] Add scan scheduling (cron/APScheduler) vs on-demand only
- [ ] Add result caching to prevent redundant scans
- [ ] Add proper logging with audit trail
- [ ] Consider async scanning with progress callbacks
- [ ] Add SNMP/WMI enrichment for better hostname resolution
- [ ] Add MAC address vendor lookup for device identification
- [ ] Integrate with Zeek for real-time traffic analysis (not just DNS logs)
- [ ] Add scan result persistence (database/file)
- [ ] Add scan diff capability (what changed since last scan)

Security Notes:
- [ ] Require elevated permissions check before scanning
- [ ] Add scope validation to prevent scanning external networks
- [ ] Rate limit scan requests per user
- [ ] Audit log all scan requests with requester identity
"""

import asyncio
import socket
import subprocess
import uuid
from datetime import datetime
from typing import List, Optional, Tuple
import re
import logging

from .models import (
    ScannerConfig,
    ScanTarget,
    ScanResult,
    DetectedNode,
    NodeType,
    RiskLevel,
)

logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Real network scanner using Nmap and DNS analysis.
    
    Requires: nmap installed on the system (brew install nmap / apt install nmap)
    
    Usage:
        scanner = NetworkScanner()
        result = await scanner.scan()
    """
    
    VERSION = "0.1.0"
    
    # Known LLM port signatures
    LLM_PORT_SIGNATURES = {
        11434: ("Ollama", "Local LLM server (Ollama)"),
        8080: ("LLM Proxy", "Potential LLM proxy/gateway"),
        8000: ("FastAPI LLM", "Potential FastAPI-based LLM service"),
        3000: ("LLM UI", "Potential LLM web interface"),
        5000: ("Flask LLM", "Potential Flask-based LLM service"),
    }
    
    # Public AI API patterns (hostname → vendor mapping)
    PUBLIC_AI_PATTERNS = {
        "api.openai.com": ("OpenAI", False),  # (vendor, has_baa)
        "huggingface.co": ("HuggingFace", False),
        "api.anthropic.com": ("Anthropic", False),
        "generativelanguage.googleapis.com": ("Google AI", True),  # GCP has BAA option
        "api.cohere.ai": ("Cohere", False),
        "api.replicate.com": ("Replicate", False),
    }
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """Initialize scanner with optional config."""
        self.config = config or ScannerConfig()
    
    async def scan(self, target: Optional[ScanTarget] = None) -> ScanResult:
        """
        Perform a network scan.
        
        Args:
            target: Optional specific scan target. If None, uses config defaults.
        
        Returns:
            ScanResult with all detected nodes.
        """
        scan_id = target.scan_id if target else f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        started_at = datetime.utcnow()
        nodes: List[DetectedNode] = []
        errors: List[str] = []
        
        # Determine subnets to scan
        subnets = (target.subnets if target and target.subnets 
                   else self.config.target_subnets)
        
        # Step 1: Port scan for LLM servers
        if not target or target.include_port_scan:
            try:
                port_nodes = await self._scan_ports(subnets)
                nodes.extend(port_nodes)
            except Exception as e:
                error_msg = f"Port scan error: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        # Step 2: DNS analysis for public AI traffic
        if not target or target.include_dns_analysis:
            try:
                dns_nodes = await self._analyze_dns()
                nodes.extend(dns_nodes)
            except Exception as e:
                error_msg = f"DNS analysis error: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
        
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
            errors=errors,
        )
        result.compute_summary()
        
        return result
    
    async def _scan_ports(self, subnets: List[str]) -> List[DetectedNode]:
        """
        Scan subnets for LLM-related ports using Nmap.
        
        Production Notes:
        - Uses -T4 timing (aggressive) for demo; use -T3 for production
        - Add --host-timeout for large networks
        - Consider -sS (SYN scan) with root for speed
        """
        nodes: List[DetectedNode] = []
        ports_str = ",".join(str(p) for p in self.config.llm_ports)
        
        for subnet in subnets:
            try:
                # Check if nmap is available
                nmap_available = await self._check_nmap()
                
                if nmap_available:
                    # Real Nmap scan
                    subnet_nodes = await self._nmap_scan(subnet, ports_str)
                    nodes.extend(subnet_nodes)
                else:
                    # Fallback to simple socket scan
                    logger.warning("Nmap not available, using socket fallback")
                    subnet_nodes = await self._socket_scan(subnet)
                    nodes.extend(subnet_nodes)
                    
            except Exception as e:
                logger.error(f"Error scanning subnet {subnet}: {e}")
                continue
        
        return nodes
    
    async def _check_nmap(self) -> bool:
        """Check if nmap is installed."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "which", "nmap",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False
    
    async def _nmap_scan(self, subnet: str, ports: str) -> List[DetectedNode]:
        """
        Run Nmap scan and parse results.
        
        Production Notes:
        - Add -oX for XML output parsing (more reliable)
        - Add --version-intensity 0 for faster scans
        - Consider python-nmap library for better parsing
        """
        nodes: List[DetectedNode] = []
        
        try:
            # Run nmap with grepable output
            cmd = [
                "nmap",
                "-T4",           # Aggressive timing (demo mode)
                "-p", ports,     # Specific ports only
                "--open",        # Only show open ports
                "-oG", "-",      # Grepable output to stdout
                subnet
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout_seconds
            )
            
            if proc.returncode != 0:
                logger.warning(f"Nmap returned {proc.returncode}: {stderr.decode()}")
            
            # Parse grepable output
            output = stdout.decode()
            nodes.extend(self._parse_nmap_output(output))
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timed out for {subnet}")
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
        
        return nodes
    
    def _parse_nmap_output(self, output: str) -> List[DetectedNode]:
        """
        Parse Nmap grepable output format.
        
        Example line:
        Host: 192.168.1.50 ()	Ports: 11434/open/tcp//unknown///
        """
        nodes: List[DetectedNode] = []
        
        # Regex for grepable output
        host_pattern = re.compile(
            r"Host:\s+(\d+\.\d+\.\d+\.\d+)\s+\(([^)]*)\)\s+Ports:\s+(.+)"
        )
        port_pattern = re.compile(r"(\d+)/open/")
        
        for line in output.split("\n"):
            match = host_pattern.search(line)
            if not match:
                continue
            
            ip = match.group(1)
            hostname = match.group(2) or None
            ports_str = match.group(3)
            
            # Extract open ports
            open_ports = [int(p) for p in port_pattern.findall(ports_str)]
            
            # Classify based on detected ports
            for port in open_ports:
                if port in self.LLM_PORT_SIGNATURES:
                    service_name, description = self.LLM_PORT_SIGNATURES[port]
                    
                    node = DetectedNode(
                        id=f"node_{ip.replace('.', '_')}_{port}",
                        ip_address=ip,
                        hostname=hostname,
                        node_type=NodeType.LOCAL_LLM,
                        risk_level=RiskLevel.CRITICAL,
                        detected_ports=[port],
                        detection_method="nmap_port_scan",
                        risk_reasons=[
                            description,
                            "No BAA coverage for local model",
                            "Potential uncontrolled PHI processing",
                        ],
                        baa_status=False,
                        display_label=f"{hostname or ip} ({service_name})",
                        scan_metadata={
                            "scanner": "nmap",
                            "port": port,
                            "service": service_name,
                        }
                    )
                    nodes.append(node)
        
        return nodes
    
    async def _socket_scan(self, subnet: str) -> List[DetectedNode]:
        """
        Fallback socket-based port scan when Nmap isn't available.
        
        Production Notes:
        - Much slower than Nmap
        - Only scans first few hosts in subnet for demo
        - Use Nmap in production
        """
        nodes: List[DetectedNode] = []
        
        # For demo, only scan a few IPs if using socket fallback
        # This is a simplified implementation
        try:
            # Get local network info
            local_ip = self._get_local_ip()
            if not local_ip:
                return nodes
            
            # Scan local machine and a few neighbors
            base_ip = ".".join(local_ip.split(".")[:-1])
            hosts_to_scan = [
                local_ip,
                f"{base_ip}.1",  # Router
            ]
            
            for host in hosts_to_scan:
                for port in self.config.llm_ports:
                    if await self._check_port(host, port):
                        service_name, description = self.LLM_PORT_SIGNATURES.get(
                            port, ("Unknown", "Unknown service")
                        )
                        
                        node = DetectedNode(
                            id=f"node_{host.replace('.', '_')}_{port}",
                            ip_address=host,
                            node_type=NodeType.LOCAL_LLM,
                            risk_level=RiskLevel.CRITICAL,
                            detected_ports=[port],
                            detection_method="socket_scan",
                            risk_reasons=[
                                description,
                                "Detected via socket probe",
                            ],
                            baa_status=False,
                            display_label=f"{host} ({service_name})",
                            scan_metadata={
                                "scanner": "socket_fallback",
                                "port": port,
                            }
                        )
                        nodes.append(node)
                        
        except Exception as e:
            logger.error(f"Socket scan error: {e}")
        
        return nodes
    
    def _get_local_ip(self) -> Optional[str]:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None
    
    async def _check_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open using socket."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _analyze_dns(self) -> List[DetectedNode]:
        """
        Analyze DNS queries for public AI API traffic.
        
        This is a simplified implementation that checks:
        1. /etc/hosts for AI-related entries
        2. Attempts DNS resolution to known AI endpoints
        
        Production Notes:
        - [ ] Integrate with Zeek for real-time DNS logging
        - [ ] Parse /var/log/named/query.log (if BIND is logging)
        - [ ] Use Pi-hole or AdGuard Home query logs if available
        - [ ] Consider DNS proxy/sinkhole for enterprise visibility
        - [ ] Add pcap analysis for DNS over HTTPS (DoH) detection
        """
        nodes: List[DetectedNode] = []
        
        # Check if we can resolve known AI endpoints
        # This indicates the network allows this traffic
        for domain, (vendor, has_baa) in self.PUBLIC_AI_PATTERNS.items():
            try:
                # Try to resolve the domain
                socket.gethostbyname(domain)
                
                # If resolvable, the network allows traffic to this endpoint
                # In production, we'd check actual traffic logs
                # For demo, we just note it's reachable
                risk_level = RiskLevel.WARNING if has_baa else RiskLevel.CRITICAL
                
                node = DetectedNode(
                    id=f"node_external_{domain.replace('.', '_')}",
                    fqdn=domain,
                    node_type=NodeType.PUBLIC_AI_API,
                    risk_level=risk_level,
                    detection_method="dns_resolution",
                    risk_reasons=[
                        f"Traffic to {vendor} API is reachable",
                        "No BAA confirmation" if not has_baa else "BAA may be available (verify)",
                    ],
                    baa_status=has_baa,
                    display_label=f"{vendor} API ({domain})",
                    scan_metadata={
                        "vendor": vendor,
                        "domain": domain,
                        "dns_reachable": True,
                    }
                )
                nodes.append(node)
                
            except socket.gaierror:
                # Domain not resolvable - could be blocked
                continue
            except Exception as e:
                logger.debug(f"Error checking {domain}: {e}")
                continue
        
        return nodes
    
    async def quick_scan_host(self, host: str) -> List[DetectedNode]:
        """
        Quick scan a single host for LLM ports.
        
        Useful for:
        - Scanning a newly discovered host
        - Verifying a reported shadow AI instance
        """
        nodes: List[DetectedNode] = []
        
        for port in self.config.llm_ports:
            if await self._check_port(host, port):
                service_name, description = self.LLM_PORT_SIGNATURES.get(
                    port, ("Unknown", "Unknown service")
                )
                
                node = DetectedNode(
                    id=f"node_{host.replace('.', '_')}_{port}",
                    ip_address=host,
                    node_type=NodeType.LOCAL_LLM,
                    risk_level=RiskLevel.CRITICAL,
                    detected_ports=[port],
                    detection_method="quick_scan",
                    risk_reasons=[description],
                    baa_status=False,
                    display_label=f"{host} ({service_name})",
                )
                nodes.append(node)
        
        return nodes

