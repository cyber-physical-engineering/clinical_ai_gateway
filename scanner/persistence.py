"""
Scanner Persistence - SQLite storage for scan results and isolation state.

This module provides persistence for:
- Last scan result (so network map survives restart)
- Isolated node IDs (so isolation actions persist)

The database is stored at:
  scanner/scanner_data.db (under the repository root)

Production Notes:
- [ ] Consider PostgreSQL for production deployment
- [ ] Add migration strategy for schema changes
- [ ] Add data retention policy (auto-delete old scans)
- [ ] Add encryption at rest for PHI considerations
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging

from .models import (
    ScanResult,
    DetectedNode,
    ScannerConfig,
    NodeType,
    RiskLevel,
)

logger = logging.getLogger(__name__)

# Database location (relative to this file)
DB_PATH = Path(__file__).parent / "scanner_data.db"


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory for dict-like access."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initialize the database schema.
    
    Creates tables if they don't exist.
    Safe to call multiple times.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Table for storing scan results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                scanner_version TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                total_nodes INTEGER NOT NULL,
                trusted_count INTEGER NOT NULL,
                warning_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                blocked_count INTEGER NOT NULL,
                config_json TEXT NOT NULL,
                errors_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                is_latest INTEGER DEFAULT 0
            )
        """)
        
        # Table for storing detected nodes (linked to scan)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detected_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                ip_address TEXT,
                hostname TEXT,
                fqdn TEXT,
                node_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                detected_ports_json TEXT NOT NULL,
                detection_method TEXT NOT NULL,
                risk_reasons_json TEXT NOT NULL,
                baa_status INTEGER,
                display_label TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                scan_metadata_json TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id)
            )
        """)
        
        # Table for tracking isolated nodes (persists across scans)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS isolated_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT UNIQUE NOT NULL,
                isolated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                isolated_by TEXT DEFAULT 'admin'
            )
        """)
        
        # Index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_nodes_scan_id 
            ON detected_nodes(scan_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_latest 
            ON scan_results(is_latest)
        """)
        
        conn.commit()
        logger.info(f"Database initialized at {DB_PATH}")
        
    finally:
        conn.close()


def _node_to_dict(node: DetectedNode) -> Dict[str, Any]:
    """Convert DetectedNode to a dictionary for storage."""
    return {
        "node_id": node.id,
        "ip_address": node.ip_address,
        "hostname": node.hostname,
        "fqdn": node.fqdn,
        "node_type": node.node_type.value if isinstance(node.node_type, NodeType) else node.node_type,
        "risk_level": node.risk_level.value if isinstance(node.risk_level, RiskLevel) else node.risk_level,
        "detected_ports_json": json.dumps(node.detected_ports),
        "detection_method": node.detection_method,
        "risk_reasons_json": json.dumps(node.risk_reasons),
        "baa_status": 1 if node.baa_status is True else (0 if node.baa_status is False else None),
        "display_label": node.display_label,
        "first_seen": node.first_seen.isoformat() if node.first_seen else datetime.utcnow().isoformat(),
        "last_seen": node.last_seen.isoformat() if node.last_seen else datetime.utcnow().isoformat(),
        "scan_metadata_json": json.dumps(node.scan_metadata),
    }


def _dict_to_node(row: sqlite3.Row) -> DetectedNode:
    """Convert a database row to DetectedNode."""
    baa = row["baa_status"]
    baa_status = True if baa == 1 else (False if baa == 0 else None)
    
    return DetectedNode(
        id=row["node_id"],
        ip_address=row["ip_address"],
        hostname=row["hostname"],
        fqdn=row["fqdn"],
        node_type=NodeType(row["node_type"]),
        risk_level=RiskLevel(row["risk_level"]),
        detected_ports=json.loads(row["detected_ports_json"]),
        detection_method=row["detection_method"],
        risk_reasons=json.loads(row["risk_reasons_json"]),
        baa_status=baa_status,
        display_label=row["display_label"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        scan_metadata=json.loads(row["scan_metadata_json"]),
    )


def save_scan_result(result: ScanResult) -> None:
    """
    Save a scan result to the database.
    
    Marks this scan as 'latest' and unmarks any previous latest.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Unmark previous latest
        cursor.execute("UPDATE scan_results SET is_latest = 0 WHERE is_latest = 1")
        
        # Insert scan result
        cursor.execute("""
            INSERT OR REPLACE INTO scan_results (
                scan_id, started_at, completed_at, duration_seconds,
                scanner_version, scan_type, total_nodes, trusted_count,
                warning_count, critical_count, blocked_count,
                config_json, errors_json, is_latest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            result.scan_id,
            result.started_at.isoformat() if result.started_at else datetime.utcnow().isoformat(),
            result.completed_at.isoformat() if result.completed_at else datetime.utcnow().isoformat(),
            result.duration_seconds,
            result.scanner_version,
            result.scan_type,
            result.total_nodes,
            result.trusted_count,
            result.warning_count,
            result.critical_count,
            result.blocked_count,
            json.dumps(result.config_used.model_dump() if result.config_used else {}),
            json.dumps(result.errors),
        ))
        
        # Delete old nodes for this scan (in case of re-run)
        cursor.execute("DELETE FROM detected_nodes WHERE scan_id = ?", (result.scan_id,))
        
        # Insert nodes
        for node in result.nodes:
            node_dict = _node_to_dict(node)
            cursor.execute("""
                INSERT INTO detected_nodes (
                    scan_id, node_id, ip_address, hostname, fqdn,
                    node_type, risk_level, detected_ports_json, detection_method,
                    risk_reasons_json, baa_status, display_label,
                    first_seen, last_seen, scan_metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id,
                node_dict["node_id"],
                node_dict["ip_address"],
                node_dict["hostname"],
                node_dict["fqdn"],
                node_dict["node_type"],
                node_dict["risk_level"],
                node_dict["detected_ports_json"],
                node_dict["detection_method"],
                node_dict["risk_reasons_json"],
                node_dict["baa_status"],
                node_dict["display_label"],
                node_dict["first_seen"],
                node_dict["last_seen"],
                node_dict["scan_metadata_json"],
            ))
        
        conn.commit()
        logger.info(f"Saved scan result {result.scan_id} with {len(result.nodes)} nodes")
        
    finally:
        conn.close()


def load_latest_scan_result() -> Optional[ScanResult]:
    """
    Load the most recent scan result from the database.
    
    Returns None if no scans have been saved.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Get latest scan
        cursor.execute("""
            SELECT * FROM scan_results WHERE is_latest = 1 LIMIT 1
        """)
        row = cursor.fetchone()
        
        if not row:
            logger.info("No saved scan results found")
            return None
        
        # Get nodes for this scan
        cursor.execute("""
            SELECT * FROM detected_nodes WHERE scan_id = ?
        """, (row["scan_id"],))
        node_rows = cursor.fetchall()
        
        nodes = [_dict_to_node(nr) for nr in node_rows]
        
        # Reconstruct ScanResult
        config_data = json.loads(row["config_json"])
        config = ScannerConfig(**config_data) if config_data else ScannerConfig()
        
        result = ScanResult(
            scan_id=row["scan_id"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]),
            duration_seconds=row["duration_seconds"],
            nodes=nodes,
            config_used=config,
            scanner_version=row["scanner_version"],
            scan_type=row["scan_type"],
            errors=json.loads(row["errors_json"]),
        )
        result.compute_summary()
        
        logger.info(f"Loaded scan result {result.scan_id} with {len(nodes)} nodes")
        return result
        
    finally:
        conn.close()


def save_isolated_nodes(node_ids: List[str]) -> None:
    """
    Save the list of isolated node IDs.
    
    Merges with existing isolations (additive).
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        for node_id in node_ids:
            cursor.execute("""
                INSERT OR IGNORE INTO isolated_nodes (node_id) VALUES (?)
            """, (node_id,))
        
        conn.commit()
        logger.info(f"Saved {len(node_ids)} isolated nodes")
        
    finally:
        conn.close()


def load_isolated_nodes() -> List[str]:
    """
    Load the list of isolated node IDs from the database.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT node_id FROM isolated_nodes")
        rows = cursor.fetchall()
        
        node_ids = [row["node_id"] for row in rows]
        logger.info(f"Loaded {len(node_ids)} isolated nodes")
        return node_ids
        
    finally:
        conn.close()


def clear_isolated_nodes() -> None:
    """Clear all isolated node records (used by reset)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM isolated_nodes")
        conn.commit()
        logger.info("Cleared all isolated nodes")
        
    finally:
        conn.close()


def remove_isolated_node(node_id: str) -> None:
    """Remove a specific node from the isolated list."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM isolated_nodes WHERE node_id = ?", (node_id,))
        conn.commit()
        logger.info(f"Removed isolated node: {node_id}")
        
    finally:
        conn.close()


def get_db_stats() -> Dict[str, Any]:
    """Get database statistics for debugging/monitoring."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM scan_results")
        total_scans = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM detected_nodes")
        total_nodes = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM isolated_nodes")
        isolated_count = cursor.fetchone()["count"]
        
        return {
            "db_path": str(DB_PATH),
            "total_scans": total_scans,
            "total_nodes": total_nodes,
            "isolated_count": isolated_count,
            "db_exists": DB_PATH.exists(),
            "db_size_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
        }
        
    finally:
        conn.close()

