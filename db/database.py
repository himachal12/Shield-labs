"""
db/database.py

SQLite storage for scan results.
One scan = one row in `scans` table.
Each finding = one row in `findings` table.
"""

import sqlite3
import json
import logging
from datetime import datetime

logger = logging.getLogger("shieldlabs.database")

DB_PATH = "shieldlabs.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates tables if they don't exist. Safe to call on every startup."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT NOT NULL,
            scan_type   TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            total_files INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            status      TEXT DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL,
            vuln_type    TEXT NOT NULL,
            file         TEXT NOT NULL,
            line         INTEGER,
            code_snippet TEXT,
            confidence   REAL,
            reason       TEXT,
            llm_verdict  TEXT,
            llm_explanation TEXT,
            fix_code     TEXT,
            fix_explanation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized")


def create_scan(source: str, scan_type: str) -> int:
    """Creates a new scan record and returns its ID."""
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO scans (source, scan_type, started_at, status) VALUES (?, ?, ?, ?)",
        (source, scan_type, datetime.utcnow().isoformat(), "running")
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def save_findings(scan_id: int, findings: list[dict]):
    """Saves all findings for a scan."""
    conn = get_connection()
    for f in findings:
        conn.execute("""
            INSERT INTO findings
            (scan_id, vuln_type, file, line, code_snippet, confidence,
             reason, llm_verdict, llm_explanation, fix_code, fix_explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            f.get("vuln_type"), f.get("file"), f.get("line"),
            f.get("code_snippet"), f.get("confidence"), f.get("reason"),
            f.get("llm_verdict"), f.get("llm_explanation"),
            f.get("fix_code"), f.get("fix_explanation")
        ))
    conn.commit()
    conn.close()


def finish_scan(scan_id: int, total_files: int, total_findings: int):
    """Marks a scan as complete."""
    conn = get_connection()
    conn.execute("""
        UPDATE scans
        SET status='complete', finished_at=?, total_files=?, total_findings=?
        WHERE id=?
    """, (datetime.utcnow().isoformat(), total_files, total_findings, scan_id))
    conn.commit()
    conn.close()


def get_scan_with_findings(scan_id: int) -> dict:
    """Returns a scan and all its findings as a dict."""
    conn = get_connection()
    scan = dict(conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
    findings = [dict(r) for r in conn.execute(
        "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
    ).fetchall()]
    conn.close()
    return {"scan": scan, "findings": findings}