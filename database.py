# database.py — SQLite helpers for Zero Day graduation project
import sqlite3
import threading
from pathlib import Path

_DB_PATH = Path(__file__).resolve().parent / "zerodaydb.sqlite"
_thread_local = threading.local()


def _new_connection():
    conn = sqlite3.connect(_DB_PATH.as_posix())
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    if getattr(_thread_local, "conn", None) is None:
        _thread_local.conn = _new_connection()
    return _thread_local.conn


def close_db():
    conn = getattr(_thread_local, "conn", None)
    if conn is not None:
        conn.close()
        _thread_local.conn = None


def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript(
        """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    description TEXT,
    technical_details TEXT,
    exploitation TEXT,
    mitigation TEXT,
    affected_systems TEXT,
    year INTEGER,
    discovered_by TEXT,
    "references" TEXT
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    year INTEGER NOT NULL,
    title TEXT NOT NULL,
    target TEXT,
    impact TEXT,
    vulnerability_type TEXT,
    description TEXT,
    severity TEXT
);

CREATE TABLE IF NOT EXISTS quiz_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    option_a TEXT,
    option_b TEXT,
    option_c TEXT,
    option_d TEXT,
    correct_answer TEXT,
    explanation TEXT,
    difficulty TEXT
);

CREATE TABLE IF NOT EXISTS quiz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score INTEGER,
    total INTEGER,
    level TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS simulation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario TEXT,
    step INTEGER,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""
    )
    db.commit()
