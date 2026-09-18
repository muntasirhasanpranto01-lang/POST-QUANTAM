from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from .config import DB_PATH

MIGRATIONS = {
1: """
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator','auditor','viewer')), disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE keys (id TEXT PRIMARY KEY, purpose TEXT NOT NULL, algorithm TEXT NOT NULL, public_key BLOB NOT NULL, encrypted_private_key BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','retired','revoked','destroyed')), created_at TEXT NOT NULL, rotated_at TEXT, revoked_at TEXT, destroyed_at TEXT);
CREATE TABLE certificates (id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(id), subject TEXT NOT NULL, serial_number TEXT NOT NULL UNIQUE, pem TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','rotated','revoked')), created_at TEXT NOT NULL, rotated_from TEXT REFERENCES certificates(id), revoked_at TEXT);
CREATE TABLE delegations (id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(id), requester TEXT NOT NULL, purpose TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active');
CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, actor TEXT, subject_id TEXT, details_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX cert_state_idx ON certificates(state); CREATE INDEX audit_created_idx ON audit_events(created_at);
""",
2: """
ALTER TABLE keys ADD COLUMN destruction_reason TEXT;
CREATE INDEX keys_state_idx ON keys(state);
""",
}

@contextmanager
def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def migrate():
    with connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        current = int(row[0]) if row else 0
        for version in sorted(MIGRATIONS):
            if version > current:
                conn.executescript(MIGRATIONS[version])
                if row: conn.execute("UPDATE schema_version SET version=?", (version,))
                else: conn.execute("INSERT INTO schema_version(version) VALUES(?)", (version,))
                current = version
