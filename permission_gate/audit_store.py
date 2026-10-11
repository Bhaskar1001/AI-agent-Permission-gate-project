"""SQLite audit log with a SHA-256 hash chain: editing or deleting a past row is detectable."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from typing import Optional

from .models import AuditEntry

GENESIS = "0" * 64


def _hash(prev: str, payload: str) -> str:
    return hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()


class AuditStore:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts TEXT NOT NULL, agent TEXT, tool TEXT, verdict TEXT, final TEXT,
                   rule TEXT, request_id TEXT,
                   payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)""")
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def head(self) -> str:
        """Latest chain hash. Anchor it externally to also detect tail truncation."""
        row = self._db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, entry: AuditEntry) -> int:
        payload = entry.model_dump_json()
        with self._lock:
            prev = self.head()
            cur = self._db.execute(
                "INSERT INTO audit (ts, agent, tool, verdict, final, rule, request_id,"
                " payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (entry.timestamp.isoformat(), entry.call.agent, entry.call.tool,
                 entry.verdict.value, entry.final, entry.rule, entry.request_id,
                 payload, prev, _hash(prev, payload)))
            self._db.commit()
            return cur.lastrowid

    def entries(self, limit: int = 100, verdict: Optional[str] = None,
                final: Optional[str] = None, agent: Optional[str] = None) -> list[dict]:
        """Newest first."""
        where, params = [], []
        for col, val in (("verdict", verdict), ("final", final), ("agent", agent)):
            if val:
                where.append(f"{col} = ?")
                params.append(val)
        sql = "SELECT id, payload, hash FROM audit"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._db.execute(sql, (*params, limit)).fetchall()
        return [{"id": i, **json.loads(p), "hash": h} for i, p, h in rows]

    def count(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]

    def verify(self) -> tuple[bool, Optional[int]]:
        """Recompute the chain. Returns (ok, id of the first bad row)."""
        prev = GENESIS
        with self._lock:
            rows = self._db.execute(
                "SELECT id, payload, prev_hash, hash FROM audit ORDER BY id").fetchall()
        for row_id, payload, prev_hash, h in rows:
            if prev_hash != prev or _hash(prev, payload) != h:
                return False, row_id
            prev = h
        return True, None
