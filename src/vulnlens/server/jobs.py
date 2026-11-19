"""Persistent async job store (sqlite) for /v1/workflow/async."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class JobStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, status TEXT, created REAL,
                         updated REAL, input TEXT, output TEXT, error TEXT)""")
            # jobs that were running when the server died can't be resumed in-process; mark them
            c.execute("UPDATE jobs SET status='interrupted', updated=? WHERE status IN ('submitted','running')",
                      (time.time(),))

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30)

    def create(self, payload: dict, job_id: str | None = None) -> str:
        job_id = job_id or uuid.uuid4().hex
        now = time.time()
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?)", (job_id, "submitted", now, now, json.dumps(payload),
                                                                 None, None))
        return job_id

    def update(self, job_id: str, status: str, output: dict | None = None, error: str | None = None) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE jobs SET status=?, updated=?, output=COALESCE(?, output), error=COALESCE(?, error) "
                      "WHERE job_id=?", (status, time.time(), json.dumps(output) if output is not None else None,
                                         error, job_id))

    def get(self, job_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT job_id,status,created,updated,output,error FROM jobs WHERE job_id=?",
                            (job_id,)).fetchone()
        if not row:
            return None
        return {"job_id": row[0], "status": row[1], "created_at": row[2], "updated_at": row[3],
                "output": json.loads(row[4]) if row[4] else None, "error": row[5]}

    def input(self, job_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT input FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return json.loads(row[0]) if row else None
