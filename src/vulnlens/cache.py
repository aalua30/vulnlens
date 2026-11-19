"""On-disk cache for agent outputs so interrupted / repeated runs resume without redoing LLM work."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

CACHE_SCHEMA_VERSION = 1


def stable_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


class AgentCache:
    def __init__(self, root: str | os.PathLike, enabled: bool = True, refresh: list[str] | None = None):
        self.root = Path(root) / "agents"
        self.enabled = enabled
        self.refresh = set(refresh or [])
        self.hits = 0
        self.misses = 0

    def _path(self, agent: str, key: dict) -> Path:
        h = stable_hash({"v": CACHE_SCHEMA_VERSION, "agent": agent, **key})
        return self.root / agent / h[:2] / f"{h}.json"

    def get(self, agent: str, key: dict) -> Any | None:
        if not self.enabled or agent in self.refresh:
            self.misses += 1
            return None
        p = self._path(agent, key)
        if not p.exists():
            self.misses += 1
            return None
        try:
            data = json.loads(p.read_text())["data"]
        except (OSError, ValueError, KeyError):
            self.misses += 1
            return None
        self.hits += 1
        return data

    def put(self, agent: str, key: dict, data: Any) -> None:
        if not self.enabled:
            return
        p = self._path(agent, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"key": key, "agent": agent, "ts": time.time(), "data": data}, default=str)
        fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        os.replace(tmp, p)  # atomic: a crash never leaves a half-written entry
