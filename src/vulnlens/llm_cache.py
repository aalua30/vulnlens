"""Local LLM response cache (exact match on prompt + model parameters + bound tools).

Complements the two other cache layers:

* ``vulnlens.cache.AgentCache`` stores whole agent outputs; it is skipped as soon as any input changes
  (new container profile, ``--refresh``), and then every LLM call of that agent is paid again.
* Provider prompt caching (Claude ``cache_control``, DeepSeek automatic prefix caching) makes the *prefix*
  cheaper but still runs the model.

This layer answers a repeated identical request locally without calling the provider at all, so a re-run whose
early ReAct steps are unchanged replays them for free and only pays from the first step that differs.

Backends: ``valkey`` / ``redis`` (shared service; plain GET/SET, no modules needed), ``sqlite`` (file under
cache_dir, no service), ``memory`` (per process), ``none``.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Optional, Sequence

from langchain_core.caches import BaseCache, InMemoryCache

log = logging.getLogger(__name__)

RETURN_VAL_TYPE = Sequence[Any]


# Per-response bookkeeping on messages already in the history. It is never sent to the provider, but differs
# between a live answer and its cached replay (message id, token usage, finish metadata). If it stayed in the key,
# a replayed step 1 would change the prompt of step 2 and nothing after the first step could ever hit.
_VOLATILE = ("id", "response_metadata", "usage_metadata")


def normalize_prompt(prompt: str) -> str:
    """Cache key for a serialized message list, without volatile per-response fields."""
    try:
        msgs = json.loads(prompt)
    except ValueError:
        return prompt
    if not isinstance(msgs, list):
        return prompt
    for m in msgs:
        kw = m.get("kwargs") if isinstance(m, dict) else None
        if isinstance(kw, dict):
            for k in _VOLATILE:
                kw.pop(k, None)  # top-level message fields only; tool_calls[].id is sent and must stay
    return json.dumps(msgs, sort_keys=True, separators=(",", ":"))


class CountingCache(BaseCache):
    """Delegating cache that counts hits/misses so runs can report how much was served locally."""

    def __init__(self, inner: BaseCache, label: str):
        self.inner, self.label = inner, label
        self.hits = self.misses = self.writes = 0
        self._lock = threading.Lock()

    def _count(self, val: Optional[RETURN_VAL_TYPE]) -> Optional[RETURN_VAL_TYPE]:
        with self._lock:
            if val is None:
                self.misses += 1
            else:
                self.hits += 1
        return val

    def lookup(self, prompt: str, llm_string: str) -> Optional[RETURN_VAL_TYPE]:
        try:
            return self._count(self.inner.lookup(normalize_prompt(prompt), llm_string))
        except Exception as e:  # a broken cache must never break a run
            log.warning("LLM cache lookup failed (%s): %s", self.label, e)
            return self._count(None)

    def update(self, prompt: str, llm_string: str, return_val: RETURN_VAL_TYPE) -> None:
        try:
            self.inner.update(normalize_prompt(prompt), llm_string, return_val)
            with self._lock:
                self.writes += 1
        except Exception as e:
            log.warning("LLM cache write failed (%s): %s", self.label, e)

    def clear(self, **kwargs: Any) -> None:
        self.inner.clear(**kwargs)

    def stats(self) -> dict[str, Any]:
        return {"backend": self.label, "hits": self.hits, "misses": self.misses, "writes": self.writes}


def _load(text: str) -> Any:
    """Deserialize a cached generation, admitting only generation/message classes (never arbitrary objects,
    in case the cache file or a shared Redis was tampered with)."""
    import warnings

    from langchain_core.load import loads
    from langchain_core.messages import AIMessage, AIMessageChunk
    from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, Generation

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # `loads` is marked beta
        return loads(text, allowed_objects=[ChatGeneration, ChatGenerationChunk, Generation, AIMessage,
                                            AIMessageChunk])


class SQLiteCache(BaseCache):
    """Minimal SQLite-backed cache (no langchain-community / SQLAlchemy dependency). Values are stored with
    langchain's own serializer, so AIMessages with tool calls and usage metadata round-trip intact."""

    def __init__(self, path: str):
        import sqlite3

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("CREATE TABLE IF NOT EXISTS llm_cache (prompt_hash TEXT, llm_hash TEXT, idx INTEGER, "
                             "value TEXT, created REAL DEFAULT (strftime('%s','now')), "
                             "PRIMARY KEY (prompt_hash, llm_hash, idx))")
            self._db.commit()

    @staticmethod
    def _h(s: str) -> str:
        import hashlib

        return hashlib.sha256(s.encode()).hexdigest()

    def lookup(self, prompt: str, llm_string: str) -> Optional[RETURN_VAL_TYPE]:
        with self._lock:
            rows = self._db.execute("SELECT value FROM llm_cache WHERE prompt_hash=? AND llm_hash=? ORDER BY idx",
                                    (self._h(prompt), self._h(llm_string))).fetchall()
        if not rows:
            return None
        try:
            return [_load(r[0]) for r in rows]
        except Exception as e:  # entry written by an incompatible langchain version: treat as a miss
            log.debug("undecodable LLM cache entry: %s", e)
            return None

    def update(self, prompt: str, llm_string: str, return_val: RETURN_VAL_TYPE) -> None:
        from langchain_core.load import dumps

        ph, lh = self._h(prompt), self._h(llm_string)
        with self._lock:
            self._db.execute("DELETE FROM llm_cache WHERE prompt_hash=? AND llm_hash=?", (ph, lh))
            self._db.executemany("INSERT INTO llm_cache (prompt_hash, llm_hash, idx, value) VALUES (?,?,?,?)",
                                 [(ph, lh, i, dumps(g)) for i, g in enumerate(return_val)])
            self._db.commit()

    def clear(self, **kwargs: Any) -> None:
        with self._lock:
            self._db.execute("DELETE FROM llm_cache")
            self._db.commit()


class KeyValueCache(BaseCache):
    """Valkey / Redis backend using only plain string commands (GET, SET EX, SCAN, DEL), so it works on a stock
    Valkey without the JSON module that langchain-redis requires. Values use the same restricted loader as the
    SQLite backend."""

    def __init__(self, url: str, ttl: int | None = None, prefix: str = "vulnlens:llm", client: Any = None):
        if client is None:
            try:
                import valkey as kv  # python3-valkey / pip install valkey
            except ImportError:
                try:
                    import redis as kv  # redis-py speaks the same protocol
                except ImportError as e:
                    raise RuntimeError("llm_cache.backend=valkey|redis needs: pip install 'vulnlens[valkey]'") from e
            client = kv.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=5)
        self.client, self.ttl, self.prefix = client, ttl, prefix

    def _key(self, prompt: str, llm_string: str) -> str:
        return f"{self.prefix}:{SQLiteCache._h(llm_string)[:16]}:{SQLiteCache._h(prompt)}"

    def ping(self) -> bool:
        return bool(self.client.ping())

    def lookup(self, prompt: str, llm_string: str) -> Optional[RETURN_VAL_TYPE]:
        raw = self.client.get(self._key(prompt, llm_string))
        if not raw:
            return None
        try:
            return [_load(g) for g in json.loads(raw)]
        except Exception as e:
            log.debug("undecodable LLM cache entry: %s", e)
            return None

    def update(self, prompt: str, llm_string: str, return_val: RETURN_VAL_TYPE) -> None:
        from langchain_core.load import dumps

        self.client.set(self._key(prompt, llm_string), json.dumps([dumps(g) for g in return_val]), ex=self.ttl)

    def keys(self) -> list:
        return list(self.client.scan_iter(match=f"{self.prefix}:*", count=500))

    def clear(self, **kwargs: Any) -> None:
        batch = self.keys()
        for i in range(0, len(batch), 500):
            self.client.delete(*batch[i:i + 500])


_CACHES: dict[tuple, CountingCache] = {}
_LOCK = threading.Lock()
KV_BACKENDS = ("valkey", "redis")


def kv_url(cfg: Any) -> str:
    return os.environ.get("VULNLENS_VALKEY_URL") or os.environ.get("VULNLENS_REDIS_URL") or cfg.redis_url


def _redact_url(url: str) -> str:
    return url.split("://", 1)[0] + "://" + url.split("@")[-1].split("://")[-1]  # drop user:password


def _sqlite(cfg: Any, cache_dir: str) -> tuple[BaseCache, str]:
    path = os.path.expanduser(cfg.path or os.path.join(cache_dir, "llm_cache.sqlite"))
    return SQLiteCache(path), f"sqlite:{path}"


def build_backend(cfg: Any, cache_dir: str) -> tuple[BaseCache, str]:
    backend = (cfg.backend or "none").lower()
    if backend == "sqlite":
        return _sqlite(cfg, cache_dir)
    if backend in KV_BACKENDS:
        url = kv_url(cfg)
        label = f"{backend}:{_redact_url(url)}"
        try:
            inner = KeyValueCache(url, ttl=cfg.ttl, prefix=cfg.prefix)
            inner.ping()
            return inner, label
        except Exception as e:
            if (cfg.fallback or "none") == "sqlite":
                log.warning("LLM cache %s unreachable (%s); falling back to SQLite", label, e)
                return _sqlite(cfg, cache_dir)
            raise RuntimeError(f"LLM cache {label} unreachable: {e}") from e
    if backend == "memory":
        return InMemoryCache(), "memory"
    raise ValueError(f"unknown llm_cache.backend '{cfg.backend}' (valkey|redis|sqlite|memory|none)")


def get_llm_cache(cfg: Any, cache_dir: str) -> CountingCache | None:
    """One shared cache per backend configuration (process-wide), or None when disabled."""
    if (cfg.backend or "none").lower() == "none":
        return None
    key = (cfg.backend, cfg.path, kv_url(cfg), cfg.ttl, cfg.prefix, cfg.fallback, cache_dir)
    with _LOCK:
        if key not in _CACHES:
            inner, label = build_backend(cfg, cache_dir)
            _CACHES[key] = CountingCache(inner, label)
            log.info("LLM response cache: %s", label)
        return _CACHES[key]


def cache_stats() -> list[dict[str, Any]]:
    return [c.stats() for c in _CACHES.values()]


def describe(cfg: Any, cache_dir: str) -> dict[str, Any]:
    """Backend, reachability and entry count, for `vulnlens llm-cache info`."""
    if (cfg.backend or "none").lower() == "none":
        return {"backend": "none"}
    inner, label = build_backend(cfg, cache_dir)
    out: dict[str, Any] = {"backend": label}
    if isinstance(inner, KeyValueCache):
        out["entries"] = len(inner.keys())
        out["ttl"] = cfg.ttl
        info = inner.client.info("server")
        out["server"] = f"valkey {info['valkey_version']}" if "valkey_version" in info \
            else f"redis {info.get('redis_version')}"
    elif isinstance(inner, SQLiteCache):
        out["entries"] = inner._db.execute("SELECT COUNT(DISTINCT prompt_hash || llm_hash) FROM llm_cache").fetchone()[0]
    return out
