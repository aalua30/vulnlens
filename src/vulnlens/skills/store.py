"""Skill store: learned playbooks as Hermes-compatible ``SKILL.md`` files (agentskills.io format).

Layout under ``<skills dir>`` (default ``<cache_dir>/skills``)::

    active/<name>/SKILL.md            used by runs
    active/<name>/history/v<N>.md     previous versions (for rollback)
    pending/<name>/SKILL.md           proposed by the reflector, waiting for replay + approval
    pending/<name>/replay.json        last gate replay result
    rejected/<name>/SKILL.md

Frontmatter keeps the Hermes fields (``name``, ``description``, ``version``, ``metadata.hermes``) so the ``active``
directory can be listed in Hermes ``skills.external_dirs``; vulnlens-specific routing lives in ``metadata.vulnlens``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

STATES = ("active", "pending", "rejected")
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:64].rstrip("-") or "skill"


def valid_name(name: str) -> bool:
    return bool(_NAME.match(name))


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Skill:
    name: str
    description: str
    body: str
    version: int = 1
    category: str = "vulnerability-analysis"
    tags: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)      # empty = every agent
    packages: list[str] = field(default_factory=list)    # lower-case package names
    cwes: list[str] = field(default_factory=list)        # "CWE-79"
    distros: list[str] = field(default_factory=list)     # os-release ID: fedora, debian, alpine ...
    evidence_runs: list[str] = field(default_factory=list)
    fitness: dict[str, Any] = field(default_factory=dict)
    locked: bool = False
    origin: str = "manual"                               # manual | reflector
    state: str = "active"
    path: Path | None = None

    def frontmatter(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "metadata": {
                "hermes": {"tags": self.tags, "category": self.category},
                "vulnlens": {"agents": self.agents, "packages": self.packages, "cwes": self.cwes,
                             "distros": self.distros, "evidence_runs": self.evidence_runs,
                             "fitness": self.fitness, "locked": self.locked, "origin": self.origin},
            },
        }

    def to_markdown(self) -> str:
        fm = yaml.safe_dump(self.frontmatter(), sort_keys=False, allow_unicode=True).strip()
        return f"---\n{fm}\n---\n\n{self.body.strip()}\n"

    @classmethod
    def from_markdown(cls, text: str, state: str = "active", path: Path | None = None) -> "Skill":
        m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.S)
        if not m:
            raise ValueError("SKILL.md has no YAML frontmatter")
        fm = yaml.safe_load(m.group(1)) or {}
        meta = fm.get("metadata") or {}
        h, v = meta.get("hermes") or {}, meta.get("vulnlens") or {}

        def low(xs: Any) -> list[str]:
            return [str(x).strip().lower() for x in (xs or []) if str(x).strip()]

        return cls(
            name=str(fm.get("name") or ""), description=str(fm.get("description") or ""), body=m.group(2).strip(),
            version=int(fm.get("version") or 1), category=h.get("category") or "vulnerability-analysis",
            tags=list(h.get("tags") or []), agents=low(v.get("agents")), packages=low(v.get("packages")),
            cwes=[str(c).upper() for c in v.get("cwes") or []], distros=low(v.get("distros")),
            evidence_runs=list(v.get("evidence_runs") or []), fitness=dict(v.get("fitness") or {}),
            locked=bool(v.get("locked")), origin=v.get("origin") or "manual", state=state, path=path)

    def content_digest(self) -> str:
        """Hash of what the model sees (description + body + routing), not of bookkeeping such as fitness."""
        core = {"d": self.description, "b": self.body.strip(), "a": self.agents, "p": self.packages, "c": self.cwes,
                "o": self.distros}
        return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()[:16]


class SkillStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser()

    def _dir(self, state: str, name: str) -> Path:
        if state not in STATES:
            raise ValueError(f"unknown skill state {state}")
        if not valid_name(name):
            raise ValueError(f"invalid skill name '{name}' (lower-case letters, digits, '-')")
        return self.root / state / name

    def list(self, state: str = "active") -> list[Skill]:
        base = self.root / state
        out = []
        for p in sorted(base.glob("*/SKILL.md")) if base.exists() else []:
            try:
                out.append(Skill.from_markdown(p.read_text(), state, p))
            except (OSError, ValueError, yaml.YAMLError):
                continue  # a broken file never breaks a run
        return out

    def get(self, name: str, state: str | None = None) -> Skill | None:
        for st in ([state] if state else STATES):
            p = self._dir(st, name) / "SKILL.md"
            if p.exists():
                return Skill.from_markdown(p.read_text(), st, p)
        return None

    def write(self, skill: Skill, state: str) -> Path:
        d = self._dir(state, skill.name)
        d.mkdir(parents=True, exist_ok=True)
        p = d / "SKILL.md"
        p.write_text(skill.to_markdown())
        skill.state, skill.path = state, p
        return p

    def move(self, name: str, src: str, dst: str) -> Skill:
        """Move a skill between states. Moving into `active` archives the current active version first."""
        sk = self.get(name, src)
        if sk is None:
            raise KeyError(f"no {src} skill '{name}'")
        if dst == "active":
            cur = self.get(name, "active")
            if cur is not None:
                hist = self._dir("active", name) / "history"
                hist.mkdir(parents=True, exist_ok=True)
                (hist / f"v{cur.version}.md").write_text(cur.to_markdown())
                sk.version = max(sk.version, cur.version + 1)
        self.write(sk, dst)
        src_dir = self._dir(src, name)
        for extra in src_dir.glob("*.json"):
            shutil.copy2(extra, self._dir(dst, name) / extra.name)
        shutil.rmtree(src_dir, ignore_errors=True)
        return sk

    def rollback(self, name: str) -> Skill:
        hist = self._dir("active", name) / "history"
        versions = sorted(hist.glob("v*.md"), key=lambda p: int(p.stem[1:])) if hist.exists() else []
        if not versions:
            raise KeyError(f"skill '{name}' has no earlier version")
        prev = Skill.from_markdown(versions[-1].read_text(), "active")
        versions[-1].unlink()
        self.write(prev, "active")
        return prev

    def set_locked(self, name: str, locked: bool) -> Skill:
        sk = self.get(name, "active")
        if sk is None:
            raise KeyError(f"no active skill '{name}'")
        sk.locked = locked
        self.write(sk, "active")
        return sk

    def save_json(self, name: str, state: str, fname: str, data: Any) -> Path:
        p = self._dir(state, name) / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=1, default=str))
        return p

    def load_json(self, name: str, state: str, fname: str) -> Any:
        p = self._dir(state, name) / fname
        return json.loads(p.read_text()) if p.exists() else None


def set_hash(skills: list[Skill]) -> str | None:
    """Stable id of a selected skill set (goes into agent cache keys); None when no skill is selected."""
    if not skills:
        return None
    return hashlib.sha256("|".join(sorted(f"{s.name}:{s.content_digest()}" for s in skills)).encode()).hexdigest()[:16]


class SkillIndex:
    """In-memory SQLite FTS5 index over a list of skills (rebuilt per run, so it can never go stale)."""

    def __init__(self, skills: list[Skill]):
        self.skills = {s.name: s for s in skills}
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE VIRTUAL TABLE s USING fts5(name, description, body, tags)")
        self.db.executemany("INSERT INTO s VALUES (?,?,?,?)",
                            [(s.name, s.description, s.body, " ".join(s.tags + s.packages + s.cwes))
                             for s in skills])

    def search(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        terms = list(dict.fromkeys(re.findall(r"[A-Za-z0-9_]{4,}", text or "")))[:40]
        if not terms or not self.skills:
            return []
        q = " OR ".join(f'"{t}"' for t in terms)
        try:
            rows = self.db.execute("SELECT name, bm25(s) FROM s WHERE s MATCH ? ORDER BY bm25(s) LIMIT ?",
                                   (q, k)).fetchall()
        except sqlite3.OperationalError:
            return []
        return [(n, -score) for n, score in rows]  # bm25: lower is better -> positive relevance
