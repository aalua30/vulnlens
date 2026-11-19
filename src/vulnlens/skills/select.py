"""Pick the playbooks relevant to one agent call and make them visible to the ReAct loop.

The graph node selects skills (by agent, affected packages, CWE, distro + FTS5 over the task text), then wraps the
agent call in ``use_playbooks(...)``. ``vulnlens.llm.run_react`` reads the context variable, appends the playbook block
to the system prompt and, when some skills did not fit the budget, adds a ``skill_view`` tool (progressive
disclosure, like Hermes ``skills_list`` / ``skill_view``). The same context carries the run's experience recorder,
so every loop reports its steps, tool errors and JSON-repair retries for the learning loop.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from langchain_core.tools import BaseTool, tool

from .store import Skill, SkillIndex, set_hash

log = logging.getLogger(__name__)

HEADER = """## Playbooks from earlier analyses
Lessons learned from previous vulnlens runs and approved by an analyst. They are advisory: the target's filesystem,
tool output and live probes are ground truth. If a playbook does not fit this target or contradicts the evidence,
follow the evidence and say so in your answer. Never skip a verification step because a playbook predicts its result."""


@dataclass
class Playbooks:
    agent: str
    inline: list[Skill] = field(default_factory=list)
    overflow: list[Skill] = field(default_factory=list)

    @property
    def skills(self) -> list[Skill]:
        return self.inline + self.overflow

    @property
    def names(self) -> list[str]:
        return [s.name for s in self.skills]

    @property
    def hash(self) -> str | None:
        return set_hash(self.skills)

    def text(self) -> str:
        if not self.skills:
            return ""
        parts = [HEADER]
        for s in self.inline:
            parts.append(f"### {s.name} (v{s.version}) — {s.description}\n{s.body.strip()}")
        if self.overflow:
            parts.append("More playbooks (load the full text with the skill_view tool only if relevant):\n" +
                         "\n".join(f"- {s.name}: {s.description}" for s in self.overflow))
        return "\n\n".join(parts)

    def view_tool(self) -> BaseTool:
        by = {s.name: s for s in self.skills}

        @tool
        def skill_view(name: str) -> str:
            """Return the full text of one playbook listed under 'More playbooks'."""
            s = by.get(name)
            return f"{s.name} (v{s.version}) — {s.description}\n\n{s.body}" if s else f"unknown playbook '{name}'"

        return skill_view


def _pkg_match(skill_pkgs: Iterable[str], pkgs: set[str]) -> int:
    n = 0
    for p in skill_pkgs:
        if any(q == p or q.startswith(p + "-") or q.startswith(p + "_") or p.startswith(q + "-") for q in pkgs):
            n += 1
    return n


def select_skills(skills: list[Skill], agent: str, packages: Iterable[str] = (), cwes: Iterable[str] = (),
                  distro: str | None = None, text: str = "", max_chars: int = 6000, max_skills: int = 6) -> Playbooks:
    pkgs = {p.lower() for p in packages if p}
    cw = {c.upper() for c in cwes if c}
    dist = (distro or "").lower() or None
    fts = {n for n, _ in SkillIndex(skills).search(text, k=max_skills)} if text and skills else set()
    scored: list[tuple[float, Skill]] = []
    for s in skills:
        if s.agents and agent not in s.agents:
            continue
        if s.distros and dist and dist not in s.distros:
            continue
        pm, cm = _pkg_match(s.packages, pkgs), len(set(s.cwes) & cw)
        targeted = bool(s.packages or s.cwes)
        if targeted and not (pm or cm):
            continue  # written for other packages / weakness classes
        score = 3.0 * pm + 2.0 * cm + (1.0 if s.distros and dist in s.distros else 0.0)
        score += 1.0 if s.name in fts else 0.0
        score += 0.0 if targeted else 0.5  # general per-agent lessons rank below targeted ones
        scored.append((score, s))
    scored.sort(key=lambda t: (-t[0], t[1].name))
    pb = Playbooks(agent=agent)
    used = 0
    for _, s in scored[:max_skills]:
        size = len(s.body) + len(s.description) + 40
        if used + size <= max_chars:
            pb.inline.append(s)
            used += size
        else:
            pb.overflow.append(s)
    return pb


# ---------------------------------------------------------------------------
# Context passed to the ReAct loop
# ---------------------------------------------------------------------------

_PLAYBOOKS: contextvars.ContextVar[Playbooks | None] = contextvars.ContextVar("vulnlens_playbooks", default=None)
_RECORDER: contextvars.ContextVar[list | None] = contextvars.ContextVar("vulnlens_experience", default=None)
_SCOPE: contextvars.ContextVar[dict] = contextvars.ContextVar("vulnlens_scope", default={})


@contextlib.contextmanager
def use_playbooks(pb: Playbooks | None, recorder: list | None = None, **scope: Any) -> Iterator[None]:
    """Make `pb` and the experience recorder visible to run_react / invoke_structured inside this block."""
    t1, t2, t3 = _PLAYBOOKS.set(pb), _RECORDER.set(recorder), _SCOPE.set(scope)
    if pb and pb.skills:
        log.info("[skills %s%s] playbooks: %s", pb.agent, f" {scope['vuln']}" if scope.get("vuln") else "",
                 ", ".join(pb.names))
    try:
        yield
    finally:
        _PLAYBOOKS.reset(t1)
        _RECORDER.reset(t2)
        _SCOPE.reset(t3)


def current_playbooks() -> Playbooks | None:
    return _PLAYBOOKS.get()


def record(event: dict) -> None:
    """Append one loop / repair event to the run's experience (no-op outside a recorded block)."""
    rec = _RECORDER.get()
    if rec is not None:
        pb = _PLAYBOOKS.get()
        rec.append({**_SCOPE.get(), "playbooks": pb.names if pb else [], **event})
