"""Promotion gate for learned skills: replay on the gold set, then explicit approval.

``replay`` runs the gold set twice per repeat: *baseline* (active skills) and *candidate* (active skills with the
pending candidate added or replacing the version it patches). Research and target profiles come from the agent
cache unless the candidate applies to them; exploitability and VEX are re-run fresh in both arms. A candidate passes when it was actually injected somewhere
(``exercised``) and no metric regressed; ``improved`` is reported separately. ``approve`` refuses candidates without a
passing replay of their *current* text unless ``force`` is given.
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path
from statistics import mean
from typing import Any

from ..config import Settings
from .store import Skill, SkillStore, now

log = logging.getLogger(__name__)

EPS = 1e-9


def _gold_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def holdout_dataset(gold: Path, cand: Skill, work: Path) -> tuple[Path, bool]:
    """Gold records not derived from the runs the candidate learned from. Falls back to the whole set (in-sample)
    when nothing would be left, and says so."""
    recs = _gold_records(gold)
    keep = [r for r in recs if not set(r.get("source_runs") or []) & set(cand.evidence_runs)]
    in_sample = not keep
    work.mkdir(parents=True, exist_ok=True)
    out = work / "gold_replay.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in (keep or recs)))
    return out, in_sample


def _loops(run_dirs: list[str]) -> list[dict]:
    loops = []
    for d in run_dirs:
        try:
            loops += json.loads((Path(d) / "experience.json").read_text()).get("loops") or []
        except (OSError, ValueError):
            pass
    return loops


def arm_metrics(report: dict, name: str | None) -> dict[str, Any]:
    m = report["metrics"]
    loops = _loops(report.get("runs") or [])
    react = [lp for lp in loops if lp.get("kind") == "react" and lp.get("agent") == "exploitability"]
    return {"status_accuracy": m.get("status_accuracy"), "justification_accuracy": m.get("justification_accuracy"),
            "unknown_rate": m.get("unknown_rate"), "n": m.get("n"),
            "exploitability_steps": sum(lp.get("steps") or 0 for lp in react),
            "exhausted": sum(bool(lp.get("exhausted")) for lp in react),
            "exercised": bool(name) and any(name in (lp.get("playbooks") or []) for lp in loops),
            "mismatches": [i for i in report["items"] if i["expected_status"] and
                           (i["expected_status"] != i["predicted_status"] or
                            (i["expected_justification"] and
                             i["expected_justification"] != i["predicted_justification"]))]}


def _avg(xs: list[dict], key: str) -> float | None:
    vals = [x[key] for x in xs if x.get(key) is not None]
    return mean(vals) if vals else None


def decide(base: list[dict], cand: list[dict]) -> dict[str, Any]:
    b = {k: _avg(base, k) for k in ("status_accuracy", "justification_accuracy", "unknown_rate",
                                    "exploitability_steps", "exhausted")}
    c = {k: _avg(cand, k) for k in b}
    reasons, better = [], []
    for k, higher_is_better in (("status_accuracy", True), ("justification_accuracy", True),
                                ("unknown_rate", False), ("exhausted", False)):
        if b[k] is None or c[k] is None:
            continue
        delta = (c[k] - b[k]) if higher_is_better else (b[k] - c[k])
        if delta < -EPS:
            reasons.append(f"{k} regressed: {b[k]:.3f} -> {c[k]:.3f}")
        elif delta > EPS:
            better.append(f"{k}: {b[k]:.3f} -> {c[k]:.3f}")
    if b["exploitability_steps"] and c["exploitability_steps"] is not None and \
            c["exploitability_steps"] <= 0.9 * b["exploitability_steps"]:
        better.append(f"exploitability steps: {b['exploitability_steps']:.1f} -> {c['exploitability_steps']:.1f}")
    exercised = any(x["exercised"] for x in cand)
    if not exercised:
        reasons.append("candidate was never injected into an agent prompt on the gold set (not exercised)")
    return {"passed": exercised and not reasons, "improved": better, "regressions": reasons,
            "baseline": b, "candidate": c}


async def replay(settings: Settings, name: str, repeats: int | None = None, profile: str | None = None) -> dict:
    from ..eval.evaluators import run_benchmark

    store = SkillStore(settings.skills_dir)
    cand = store.get(name, "pending")
    if cand is None:
        raise KeyError(f"no pending skill '{name}'")
    gold = Path(settings.skills.gold_set)
    if not gold.exists():
        raise FileNotFoundError(f"gold set {gold} not found (skills.gold_set)")
    work = Path(settings.output_dir) / "replay" / name
    dataset, in_sample = holdout_dataset(gold, cand, work)
    k = repeats or settings.skills.replay_repeats
    arms: dict[str, list[dict]] = {"baseline": [], "candidate": []}
    for arm, include in (("baseline", []), ("candidate", [name])):
        for i in range(k):
            st = settings.model_copy(deep=True)
            st.skills.include_pending = include
            # Both arms always re-run the deep analysis (agent + LLM response cache bypassed) so they are fresh samples
            # of the same model; a cached baseline vs a fresh candidate would compare run-to-run noise, not the skill.
            refresh = ["exploitability", "vex_categorizer"]
            log.info("[gate %s] %s arm, repeat %d/%d", name, arm, i + 1, k)
            rep = await run_benchmark(str(dataset), st, llm_profile=profile, refresh=refresh,
                                      output_dir=str(work / f"{arm}-{i}"))
            arms[arm].append(arm_metrics(rep, name if arm == "candidate" else None))
    result = {"skill": name, "digest": cand.content_digest(), "ts": now(), "repeats": k, "in_sample": in_sample,
              "dataset": str(gold), **decide(arms["baseline"], arms["candidate"]), "arms": arms}
    store.save_json(name, "pending", "replay.json", result)
    return result


def approve(settings: Settings, name: str, force: bool = False) -> Skill:
    store = SkillStore(settings.skills_dir)
    cand = store.get(name, "pending")
    if cand is None:
        raise KeyError(f"no pending skill '{name}'")
    rep = store.load_json(name, "pending", "replay.json")
    if settings.skills.require_replay and not force:
        if not rep:
            raise PermissionError(f"'{name}' has no replay result; run `vulnlens skills replay {name}` first")
        if rep.get("digest") != cand.content_digest():
            raise PermissionError(f"'{name}' changed after its replay; replay it again")
        if not rep.get("passed"):
            raise PermissionError(f"'{name}' failed its replay: {'; '.join(rep.get('regressions') or [])}")
    cand.fitness = {**cand.fitness, "approved": now(), "forced": bool(force and not (rep or {}).get("passed")),
                    "replay": {k: rep.get(k) for k in ("passed", "improved", "regressions", "in_sample", "repeats",
                                                       "baseline", "candidate", "ts")} if rep else None}
    store.write(cand, "pending")
    return store.move(name, "pending", "active")


def reject(settings: Settings, name: str, reason: str = "") -> Skill:
    store = SkillStore(settings.skills_dir)
    store.save_json(name, "pending", "rejection.json", {"reason": reason, "ts": now()})
    return store.move(name, "pending", "rejected")


def diff(settings: Settings, name: str) -> str:
    store = SkillStore(settings.skills_dir)
    cand = store.get(name, "pending")
    if cand is None:
        raise KeyError(f"no pending skill '{name}'")
    cur = store.get(name, "active")
    a = cur.to_markdown().splitlines(keepends=True) if cur else []
    return "".join(difflib.unified_diff(a, cand.to_markdown().splitlines(keepends=True),
                                        f"active/{name}/SKILL.md" if cur else "/dev/null",
                                        f"pending/{name}/SKILL.md"))
