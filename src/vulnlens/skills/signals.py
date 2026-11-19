"""Learning signals for one run: what went wrong (or right) and is worth turning into a playbook.

Sources, all from our own artefacts (never from target-supplied text):

* live verification that refuted / confirmed a static verdict (``exploitability.json`` → ``verification``)
* analyst feedback recorded with ``vulnlens feedback`` (``feedback.json`` in the run directory)
* gold-set mismatches written by the gate replay / ``vulnlens eval`` (``eval_mismatches`` argument)
* loop health from the ReAct recorder: exhausted step budgets, tool errors, JSON-repair retries
* unknown / low-confidence verdicts, and verdict flips versus earlier runs of the same target digest + CVE

``experience.json`` = {run_id, target, digest, distro, cves[], loops[], signals[]}.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from .store import now

log = logging.getLogger(__name__)

LOW_CONFIDENCE = 0.6


def _load(p: Path) -> Any:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def cve_records(run_dir: Path) -> list[dict]:
    """Compact per-CVE view built from the run's JSON reports."""
    out = []
    for d in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        er, vex, vr = (_load(d / f) for f in ("exploitability.json", "vex.json", "cve_research.json"))
        if not er or not vex:
            continue
        ver = er.get("verification") or None
        out.append({
            "vuln": er["vuln_id"], "verdict": er.get("verdict"), "confidence": er.get("confidence"),
            "early_exit": er.get("early_exit"), "complete": er.get("complete"),
            "status": vex.get("status"), "justification": vex.get("justification"),
            "summary": (er.get("summary") or "")[:1500],
            "evidence": [{"kind": e.get("kind"), "path": e.get("path"), "detail": (e.get("detail") or "")[:300]}
                         for e in (er.get("evidence") or [])][:15],
            "conditions": er.get("conditions") or [], "errors": er.get("errors") or [],
            "packages": sorted({p.get("name", "").lower() for p in (vr or {}).get("affected_packages", [])})[:20],
            "cwes": (vr or {}).get("cwe", []),
            "live": {"outcome": ver.get("outcome"), "static_verdict": ver.get("static_verdict"),
                     "verdict": ver.get("verdict"), "summary": (ver.get("summary") or "")[:800]} if ver else None,
        })
    return out


def _previous_verdicts(run_dir: Path, digest: str) -> dict[str, list[tuple[str, str]]]:
    """vuln -> [(run_id, verdict)] from earlier runs of the same target digest in the same output dir."""
    hist: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for other in sorted(run_dir.parent.glob("*/summary.json")):
        if other.parent == run_dir:
            continue
        s = _load(other) or {}
        if s.get("digest") != digest:
            continue
        for r in s.get("results", []):
            if r.get("exploitability_verdict"):
                hist[r["cve_id"]].append((s.get("run_id", other.parent.name), r["exploitability_verdict"]))
    return hist


def collect_signals(run_dir: Path, loops: list[dict] | None = None,
                    eval_mismatches: list[dict] | None = None) -> dict:
    run_dir = Path(run_dir)
    summary = _load(run_dir / "summary.json") or {}
    inv = _load(run_dir / "inventory.json") or {}
    cves = cve_records(run_dir)
    loops = loops if loops is not None else ((_load(run_dir / "experience.json") or {}).get("loops") or [])
    sig: list[dict] = []

    def add(kind: str, severity: str, detail: str, **kw: Any) -> None:
        sig.append({"kind": kind, "severity": severity, "detail": detail[:1200], **kw})

    for c in cves:
        lv = c["live"]
        if lv and lv["outcome"] == "refuted":
            add("live_refuted", "high", f"live verification refuted static verdict {lv['static_verdict']} -> "
                f"{lv['verdict']}: {lv['summary']}", vuln=c["vuln"], agent="exploitability")
        elif lv and lv["outcome"] == "confirmed":
            add("live_confirmed", "info", lv["summary"], vuln=c["vuln"], agent="exploitability")
        if c["status"] == "unknown" or not c["complete"]:
            add("unknown_verdict", "high", "; ".join(c["errors"]) or "no verdict", vuln=c["vuln"],
                agent="exploitability")
        elif not c["early_exit"] and (c["confidence"] or 0) < LOW_CONFIDENCE:
            add("low_confidence", "medium", f"{c['verdict']} at confidence {c['confidence']}", vuln=c["vuln"],
                agent="exploitability")
    for vuln, prev in _previous_verdicts(run_dir, summary.get("digest", "")).items():
        cur = next((c for c in cves if c["vuln"] == vuln), None)
        flips = sorted({v for _, v in prev} - {cur["verdict"]}) if cur and cur["verdict"] else []
        if flips:
            add("verdict_flip", "medium", f"now {cur['verdict']}; earlier runs said {', '.join(flips)} "
                f"({', '.join(r for r, _ in prev[-3:])})", vuln=vuln, agent="exploitability")
    for fb in (_load(run_dir / "feedback.json") or []):
        c = next((c for c in cves if c["vuln"] == fb.get("vuln")), None)
        wrong = c and ((fb.get("status") and fb["status"] != c["status"]) or
                       (fb.get("justification") and fb["justification"] != c["justification"]))
        add("analyst_correction" if wrong else "analyst_note", "high" if wrong else "medium",
            f"analyst: status={fb.get('status') or '-'} justification={fb.get('justification') or '-'}; "
            f"note: {fb.get('note') or ''}" + (f" (predicted {c['status']}/{c['justification']})" if c else ""),
            vuln=fb.get("vuln"), agent=fb.get("agent") or "exploitability")
    for m in eval_mismatches or []:
        add("gold_mismatch", "high", f"expected {m.get('expected_status')}/{m.get('expected_justification')}, "
            f"predicted {m.get('predicted_status')}/{m.get('predicted_justification')}", vuln=m.get("vuln_id"),
            agent="exploitability")
    for lp in loops:
        if lp.get("kind") == "react":
            agent = lp.get("agent")
            if lp.get("exhausted"):
                add("step_budget_exhausted", "medium", f"{lp.get('label')}: used all {lp.get('max_steps')} steps",
                    vuln=lp.get("vuln"), agent=agent)
            errs: dict[str, list] = defaultdict(list)
            for e in lp.get("tool_errors") or []:
                errs[e["tool"]].append(e)
            for tool, es in errs.items():
                add("tool_error", "low" if len(es) < 3 else "medium",
                    f"{lp.get('label')}: {len(es)}x {tool} failed, e.g. args={json.dumps(es[0]['args'])[:200]} "
                    f"-> {es[0]['error']}", vuln=lp.get("vuln"), agent=agent)
        elif lp.get("kind") == "json_repair":
            add("json_repair", "low", f"{lp.get('label')}: invalid {lp.get('schema')}: {lp.get('error')}",
                vuln=lp.get("vuln"), agent=lp.get("agent"))
    return {"run_id": summary.get("run_id", run_dir.name), "target": summary.get("target"),
            "digest": summary.get("digest"), "distro": (inv.get("distro") or {}).get("ID"),
            "created": now(), "cves": cves, "loops": loops, "signals": sig}


def write_experience(run_dir: Path, loops: list[dict]) -> dict:
    exp = collect_signals(run_dir, loops)
    (Path(run_dir) / "experience.json").write_text(json.dumps(exp, indent=1, default=str))
    return exp


def add_feedback(run_dir: Path, vuln: str, status: str | None = None, justification: str | None = None,
                 note: str = "", agent: str | None = None) -> list[dict]:
    """Record an analyst label / comment for one CVE of a run (feeds the reflector and the gold set)."""
    p = Path(run_dir) / "feedback.json"
    items = _load(p) or []
    items.append({"vuln": vuln, "status": status, "justification": justification, "note": note, "agent": agent,
                  "ts": now()})
    p.write_text(json.dumps(items, indent=1))
    return items
