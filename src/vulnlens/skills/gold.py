"""Local gold set (``skills.gold_set``, JSONL in the format vulnlens.eval.dataset loads).

One record per labeled CVE::

    {"input": {"target": {...}, "vulnerabilities": [{"vuln_id": "CVE-…"}]},
     "expected": {"status": "not_affected", "justification": "code_not_reachable"},
     "source_runs": ["<run id>"], "label_source": "analyst", "ts": "2026-01-01T00:00:00Z"}

``source_runs`` lets the gate hold out records derived from the runs a candidate skill learned from.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import Settings
from .store import now


def _target_of_run(run_dir: Path) -> dict:
    p = run_dir / "input.json"
    if not p.exists():
        raise FileNotFoundError(f"{p} missing (runs before this version did not save their input); "
                                "add the record to the gold set by hand")
    return json.loads(p.read_text())["target"]


def add_gold_label(settings: Settings, run_dir: Path, vuln: str, status: str, justification: str | None) -> str:
    gold = Path(settings.skills.gold_set)
    gold.parent.mkdir(parents=True, exist_ok=True)
    target = _target_of_run(run_dir)
    run_id = json.loads((run_dir / "summary.json").read_text())["run_id"]
    recs = [json.loads(line) for line in gold.read_text().splitlines() if line.strip()] if gold.exists() else []
    rec = {"input": {"target": target, "vulnerabilities": [{"vuln_id": vuln}]},
           "expected": {"status": status, "justification": justification},
           "source_runs": [run_id], "label_source": "analyst", "ts": now()}
    same = lambda r: r["input"]["target"] == target and r["input"]["vulnerabilities"][0]["vuln_id"] == vuln  # noqa
    old = next((r for r in recs if same(r)), None)
    if old:
        rec["source_runs"] = sorted(set(old.get("source_runs") or []) | {run_id})
    recs = [r for r in recs if not same(r)] + [rec]
    gold.write_text("".join(json.dumps(r) + "\n" for r in recs))
    return f"{gold} ({len(recs)} records)"
