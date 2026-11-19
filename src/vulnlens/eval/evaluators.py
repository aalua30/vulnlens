"""Metrics for VEX predictions vs. ground truth, plus a standalone benchmark runner."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from pathlib import Path

from ..config import Settings
from ..graph import run_pipeline
from .dataset import EvalItem, group_inputs, load_dataset, norm_status

log = logging.getLogger(__name__)


def score(pairs: list[dict]) -> dict:
    """pairs: [{expected_status, predicted_status, expected_justification, predicted_justification}]"""
    st = [p for p in pairs if p["expected_status"]]
    js = [p for p in pairs if p["expected_justification"]]
    status_acc = sum(p["expected_status"] == p["predicted_status"] for p in st) / len(st) if st else None
    just_acc = (sum(p["expected_justification"] == p["predicted_justification"] for p in js) / len(js)) if js else None
    confusion: dict[str, Counter] = defaultdict(Counter)
    for p in st:
        confusion[p["expected_status"]][p["predicted_status"]] += 1
    per_class = {}
    labels = sorted({p["expected_status"] for p in st} | {p["predicted_status"] for p in st})
    for c in labels:
        tp = sum(1 for p in st if p["expected_status"] == c and p["predicted_status"] == c)
        fp = sum(1 for p in st if p["expected_status"] != c and p["predicted_status"] == c)
        fn = sum(1 for p in st if p["expected_status"] == c and p["predicted_status"] != c)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        per_class[c] = {"precision": round(prec, 3), "recall": round(rec, 3),
                        "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0, "support": tp + fn}
    return {"n": len(pairs), "status_accuracy": status_acc, "justification_accuracy": just_acc,
            "per_class": per_class, "confusion": {k: dict(v) for k, v in confusion.items()},
            "unknown_rate": sum(p["predicted_status"] == "unknown" for p in pairs) / len(pairs) if pairs else None}


async def run_benchmark(dataset_path: str, settings: Settings, out_path: str | None = None, limit: int | None = None,
                        relaxed: bool = False, skip_web: bool = False, llm_profile: str | None = None,
                        refresh: list[str] | None = None, output_dir: str | None = None) -> dict:
    items: list[EvalItem] = load_dataset(dataset_path, limit)
    base = {"options": {"relaxed_vex": relaxed, "skip_web_research": skip_web, "llm_profile": llm_profile},
            "output": {"dir": output_dir or str(Path(settings.output_dir) / "eval")},
            "cache": {"refresh": list(refresh or [])}}
    pairs, runs = [], []
    for pin, its in group_inputs(items, base):
        log.info("eval target %s (%d vulns)", pin.target.display_name, len(its))
        err = "no results"
        try:
            out = await run_pipeline(pin, settings)
            runs.append(out.output_dir)
            by = {r.vex.cve_id: r.vex for r in out.results}
        except Exception as e:
            log.exception("eval target failed")
            by = {}
            err = str(e)
        for it in its:
            v = by.get(it.vuln_id)
            pairs.append({"id": it.id, "target": it.group, "vuln_id": it.vuln_id,
                          "expected_status": it.expected_status, "predicted_status": v.status.value if v else "unknown",
                          "expected_justification": it.expected_justification,
                          "predicted_justification": v.justification.value if v else "uncertain",
                          "error": None if v else err if not by else "missing result"})
    report = {"dataset": dataset_path, "relaxed": relaxed, "metrics": score(pairs), "items": pairs, "runs": runs}
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(report, indent=2))
    return report


def score_item(expected: dict, predicted_vex: dict) -> dict:
    """Single-item score used by the NAT evaluator: 1.0 status match (+ justification bonus)."""
    es = norm_status(expected.get("status") or expected.get("label"))
    ps = predicted_vex.get("status")
    status_ok = es == ps if es else None
    ej = expected.get("justification")
    just_ok = (ej == predicted_vex.get("justification")) if ej else None
    s = (1.0 if status_ok else 0.0) if status_ok is not None else 0.0
    if just_ok is not None:
        s = 0.7 * s + 0.3 * (1.0 if just_ok else 0.0)
    return {"score": s, "status_match": status_ok, "justification_match": just_ok}
