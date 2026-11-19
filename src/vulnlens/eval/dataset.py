"""Benchmark dataset loading (e.g. the Morpheus 25.06 exploitability benchmark).

The loader is column-tolerant: each record needs an image (``image`` | ``container`` | ``image_name``+``image_tag``)
or ``filesystem_path``, a vulnerability id (``vuln_id`` | ``cve`` | ``cve_id`` | ``vulnerability``) and a label
(``status`` / ``label`` / ``vex_status`` and optionally ``justification`` / ``label_justification``).
Formats: JSON list, JSON object with a list field, JSONL, CSV. A record may also carry a full ``input`` PipelineInput
(blueprint style); its expected labels then live in ``expected`` / ``ground_truth``.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from ..models import Justification, PipelineInput

JUSTIFICATION_SYNONYMS = {
    "vulnerable_code_not_present": "code_not_present", "component_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable", "not_reachable": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_configuration",
    "inline_mitigations_already_exist": "mitigating_control_protected",
    "protected_by_compiler": "compiler_protected", "protected_by_perimeter": "perimeter_protected",
    "protected_by_mitigating_control": "mitigating_control_protected", "exploitable": "vulnerable",
    "affected": "vulnerable", "true_positive": "vulnerable",
}
STATUS_SYNONYMS = {"true": "affected", "vulnerable": "affected", "exploitable": "affected", "false": "not_affected",
                   "not_vulnerable": "not_affected", "under_investigation": "unknown", "fixed": "not_affected"}


def norm_status(s: str | None) -> str | None:
    if s is None or s == "":
        return None
    s = str(s).strip().lower().replace(" ", "_").replace("-", "_")
    return STATUS_SYNONYMS.get(s, s)


def norm_justification(j: str | None) -> str | None:
    if not j:
        return None
    j = str(j).strip().lower().replace(" ", "_").replace("-", "_")
    j = JUSTIFICATION_SYNONYMS.get(j, j)
    return j if j in {x.value for x in Justification} else j


@dataclass
class EvalItem:
    id: str
    group: str  # target key; items sharing a group run in one PipelineInput
    target: dict
    vuln_id: str
    expected_status: str | None
    expected_justification: str | None
    vuln_input: dict | None = None  # full VulnInput (package_hint, notes) when the record carries one


def _records(path: Path) -> list[dict]:
    text = path.read_text()
    if path.suffix == ".csv":
        return list(csv.DictReader(text.splitlines()))
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    data = json.loads(text)
    if isinstance(data, dict):
        for k in ("items", "data", "records", "dataset", "examples"):
            if isinstance(data.get(k), list):
                return data[k]
        return [data]
    return data


def _target_of(r: dict) -> dict:
    if r.get("filesystem_path"):
        return {"filesystem_path": r["filesystem_path"], "kind": r.get("kind", "container"),
                "image_name": r.get("image_name")}
    img = r.get("image") or r.get("container") or r.get("container_image")
    if img and not r.get("image_name"):
        name, _, tag = img.rpartition(":") if ":" in img.rsplit("/", 1)[-1] else (img, "", "latest")
        return {"image_name": name, "image_tag": tag or "latest"}
    return {"image_name": r.get("image_name"), "image_tag": r.get("image_tag") or "latest"}


def load_dataset(path: str | Path, limit: int | None = None) -> list[EvalItem]:
    items: list[EvalItem] = []
    for i, r in enumerate(_records(Path(path))):
        if "input" in r and isinstance(r["input"], dict):
            pin = PipelineInput.model_validate(r["input"])
            exp = r.get("expected") or r.get("ground_truth") or {}
            if isinstance(exp, list):
                exp = {e.get("vuln_id") or e.get("cve_id"): e for e in exp}
            for v in pin.vulnerabilities:
                e = exp.get(v.vuln_id, exp) if isinstance(exp, dict) else {}
                items.append(EvalItem(f"{i}:{v.vuln_id}", pin.target.display_name, pin.target.model_dump(), v.vuln_id,
                                      norm_status(e.get("status") or e.get("label")),
                                      norm_justification(e.get("justification") or e.get("label_justification")),
                                      v.model_dump(exclude_none=True)))
            continue
        vid = r.get("vuln_id") or r.get("cve") or r.get("cve_id") or r.get("vulnerability")
        if not vid:
            continue
        tgt = _target_of(r)
        group = tgt.get("filesystem_path") or f"{tgt.get('image_name')}:{tgt.get('image_tag')}"
        items.append(EvalItem(str(r.get("id", i)), group, tgt, str(vid).strip(),
                              norm_status(r.get("status") or r.get("label") or r.get("vex_status")),
                              norm_justification(r.get("justification") or r.get("label_justification"))))
        if limit and len(items) >= limit:
            break
    return items[:limit] if limit else items


def group_inputs(items: list[EvalItem], base: dict | None = None) -> list[tuple[PipelineInput, list[EvalItem]]]:
    groups: dict[str, list[EvalItem]] = defaultdict(list)
    for it in items:
        groups[it.group].append(it)
    out = []
    for _g, its in groups.items():
        doc = {**(base or {}), "target": its[0].target,
               "vulnerabilities": [i.vuln_input or {"vuln_id": i.vuln_id} for i in its]}
        out.append((PipelineInput.model_validate(doc), its))
    return out
