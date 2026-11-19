"""Self-contained HTML report (one file, no external assets except Google Fonts with system fallbacks).

`write_html_report(out, path)` is called at the end of every run; `load_run(run_dir)` rebuilds a PipelineOutput
from a finished run directory so `vulnlens report <run_dir>` can regenerate the page later.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from ..models import (ContainerReport, CveResult, ExploitabilityReport, PipelineOutput, RuntimeReport, Verdict,
                      VexResult, VexStatus, VulnerabilityReport)

_env = Environment(loader=PackageLoader("vulnlens.reports", "templates"), autoescape=select_autoescape(["html", "j2"]))

JUST_LABEL = {
    "false_positive": "False positive", "code_not_present": "Code not present",
    "code_not_reachable": "Code not reachable", "requires_configuration": "Requires configuration",
    "requires_dependency": "Requires dependency", "requires_environment": "Requires environment",
    "compiler_protected": "Compiler protected", "perimeter_protected": "Perimeter protected",
    "mitigating_control_protected": "Mitigating control", "vulnerable": "Vulnerable", "uncertain": "Uncertain",
}
_STATUS_ORDER = {VexStatus.AFFECTED: 0, VexStatus.UNKNOWN: 1, VexStatus.NOT_AFFECTED: 2}
_VERDICT_ORDER = {v: i for i, v in enumerate([Verdict.EXPLOITABLE, Verdict.CONDITIONALLY_EXPLOITABLE, Verdict.MITIGATED,
                                              Verdict.ENVIRONMENT_ISOLATED, Verdict.NOT_REACHABLE,
                                              Verdict.NOT_APPLICABLE])}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3}
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}


def _first_sentences(text: str, n: int = 1, limit: int = 400) -> str:
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    out = " ".join(parts[:n]).strip()
    return out if len(out) <= limit else out[: limit - 1].rstrip() + "…"


def _package(r: CveResult) -> str:
    """The installed package the verdict is about: the found one the reasoning talks about most."""
    subject = (r.vulnerability_report.summary or r.vulnerability_report.description)[:400].lower()
    text = (r.vex.reasoning + " " + r.exploitability_report.summary).lower()

    def score(p) -> tuple:
        word = re.compile(rf"(?<![\w-]){re.escape(p.package.lower())}(?![\w-])")
        return (len(word.findall(subject)), len(word.findall(text)), p.vulnerable is True)

    found = [p for p in r.exploitability_report.pretriage if p.found and p.installed]
    if found:
        best = max(found, key=score)
        i = best.installed[0]
        return f"{i.get('name') or best.package} {i.get('version', '')}".strip()
    if r.vulnerability_report.affected_packages:
        return r.vulnerability_report.affected_packages[0].name
    return ""


def _band(v: VexResult) -> str:
    if v.status == VexStatus.AFFECTED:
        return "bad"
    if v.status == VexStatus.UNKNOWN:
        return "unknown"
    return "warn" if v.exploitability_verdict == Verdict.CONDITIONALLY_EXPLOITABLE else "ok"


def _finding(r: CveResult) -> dict:
    v, vr, er = r.vex, r.vulnerability_report, r.exploitability_report
    sev = (vr.severity or "").lower()
    return {
        "id": v.cve_id, "anchor": re.sub(r"[^\w-]", "-", v.cve_id), "package": _package(r), "band": _band(v),
        "status": v.status.value, "justification": v.justification.value,
        "just_label": JUST_LABEL.get(v.justification.value, v.justification.value),
        "verdict": v.exploitability_verdict.value if v.exploitability_verdict else "n/a",
        "confidence": v.confidence, "severity": sev, "cvss": vr.cvss_score,
        "summary": _first_sentences(vr.summary or vr.description, 1, 320), "reasoning": v.reasoning,
        "conditions": er.conditions, "conditions_met": er.conditions_met, "chain": er.reachability_chain,
        "remediation": vr.remediation, "verification": er.verification, "errors": v.errors + er.errors,
    }


def _ports(out: PipelineOutput, attention: list[dict]) -> list[dict]:
    cr, facts = out.container_report, (out.runtime_report.facts if out.runtime_report else {}) or {}
    published = facts.get("published_ports") or {}
    seen: dict[str, dict] = {}
    for raw in list(cr.exposed_ports) + list(facts.get("exposed_ports") or []) + list(published):
        m = re.search(r"\d{1,5}", str(raw))
        if not m:
            continue
        port = m.group(0)
        proto = "udp" if "udp" in str(raw) else "tcp"
        row = seen.setdefault(port, {"port": port, "proto": proto, "note": "", "published": [], "findings": []})
        note = re.sub(rf"^\s*{port}(/\w+)?\s*[-:]?\s*", "", str(raw)).strip()
        if note.startswith("(") and note.endswith(")"):
            note = note[1:-1]
        if note and not row["note"]:
            row["note"] = note
    for key, binds in published.items():
        m = re.search(r"\d{1,5}", key)
        if m and m.group(0) in seen:
            seen[m.group(0)]["published"] = binds
    for f in attention:
        blob = " ".join([f["reasoning"], *f["conditions"], *f["chain"]])
        for port, row in seen.items():
            if re.search(rf"(?<![\d.]){port}(?!\d)", blob):
                row["findings"].append(f)
    return sorted(seen.values(), key=lambda r: int(r["port"]))


def _actions(findings: list[dict], runtime: RuntimeReport | None) -> list[dict]:
    acts = []
    for f in findings:
        if f["band"] == "bad":
            fix = _first_sentences(f["remediation"], 2, 420) or "Upgrade the component to a fixed version."
            acts.append({"title": f"Fix {f['id']}" + (f" in {f['package']}" if f["package"] else ""), "body": fix,
                         "rank": (0, _SEV_ORDER.get(f["severity"], 5))})
    if runtime:
        for c in runtime.checks:
            if c.status == "issue":
                acts.append({"title": c.title, "body": c.recommendation or c.evidence,
                             "rank": (1, _RISK_ORDER.get(c.severity, 5))})
    for f in findings:
        if f["band"] == "warn":
            acts.append({"title": f"Review {f['id']}" + (f" in {f['package']}" if f["package"] else ""),
                         "body": "The vulnerable code is reachable, but the exploitation conditions were judged not "
                                 "met here. Re-assess if any of the conditions below change.",
                         "rank": (2, _SEV_ORDER.get(f["severity"], 5))})
        elif f["band"] == "unknown":
            acts.append({"title": f"Finish the analysis of {f['id']}",
                         "body": "The automated analysis did not complete; rerun it or review by hand.",
                         "rank": (3, 0)})
    return sorted(acts, key=lambda a: a["rank"])


def build_view(out: PipelineOutput) -> dict:
    results = sorted(out.results, key=lambda r: (
        _STATUS_ORDER.get(r.vex.status, 3), _VERDICT_ORDER.get(r.vex.exploitability_verdict, 9),
        _SEV_ORDER.get((r.vulnerability_report.severity or "").lower(), 9), r.vex.cve_id))
    findings = [_finding(r) for r in results]
    attention = [f for f in findings if f["band"] != "ok"]
    rest = [f for f in findings if f["band"] == "ok"]
    just_counts: dict[str, int] = {}
    for f in findings:
        if f["status"] == "not_affected":
            just_counts[f["justification"]] = just_counts.get(f["justification"], 0) + 1
    cr, rr = out.container_report, out.runtime_report
    try:
        assessed = datetime.strptime(out.run_id[:16], "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%d")
    except ValueError:
        assessed = ""
    meta = []
    if rr and rr.facts.get("image"):
        meta.append(("Image", rr.facts["image"]))
    meta.append(("Type", cr.container_type))
    if cr.distro.get("PRETTY_NAME"):
        meta.append(("OS", cr.distro["PRETTY_NAME"]))
    meta += [("Runtime", x) for x in cr.language_runtimes[:2]]
    if assessed:
        meta.append(("Assessed", assessed))
    meta.append(("Run", out.run_id))
    peers = sum((n.get("peer_count") or 0) for n in (rr.facts.get("networks") or {}).values()) if rr else None
    verified = [f for f in findings if f["verification"] is not None]
    return {
        "o": out, "cr": cr, "rr": rr, "meta": meta, "lede": _first_sentences(cr.summary, 2, 500),
        "n": len(findings), "n_affected": sum(f["band"] == "bad" for f in findings),
        "n_borderline": sum(f["band"] == "warn" for f in findings),
        "n_unknown": sum(f["band"] == "unknown" for f in findings),
        "n_not_affected": sum(f["status"] == "not_affected" for f in findings),
        "just_counts": sorted(just_counts.items(), key=lambda kv: -kv[1]), "just_label": JUST_LABEL,
        "attention": attention, "rest": rest, "actions": _actions(findings, rr), "ports": _ports(out, attention),
        "peers": peers, "verified": verified,
        "posture_issues": [c for c in rr.checks if c.status == "issue"] if rr else [],
        "posture_other": [c for c in rr.checks if c.status != "issue"] if rr else [],
    }


def render_html(out: PipelineOutput, standalone: bool = True) -> str:
    """standalone=True gives a complete document for opening locally; False gives the head-less fragment that
    page hosts which add their own document skeleton (e.g. claude.ai Artifacts) expect."""
    body = _env.get_template("report.html.j2").render(**build_view(out))
    return f'<!doctype html>\n<html lang="en">\n{body}\n</html>\n' if standalone else body


def write_html_report(out: PipelineOutput, path: str | Path, standalone: bool = True) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(out, standalone))
    return str(path)


def load_run(run_dir: str | Path) -> PipelineOutput:
    """Rebuild a PipelineOutput from the files a run wrote (summary.json + per-CVE JSON reports)."""
    d = Path(run_dir)
    summ = json.loads((d / "summary.json").read_text())
    cr = ContainerReport.model_validate_json((d / "container_analysis.json").read_text())
    rr = None
    if (d / "runtime_verification.json").exists():
        rr = RuntimeReport.model_validate_json((d / "runtime_verification.json").read_text())
    results = []
    for v in summ["results"]:
        vex = VexResult.model_validate(v)
        sub = Path(vex.report_paths.get("vex_json", d / vex.cve_id / "vex.json")).parent
        if not sub.exists():
            sub = d / re.sub(r"[^\w.\-]+", "_", vex.cve_id)
        vr = (VulnerabilityReport.model_validate_json((sub / "cve_research.json").read_text())
              if (sub / "cve_research.json").exists() else VulnerabilityReport(vuln_id=vex.cve_id))
        er = (ExploitabilityReport.model_validate_json((sub / "exploitability.json").read_text())
              if (sub / "exploitability.json").exists() else ExploitabilityReport(vuln_id=vex.cve_id))
        results.append(CveResult(vulnerability_report=vr, exploitability_report=er, vex=vex))
    return PipelineOutput(run_id=summ["run_id"], target=summ["target"], digest=summ["digest"], container_report=cr,
                          results=results, runtime_report=rr, output_dir=str(d),
                          summary_path=str(d / "summary.json"), openvex_path=str(d / "openvex.json"))
