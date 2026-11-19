"""Write Markdown reports per agent, per-CVE VEX JSON, summary.json and an OpenVEX document."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from jinja2 import Environment, PackageLoader, StrictUndefined

from ..models import (ContainerReport, ExploitabilityReport, Justification, PipelineOutput, RuntimeReport, VexResult,
                      VexStatus, VulnerabilityReport)

_env = Environment(loader=PackageLoader("vulnlens.reports", "templates"), undefined=StrictUndefined,
                   trim_blocks=False, lstrip_blocks=False, autoescape=False)

OPENVEX_JUSTIFICATION = {
    Justification.CODE_NOT_PRESENT: "vulnerable_code_not_present",
    Justification.FALSE_POSITIVE: "component_not_present",
    Justification.CODE_NOT_REACHABLE: "vulnerable_code_not_in_execute_path",
    Justification.REQUIRES_CONFIGURATION: "vulnerable_code_cannot_be_controlled_by_adversary",
    Justification.REQUIRES_DEPENDENCY: "vulnerable_code_cannot_be_controlled_by_adversary",
    Justification.REQUIRES_ENVIRONMENT: "vulnerable_code_cannot_be_controlled_by_adversary",
    Justification.PERIMETER_PROTECTED: "inline_mitigations_already_exist",
    Justification.COMPILER_PROTECTED: "inline_mitigations_already_exist",
    Justification.MITIGATING_CONTROL_PROTECTED: "inline_mitigations_already_exist",
}


def safe_name(s: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", s)[:150]


def _render(name: str, path: Path, **ctx) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_env.get_template(name).render(**ctx))
    return str(path)


def write_container_report(out_dir: Path, cr: ContainerReport, markdown: bool = True) -> dict[str, str]:
    paths = {"container_report_json": str(out_dir / "container_analysis.json")}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "container_analysis.json").write_text(cr.model_dump_json(indent=2))
    if markdown:
        paths["container_report"] = _render("container_analysis.md.j2", out_dir / "container_analysis.md", c=cr)
    return paths


def write_runtime_report(out_dir: Path, rr: RuntimeReport, markdown: bool = True) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "runtime_verification.json").write_text(rr.model_dump_json(indent=2))
    paths = {"runtime_report_json": str(out_dir / "runtime_verification.json")}
    if markdown:
        paths["runtime_report"] = _render("runtime_verification.md.j2", out_dir / "runtime_verification.md", r=rr)
    return paths


def write_cve_reports(out_dir: Path, target: str, vr: VulnerabilityReport, er: ExploitabilityReport, vex: VexResult,
                      container_paths: dict[str, str], markdown: bool = True) -> VexResult:
    d = out_dir / safe_name(vr.vuln_id)
    d.mkdir(parents=True, exist_ok=True)
    paths = dict(container_paths)
    (d / "cve_research.json").write_text(vr.model_dump_json(indent=2))
    (d / "exploitability.json").write_text(er.model_dump_json(indent=2))
    if markdown:
        paths["cve_research"] = _render("cve_research.md.j2", d / "cve_research.md", r=vr)
        paths["exploitability"] = _render("exploitability.md.j2", d / "exploitability.md", e=er, target=target)
        paths["vex_report"] = str(d / "vex.md")
    paths["vex_json"] = str(d / "vex.json")
    vex = vex.model_copy(update={"report_paths": paths})
    if markdown:
        _render("vex.md.j2", d / "vex.md", v=vex)
    (d / "vex.json").write_text(vex.model_dump_json(indent=2))
    return vex


def product_id(target: str, digest: str) -> str:
    if digest.startswith("sha256:") and "@" not in target:
        name = target.rsplit(":", 1)[0] if ":" in target.rsplit("/", 1)[-1] else target
        return f"pkg:oci/{quote(name.rsplit('/', 1)[-1])}@{quote(digest)}?repository_url={quote(name)}"
    return target


def openvex_document(out: PipelineOutput) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    statements = []
    for r in out.results:
        v = r.vex
        st = {"vulnerability": {"name": v.cve_id, "aliases": r.vulnerability_report.aliases},
              "products": [{"@id": product_id(out.target, out.digest)}], "timestamp": now}
        if v.status == VexStatus.NOT_AFFECTED:
            st["status"] = "not_affected"
            st["justification"] = OPENVEX_JUSTIFICATION.get(v.justification, "vulnerable_code_not_present")
            st["impact_statement"] = v.reasoning[:2000]
        elif v.status == VexStatus.AFFECTED:
            st["status"] = "affected"
            st["action_statement"] = (r.vulnerability_report.remediation or "Upgrade to a fixed version.")[:2000]
        else:
            st["status"] = "under_investigation"
        st["status_notes"] = f"vulnlens justification={v.justification.value} verdict=" + (
            v.exploitability_verdict.value if v.exploitability_verdict else "n/a")
        statements.append(st)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:vulnlens:{out.run_id}", "author": "vulnlens",
            "timestamp": now, "version": 1, "statements": statements}


def write_summary(out: PipelineOutput, markdown: bool = True, html: bool = True) -> None:
    d = Path(out.output_dir)
    Path(out.summary_path).write_text(json.dumps(
        {"run_id": out.run_id, "target": out.target, "digest": out.digest,
         "container_type": out.container_report.container_type,
         "runtime_checks": [c.model_dump(mode="json") for c in out.runtime_report.checks] if out.runtime_report else None,
         "results": [r.vex.model_dump(mode="json") for r in out.results]}, indent=2))
    Path(out.openvex_path).write_text(json.dumps(openvex_document(out), indent=2))
    if markdown:
        _render("index.md.j2", d / "index.md", o=out)
    if html:
        from .html import write_html_report

        write_html_report(out, d / "report.html")
