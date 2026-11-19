"""CVE Researcher: deterministic intel from NVD / GHSA / OSV, then an LLM web-research pass (Tavily + fetch)
to fill gaps (vulnerable functions, attack preconditions, vendor/distro guidance). Output: VulnerabilityReport."""

from __future__ import annotations

import asyncio
import json
import logging

from pydantic import BaseModel, Field

from ..config import Settings
from ..llm import LLMHandle, run_react, react_steps
from ..models import AffectedPackage, VulnerabilityReport, VulnInput
from ..tools import web
from ..tools.registry import web_tools

log = logging.getLogger(__name__)

GHSA_ECO = {"pip": "pypi", "npm": "npm", "maven": "maven", "go": "go", "rubygems": "gem", "nuget": "nuget",
            "composer": "composer", "rust": "cargo", "erlang": "hex", "pub": "pub", "swift": "swift"}

SYSTEM = """You are a senior vulnerability researcher. Build an accurate, evidence-backed profile of ONE vulnerability
so a downstream analyst can decide whether a specific container or host is exploitable.

Priorities:
1. Exactly which packages/components and version ranges are affected (upstream AND distro-specific if known).
2. The vulnerable functions, methods, classes, modules, CLI flags or config options - be concrete (symbol names),
   using patch commits and advisories. This is what reachability analysis will grep for.
3. Attack vector and preconditions (network-reachable? needs a specific config/feature/protocol? authentication?
   attacker-controlled input to which API?).
4. Fixed versions and remediation / workarounds.

Rules: use the provided intel first; use tools only to fill real gaps (patch commit, vendor advisory). Never invent
version numbers or function names - leave a field empty if unknown. Cite URLs you relied on in `references`."""


class ResearchFindings(BaseModel):
    summary: str = Field(description="2-4 sentence technical summary")
    vulnerable_functions: list[str] = Field(default_factory=list)
    vulnerable_files: list[str] = Field(default_factory=list)
    attack_vector: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    exploit_available: bool | None = None
    remediation: str = ""
    additional_affected_packages: list[AffectedPackage] = Field(
        default_factory=list, description="Only packages/ranges NOT already in the intel, with evidence. `name` must be "
        "the bare package name (e.g. 'nginx', not 'nginx (ngx_http_v2_module)'); use `component` for modules")
    references: list[str] = Field(default_factory=list)


def gather_intel(settings: Settings, vuln_id: str) -> dict:
    """Deterministic multi-source fetch. Every source is optional."""
    intel: dict = {"errors": []}
    try:
        if vuln_id.startswith("CVE-"):
            rec = web.nvd_lookup(settings, vuln_id)
            if rec:
                intel["nvd"] = web.summarize_nvd(rec)
    except Exception as e:
        intel["errors"].append(f"nvd: {e}")
    try:
        intel["ghsa"] = web.ghsa_lookup(settings, vuln_id)
    except Exception as e:
        intel["errors"].append(f"ghsa: {e}")
    osv_ids = [vuln_id] + [g["ghsa_id"] for g in intel.get("ghsa", []) if g.get("ghsa_id")]
    if vuln_id.startswith("CVE-"):
        osv_ids += [f"DEBIAN-{vuln_id}", f"UBUNTU-{vuln_id}"]
    intel["osv"] = []
    seen = set()
    for oid in osv_ids:
        if oid in seen:
            continue
        seen.add(oid)
        try:
            rec = web.osv_get(settings, oid)
        except Exception as e:
            intel["errors"].append(f"osv {oid}: {e}")
            continue
        if rec:
            intel["osv"].append(rec)
    return intel


def deterministic_affected(intel: dict) -> tuple[list[AffectedPackage], list[str]]:
    pkgs: list[AffectedPackage] = []
    funcs: list[str] = []
    for rec in intel.get("osv", []):
        for a in web.osv_to_affected(rec):
            funcs += a.pop("_functions", [])
            pkgs.append(AffectedPackage(**a))
    for g in intel.get("ghsa", []):
        for v in g.get("vulnerabilities", []):
            if not v.get("name"):
                continue
            eco = GHSA_ECO.get((v.get("ecosystem") or "").lower(), "generic")
            rng = [{"expr": v["vulnerable_version_range"]}] if v.get("vulnerable_version_range") else []
            fixed = [v["first_patched_version"]] if v.get("first_patched_version") else []
            pkgs.append(AffectedPackage(name=v["name"], ecosystem=eco, ranges=rng, fixed_versions=fixed,
                                        source=f"ghsa:{g.get('ghsa_id')}"))
            funcs += v.get("vulnerable_functions") or []
    if intel.get("nvd"):
        for a in web.cpe_to_affected(intel["nvd"].get("cpe_matches", [])):
            pkgs.append(AffectedPackage(**a))
    return _dedupe(pkgs), sorted(set(funcs))


def _dedupe(pkgs: list[AffectedPackage]) -> list[AffectedPackage]:
    by: dict[tuple, AffectedPackage] = {}
    for p in pkgs:
        k = (p.ecosystem, p.name.lower(), p.distro)
        if k in by:
            e = by[k]
            e.ranges += [r for r in p.ranges if r not in e.ranges]
            e.fixed_versions += [f for f in p.fixed_versions if f not in e.fixed_versions]
            if p.source not in e.source:
                e.source += f",{p.source}"
        else:
            by[k] = p.model_copy(deep=True)
    return list(by.values())


def _compact_intel(intel: dict, affected: list[AffectedPackage], max_chars: int = 24000) -> str:
    view = {
        "nvd": {k: v for k, v in (intel.get("nvd") or {}).items() if k != "cpe_matches"},
        "ghsa": [{k: g[k] for k in ("ghsa_id", "summary", "description", "severity", "cwes", "references") if k in g}
                 for g in intel.get("ghsa", [])],
        "osv": [{"id": r.get("id"), "aliases": r.get("aliases"), "summary": r.get("summary"),
                 "details": (r.get("details") or "")[:3000],
                 "references": [x.get("url") for x in (r.get("references") or [])][:25]} for r in intel.get("osv", [])],
        "affected_packages_from_databases": [
            {"name": a.name, "ecosystem": a.ecosystem, "distro": a.distro, "fixed": a.fixed_versions[:6],
             "ranges": a.ranges[:4]} for a in affected[:40]],
    }
    s = json.dumps(view, ensure_ascii=False)
    return s[:max_chars]


async def research_cve(vuln: VulnInput, settings: Settings, llm: LLMHandle) -> VulnerabilityReport:
    vid = vuln.vuln_id
    intel = await asyncio.to_thread(gather_intel, settings, vid)
    affected, db_funcs = deterministic_affected(intel)
    nvd = intel.get("nvd") or {}
    ghsa0 = (intel.get("ghsa") or [{}])[0] if intel.get("ghsa") else {}
    aliases = sorted({a for r in intel.get("osv", []) for a in (r.get("aliases") or [])} |
                     {g["ghsa_id"] for g in intel.get("ghsa", []) if g.get("ghsa_id")} - {vid})
    report = VulnerabilityReport(
        vuln_id=vid,
        aliases=aliases,
        description=nvd.get("description") or ghsa0.get("description") or next(
            (r.get("details", "") for r in intel.get("osv", []) if r.get("details")), ""),
        summary=ghsa0.get("summary") or next((r.get("summary", "") for r in intel.get("osv", []) if r.get("summary")), ""),
        cwe=nvd.get("cwe") or [c for c in ghsa0.get("cwes", []) if c],
        cvss_score=nvd.get("cvss_score"),
        cvss_vector=nvd.get("cvss_vector"),
        severity=(nvd.get("severity") or ghsa0.get("severity") or None),
        affected_packages=affected,
        vulnerable_functions=db_funcs,
        references=(nvd.get("references") or [])[:30],
        errors=list(intel.get("errors", [])),
    )
    if not (intel.get("nvd") or intel.get("ghsa") or intel.get("osv")):
        report.errors.append("no public database record found")

    task = (f"Vulnerability: {vid}\n"
            + (f"Scanner flagged package: {vuln.package_hint}\n" if vuln.package_hint else "")
            + (f"Analyst notes: {vuln.notes}\n" if vuln.notes else "")
            + f"\nIntel already gathered (JSON):\n{_compact_intel(intel, affected)}")
    try:
        findings, trace = await run_react(
            llm, SYSTEM, task, web_tools(settings), ResearchFindings,
            max_steps=react_steps(settings, llm, "cve_researcher", 8),
            max_tool_chars=settings.max_tool_output_chars,
            final_instruction="Stop researching. Produce the final research findings.",
            label=f"research {report.vuln_id}",
        )
        report.summary = findings.summary or report.summary
        report.vulnerable_functions = sorted(set(report.vulnerable_functions) | set(findings.vulnerable_functions))
        report.vulnerable_files = findings.vulnerable_files
        report.attack_vector = findings.attack_vector
        report.preconditions = findings.preconditions
        report.exploit_available = findings.exploit_available
        report.remediation = findings.remediation
        extra = [p.model_copy(update={"source": "llm"}) for p in findings.additional_affected_packages]
        report.affected_packages = _dedupe(report.affected_packages + extra)
        report.references = list(dict.fromkeys(findings.references + report.references))[:50]
        if trace.exhausted:
            report.errors.append("research step budget exhausted")
    except Exception as e:
        log.exception("LLM research failed for %s", vid)
        report.errors.append(f"llm research failed: {e}")
        report.research_complete = bool(report.affected_packages)
    if vuln.package_hint and not any(p.name.lower() == vuln.package_hint.lower() for p in report.affected_packages):
        report.affected_packages.append(AffectedPackage(name=vuln.package_hint, ecosystem="generic", source="scanner"))
    return report
