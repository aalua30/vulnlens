"""Container / Target Analyzer.

Phase A (optional, web only): public registry + vendor docs about the image.
Phase B (filesystem only, fresh context): classify the target, map dependencies, inventory entrypoints and
services, record security controls. The deterministic inventory + security scan are injected up front so the
LLM verifies and interprets rather than discovering from scratch.
"""

from __future__ import annotations

import asyncio
import json
import logging

from pydantic import BaseModel, Field

from ..config import Settings
from ..llm import LLMHandle, run_react, react_steps
from ..models import ContainerReport, Entrypoint, SecurityControl, Target, WebFindings
from ..tools import security_controls as sc
from ..tools.registry import ToolContext, analysis_tools, web_tools

log = logging.getLogger(__name__)

WEB_SYSTEM = """You research a container image using ONLY public sources (registry pages such as Docker Hub / Quay /
GHCR / NGC, vendor documentation, the image's source repository). Find: what the image is for, who publishes it,
documented ports/protocols, how it is normally deployed, and documented security posture (non-root user, read-only
fs, hardening guides). Be brief and cite URLs. If nothing reliable is found, say so."""

FS_SYSTEM = """You are a container/host security analyst with read-only access to the target's root filesystem through
tools. The filesystem is ground truth - prefer it over assumptions or SBOMs.

Produce a security-focused profile:
- container_type: one of base-os, language-runtime, web-server, web-app, database, message-queue, ml-inference,
  cli-tool, build-tool, proxy, host-system, other.
- purpose and summary of what actually runs here.
- entrypoints: image ENTRYPOINT/CMD, scripts they call, systemd/supervisord/init services, cron jobs. Follow
  wrapper scripts (docker-entrypoint.sh etc.) to find the real main process.
- key_dependencies: the libraries/frameworks the main process really uses (not every installed package).
- language_runtimes present, exposed/listening ports, network_exposure (how the service is reached).
- security_controls: user, privilege, setuid, capabilities, shells/package managers, MAC, hardening flags, TLS, auth.
Be efficient: a handful of targeted tool calls, not exhaustive crawling."""


class FsAnalysis(BaseModel):
    container_type: str
    summary: str
    purpose: str = ""
    key_dependencies: list[str] = Field(default_factory=list)
    language_runtimes: list[str] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    exposed_ports: list[str] = Field(default_factory=list)
    user: str = ""
    network_exposure: str = ""
    security_controls: list[SecurityControl] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _baseline_controls(scan: dict) -> list[SecurityControl]:
    out = []
    if "runs_as_root" in scan:
        out.append(SecurityControl(name="non_root_user", status="absent" if scan["runs_as_root"] else "present",
                                   detail=f"user={scan.get('image_config', {}).get('user') or 'root(default)'}"))
    out.append(SecurityControl(name="minimal_image (no shell/package manager)",
                               status="present" if scan.get("distroless_like") else "absent",
                               detail=f"shells={scan.get('shell_present')} pkg_mgrs={scan.get('package_managers')}"))
    out.append(SecurityControl(name="setuid_binaries", status="present" if scan.get("setuid_binaries") else "absent",
                               detail=", ".join(scan.get("setuid_binaries", [])[:15])))
    if scan.get("mac"):
        out.append(SecurityControl(name="mandatory_access_control", status="present", detail=json.dumps(scan["mac"])))
    return out


async def analyze_target(
    target: Target,
    digest: str,
    ctx: ToolContext,
    settings: Settings,
    llm_web: LLMHandle,
    llm_fs: LLMHandle,
    skip_web: bool,
) -> ContainerReport:
    inv = ctx.inventory
    report = ContainerReport(target=target.display_name, kind=target.kind, digest=digest,
                             distro={k: v for k, v in inv.distro.items() if k in ("ID", "VERSION_ID", "PRETTY_NAME")},
                             package_counts=inv.counts())
    scan = await asyncio.to_thread(sc.inspect_security_controls, ctx.jail, ctx.image_config, ctx.manifest_path,
                                   target.kind)
    cfg = scan.get("image_config", {})
    services = await asyncio.to_thread(sc.systemd_units, ctx.jail) if target.kind == "host" else []

    # ---- Phase A: web research (isolated context, web tools only) -----------------------------------
    web_summary = ""
    if not skip_web and target.kind == "container" and target.image_name and not target.private:
        try:
            findings, _ = await run_react(
                llm_web, WEB_SYSTEM,
                f"Image: {target.image_ref}\nLabels: {json.dumps(cfg.get('labels', {}))[:2000]}",
                [t for t in web_tools(settings) if t.name in ("web_search", "fetch_url")],
                WebFindings, max_steps=react_steps(settings, llm_web, "container_web", 6),
                max_tool_chars=settings.max_tool_output_chars, label="container:web",
            )
            report.web_findings = findings
            web_summary = findings.model_dump_json()
        except Exception as e:
            log.warning("web phase failed: %s", e)
            report.errors.append(f"web research failed: {e}")

    # ---- Phase B: filesystem analysis (fresh context, fs tools only) ---------------------------------
    task = json.dumps({
        "target": target.display_name, "kind": target.kind,
        "deployment_notes": target.deployment_notes,
        "image_config": cfg,
        "systemd_services": services[:40],
        "inventory_summary": inv.summary(),
        "security_scan": {k: v for k, v in scan.items() if k != "image_config"},
        "public_web_findings": web_summary or "(skipped)",
    }, default=str)[:30000]
    try:
        fa, trace = await run_react(
            llm_fs, FS_SYSTEM, f"Target facts gathered deterministically:\n{task}", analysis_tools(ctx), FsAnalysis,
            max_steps=react_steps(settings, llm_fs, "container_fs", 14), max_tool_chars=settings.max_tool_output_chars, label="container:fs",
        )
        report.container_type = fa.container_type
        report.summary, report.purpose = fa.summary, fa.purpose
        report.key_dependencies, report.language_runtimes = fa.key_dependencies, fa.language_runtimes
        report.entrypoints = fa.entrypoints
        report.exposed_ports = sorted(set(fa.exposed_ports) | set(cfg.get("exposed_ports", [])))
        report.user = fa.user or cfg.get("user", "")
        report.network_exposure = fa.network_exposure
        names = {c.name for c in fa.security_controls}
        report.security_controls = fa.security_controls + [c for c in _baseline_controls(scan) if c.name not in names]
        report.notes = fa.notes
        if trace.exhausted:
            report.notes.append("filesystem analysis step budget exhausted")
    except Exception as e:
        log.exception("filesystem analysis failed")
        report.errors.append(f"filesystem analysis failed: {e}")
        report.security_controls = _baseline_controls(scan)
        report.exposed_ports = cfg.get("exposed_ports", [])
        report.user = cfg.get("user", "")
        for kind in ("entrypoint", "cmd"):
            if cfg.get(kind):
                report.entrypoints.append(Entrypoint(kind=kind, command=" ".join(cfg[kind]), source="image config"))
        for s in services:
            report.entrypoints.append(Entrypoint(kind="systemd", command=s["exec"], source=s["unit"]))
        report.container_type = "host-system" if target.kind == "host" else "unknown"
    return report
