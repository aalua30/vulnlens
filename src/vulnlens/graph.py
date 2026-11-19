"""Top-level LangGraph workflow.

    resolve_target ──► analyze_container ─────────────┐
                  └──► research_cve  (Send, per CVE) ─┴─► dispatch ──► analyze_cve (Send, per CVE) ──► finalize

* Target analysis runs once and is shared by all CVEs; CVE research runs in parallel with it.
* analyze_cve = exploitability (pre-triage + deep) → [live verification] → VEX categorization → per-CVE reports.
* With options.live_verification and target.runtime, the live verifier also runs posture checks on the running
  target right after the container analysis, and re-checks runtime-dependent verdicts per CVE.
* Every agent output is cached on disk (vulnlens.cache), so re-runs / interrupted runs resume cheaply.
"""

from __future__ import annotations

import asyncio
import time
import logging
import operator
from collections import Counter
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from .agents import (analyze_exploitability, analyze_target, apply_verification, assess_posture, categorize,
                     needs_verification, research_cve, verify_cve)
from .cache import AgentCache, stable_hash
from .llm_cache import cache_stats
from .config import Settings, load_settings
from .llm import LLMHandle, get_llm
from .skills import Playbooks, Skill, SkillStore, select_skills, use_playbooks
from .skills.signals import write_experience
from .models import (ContainerReport, CveResult, ExploitabilityReport, Justification, PipelineInput, PipelineOutput,
                     RuntimeReport, VexResult, VexStatus, VulnerabilityReport, VulnInput)
from .reports.render import (safe_name, write_container_report, write_cve_reports, write_runtime_report,
                             write_summary)
from .tools.runtime import LiveTarget
from .rootfs import ResolvedRootfs, resolve_target
from .agents.exploitability import PRETRIAGE_VERSION
from .tools import Jail, ToolContext, load_or_build_inventory
from .tools.inventory import INVENTORY_VERSION

log = logging.getLogger(__name__)


def _merge(a: dict | None, b: dict | None) -> dict:
    return {**(a or {}), **(b or {})}


class State(TypedDict, total=False):
    input: dict
    run_id: str
    out_dir: str
    rootfs: dict
    container_report: dict
    container_paths: dict
    runtime_report: dict
    vuln_reports: Annotated[dict, _merge]
    results: Annotated[dict, _merge]
    errors: Annotated[list, operator.add]
    output: dict


@dataclass
class Runtime:
    """Non-serializable per-run objects, passed through config['configurable']['runtime']."""
    settings: Settings
    cache: AgentCache
    inp: PipelineInput
    ctx: ToolContext | None = None
    live: LiveTarget | None = None
    runtime_report: RuntimeReport | None = None
    llms: dict[str, LLMHandle] = field(default_factory=dict)
    skills: list[Skill] = field(default_factory=list)
    experience: list[dict] = field(default_factory=list)   # per-loop records for the learning loop

    def playbooks(self, agent: str, packages=(), cwes=(), text: str = "") -> Playbooks | None:
        if not self.skills:
            return None
        distro = (self.ctx.inventory.distro.get("ID") if self.ctx else None) or None
        s = self.settings.skills
        return select_skills(self.skills, agent, packages, cwes, distro, text, s.max_chars, s.max_skills)

    def llm(self, agent: str) -> LLMHandle:
        o = self.inp.options
        profile = o.llm_profile or o.llm_overrides.get(agent)
        key = f"{agent}:{profile}"
        if key not in self.llms:
            fresh = not self.cache.enabled or agent in self.cache.refresh
            self.llms[key] = get_llm(self.settings, agent, profile, use_cache=not fresh)
        return self.llms[key]


def _rt(config: RunnableConfig) -> Runtime:
    return config["configurable"]["runtime"]


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def resolve_node(state: State, config: RunnableConfig) -> dict:
    rt = _rt(config)
    t = rt.inp.target
    rf: ResolvedRootfs = await asyncio.to_thread(resolve_target, t, rt.settings)
    jail = Jail(rf.path)
    inv = await asyncio.to_thread(load_or_build_inventory, jail, rf.digest, rt.settings.cache_dir,
                                  "inventory" in rt.cache.refresh)
    rt.ctx = ToolContext(settings=rt.settings, jail=jail, inventory=inv, image_config=rf.image_config,
                         manifest_path=rf.manifest_path, kind=t.kind)
    out_dir = Path(state["out_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "inventory.json").write_text(__import__("json").dumps(inv.to_dict(), indent=1))
    log.info("rootfs %s (%s, source=%s) inventory=%s", rf.path, rf.digest, rf.source, inv.counts())
    return {"rootfs": rf.to_dict()}


def fanout_after_resolve(state: State) -> list[Send]:
    inp = PipelineInput.model_validate(state["input"])
    sends = [Send("analyze_container", state)]
    sends += [Send("research_cve", {"vuln": v.model_dump()}) for v in inp.vulnerabilities]
    return sends


async def container_node(state: State, config: RunnableConfig) -> dict:
    rt = _rt(config)
    t = rt.inp.target
    digest = state["rootfs"]["digest"]
    skip_web = rt.inp.options.skip_web_research
    llm_fs = rt.llm("container_analyzer")
    manifest = rt.ctx.manifest_path if rt.ctx else None
    pb = rt.playbooks("container_analyzer", text=f"{t.display_name} {t.deployment_notes or ''}")
    key = {"digest": digest, "skip_web": skip_web, "kind": t.kind, "notes": t.deployment_notes,
           "name": t.display_name, "llm": llm_fs.ident,
           # setuid/setgid records change the security-controls profile; a profile built without them is stale
           "manifest": stable_hash(Path(manifest).read_text()) if manifest and Path(manifest).exists() else None}
    if pb and pb.hash:
        key["skills"] = pb.hash  # only when set, so cache entries from runs without skills stay valid
    cached = rt.cache.get("container_analyzer", key)
    t0 = time.monotonic()
    if cached:
        cr = ContainerReport.model_validate(cached)
        log.info("[container] cache hit (%s)", cr.container_type)
    else:
        log.info("[container] analyzing %s (web research %s)", t.display_name, "skipped" if skip_web else "on")
        try:
            with use_playbooks(pb, rt.experience, agent="container_analyzer"):
                cr = await analyze_target(t, digest, rt.ctx, rt.settings, llm_fs, llm_fs, skip_web)
        except Exception as e:
            log.exception("container analysis crashed")
            cr = ContainerReport(target=t.display_name, kind=t.kind, digest=digest, errors=[f"crashed: {e}"])
        if not any("failed" in e or "crashed" in e for e in cr.errors):
            rt.cache.put("container_analyzer", key, cr.model_dump(mode="json"))
        log.info("[container] finished in %.1fs: type=%s errors=%d", time.monotonic() - t0, cr.container_type,
                 len(cr.errors))
    paths = write_container_report(Path(state["out_dir"]), cr, rt.inp.output.write_markdown)
    upd = {"container_report": cr.model_dump(mode="json"), "container_paths": paths}
    if rt.inp.options.live_verification:
        upd["runtime_report"] = (await _posture(rt, cr, Path(state["out_dir"]))).model_dump(mode="json")
    return upd


async def _posture(rt: Runtime, cr: ContainerReport, out_dir: Path) -> RuntimeReport:
    """Live posture checks (never cached: the running target changes independently of its image)."""
    spec = rt.inp.target.runtime
    if spec is None:
        rep = RuntimeReport(engine="none", errors=["live_verification requested but target.runtime is not set"])
    else:
        t0 = time.monotonic()
        log.info("[live] posture checks on %s (%s)", spec.container or "local host", spec.engine)
        try:
            rt.live = LiveTarget(spec, rt.settings.live_probes)
            pb = rt.playbooks("live_verifier", text=cr.summary)
            with use_playbooks(pb, rt.experience, agent="live_verifier"):
                rep = await assess_posture(cr, rt.live, rt.settings, rt.llm("live_verifier"))
        except Exception as e:
            log.exception("posture checks crashed")
            rep = RuntimeReport(engine=spec.engine, container=spec.container, errors=[f"crashed: {e}"])
        if not rep.available:
            rt.live = None
        log.info("[live] posture finished in %.1fs: %d checks, %d issues, %d probes, errors=%d",
                 time.monotonic() - t0, len(rep.checks), sum(c.status == "issue" for c in rep.checks),
                 len(rep.probes), len(rep.errors))
    rt.runtime_report = rep
    write_runtime_report(out_dir, rep, rt.inp.output.write_markdown)
    return rep


async def research_node(payload: dict, config: RunnableConfig) -> dict:
    rt = _rt(config)
    v = VulnInput.model_validate(payload["vuln"])
    llm = rt.llm("cve_researcher")
    pb = rt.playbooks("cve_researcher", packages=[v.package_hint] if v.package_hint else [],
                      text=f"{v.vuln_id} {v.package_hint or ''} {v.notes or ''}")
    key = {"vuln": v.vuln_id, "hint": v.package_hint, "notes": v.notes, "llm": llm.ident}
    if pb and pb.hash:
        key["skills"] = pb.hash  # only when set, so existing cache entries stay valid without skills
    cached = rt.cache.get("cve_researcher", key)
    t0 = time.monotonic()
    if cached:
        vr = VulnerabilityReport.model_validate(cached)
        log.info("[research %s] cache hit", v.vuln_id)
    else:
        log.info("[research %s] started", v.vuln_id)
        try:
            with use_playbooks(pb, rt.experience, agent="cve_researcher", vuln=v.vuln_id):
                vr = await research_cve(v, rt.settings, llm)
        except Exception as e:
            log.exception("research crashed for %s", v.vuln_id)
            vr = VulnerabilityReport(vuln_id=v.vuln_id, research_complete=False, errors=[f"crashed: {e}"])
        if vr.research_complete and not any("failed" in e or "crashed" in e for e in vr.errors):
            rt.cache.put("cve_researcher", key, vr.model_dump(mode="json"))
        log.info("[research %s] finished in %.1fs: %d affected packages, complete=%s, errors=%d", v.vuln_id,
                 time.monotonic() - t0, len(vr.affected_packages), vr.research_complete, len(vr.errors))
    return {"vuln_reports": {v.vuln_id: vr.model_dump(mode="json")}}


async def dispatch_node(state: State) -> dict:
    return {}


def fanout_cves(state: State) -> list[Send]:
    return [Send("analyze_cve", {"vuln_id": vid, "vuln_report": vr, "container_report": state["container_report"],
                                 "container_paths": state.get("container_paths", {}), "out_dir": state["out_dir"],
                                 "digest": state["rootfs"]["digest"]})
            for vid, vr in state["vuln_reports"].items()]


async def analyze_cve_node(payload: dict, config: RunnableConfig) -> dict:
    rt = _rt(config)
    vr = VulnerabilityReport.model_validate(payload["vuln_report"])
    cr = ContainerReport.model_validate(payload["container_report"])
    digest, notes = payload["digest"], rt.inp.target.deployment_notes
    relaxed = rt.inp.options.relaxed_vex
    try:
        llm_x = rt.llm("exploitability")
        xkey = {"vuln": vr.vuln_id, "digest": digest, "vr": stable_hash(payload["vuln_report"]),
                "cr": stable_hash(payload["container_report"]), "notes": notes, "llm": llm_x.ident,
                "logic": PRETRIAGE_VERSION, "inv": INVENTORY_VERSION}
        pb = rt.playbooks("exploitability", packages=[p.name for p in vr.affected_packages], cwes=vr.cwe,
                          text=f"{vr.vuln_id} {vr.summary}")
        if pb and pb.hash:
            xkey["skills"] = pb.hash
        cached = rt.cache.get("exploitability", xkey)
        t0 = time.monotonic()
        if cached:
            er = ExploitabilityReport.model_validate(cached)
            log.info("[exploitability %s] cache hit: %s", vr.vuln_id, er.verdict)
        else:
            log.info("[exploitability %s] started", vr.vuln_id)
            with use_playbooks(pb, rt.experience, agent="exploitability", vuln=vr.vuln_id):
                er = await analyze_exploitability(vr, cr, rt.ctx, rt.settings, llm_x, notes)
            log.info("[exploitability %s] finished in %.1fs: verdict=%s%s confidence=%.2f", vr.vuln_id,
                     time.monotonic() - t0, er.verdict.value if er.verdict else None,
                     " (pre-triage early exit)" if er.early_exit else "", er.confidence or 0)
            if er.complete:
                rt.cache.put("exploitability", xkey, er.model_dump(mode="json"))

        if rt.live is not None and needs_verification(er, rt.settings):
            t0 = time.monotonic()
            log.info("[live %s] verifying static verdict %s", vr.vuln_id, er.verdict.value)
            pbl = rt.playbooks("live_verifier", packages=[p.name for p in vr.affected_packages], cwes=vr.cwe,
                               text=vr.vuln_id)
            with use_playbooks(pbl, rt.experience, agent="live_verifier", vuln=vr.vuln_id):
                ver = await verify_cve(vr, er, cr, rt.runtime_report, rt.live, rt.settings,
                                       rt.llm("live_verifier"))
            er = apply_verification(er, ver)
            log.info("[live %s] %s in %.1fs (%d probes): verdict=%s conditions_met=%s", vr.vuln_id, ver.outcome,
                     time.monotonic() - t0, len(ver.probes), er.verdict.value if er.verdict else None,
                     er.conditions_met)

        llm_v = rt.llm("vex_categorizer")
        vkey = {"vuln": vr.vuln_id, "digest": digest, "er": stable_hash(er.model_dump(mode="json")),
                "relaxed": relaxed, "llm": llm_v.ident}
        cached = rt.cache.get("vex_categorizer", vkey)
        if cached:
            vex = VexResult.model_validate(cached)
        else:
            vex = await categorize(vr, cr, er, rt.settings, llm_v, relaxed)
            log.info("[vex %s] %s / %s", vr.vuln_id, vex.status.value, vex.justification.value)
            if vex.status != VexStatus.UNKNOWN and not any("failed" in e for e in vex.errors):
                rt.cache.put("vex_categorizer", vkey, vex.model_dump(mode="json"))
    except Exception as e:
        log.exception("analysis crashed for %s", vr.vuln_id)
        er = ExploitabilityReport(vuln_id=vr.vuln_id, errors=[f"crashed: {e}"])
        vex = VexResult(cve_id=vr.vuln_id, container=cr.target, status=VexStatus.UNKNOWN,
                        justification=Justification.UNCERTAIN, reasoning=f"Analysis failed: {e}",
                        container_type=cr.container_type, relaxed_mode=relaxed, errors=[str(e)])
    vex = write_cve_reports(Path(payload["out_dir"]), cr.target, vr, er, vex, payload["container_paths"],
                            rt.inp.output.write_markdown)
    res = CveResult(vulnerability_report=vr, exploitability_report=er, vex=vex)
    return {"results": {vr.vuln_id: res.model_dump(mode="json")}}


async def finalize_node(state: State, config: RunnableConfig) -> dict:
    rt = _rt(config)
    order = [v.vuln_id for v in rt.inp.vulnerabilities]
    results = [CveResult.model_validate(state["results"][vid]) for vid in order if vid in state["results"]]
    out_dir = Path(state["out_dir"])
    cr = ContainerReport.model_validate(state["container_report"])
    rr = state.get("runtime_report")
    out = PipelineOutput(run_id=state["run_id"], target=cr.target, digest=state["rootfs"]["digest"],
                         container_report=cr, results=results, output_dir=str(out_dir),
                         runtime_report=RuntimeReport.model_validate(rr) if rr else None,
                         summary_path=str(out_dir / "summary.json"), openvex_path=str(out_dir / "openvex.json"))
    write_summary(out, rt.inp.output.write_markdown, rt.inp.output.write_html)
    try:
        exp = write_experience(out_dir, rt.experience)
        if exp["signals"]:
            log.info("learning signals: %s", ", ".join(f"{k}={n}" for k, n in
                                                     Counter(x["kind"] for x in exp["signals"]).items()))
    except Exception as e:  # the learning loop must never break a run
        log.warning("could not write experience.json: %s", e)
    log.info("cache hits=%d misses=%d", rt.cache.hits, rt.cache.misses)
    for st in cache_stats():
        log.info("LLM response cache %s: hits=%d misses=%d writes=%d", st["backend"], st["hits"], st["misses"],
                 st["writes"])
    return {"output": out.model_dump(mode="json")}


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


def build_graph():
    g = StateGraph(State)
    g.add_node("resolve_target", resolve_node)
    g.add_node("analyze_container", container_node)
    g.add_node("research_cve", research_node)
    g.add_node("dispatch", dispatch_node)
    g.add_node("analyze_cve", analyze_cve_node)
    g.add_node("finalize", finalize_node)
    g.add_edge(START, "resolve_target")
    g.add_conditional_edges("resolve_target", fanout_after_resolve, ["analyze_container", "research_cve"])
    g.add_edge("analyze_container", "dispatch")
    g.add_edge("research_cve", "dispatch")
    g.add_conditional_edges("dispatch", fanout_cves, ["analyze_cve"])
    g.add_edge("analyze_cve", "finalize")
    g.add_edge("finalize", END)
    return g.compile()


_GRAPH = None


def graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


def new_run_id(inp: PipelineInput) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{uuid.uuid4().hex[:6]}"


async def run_pipeline(inp: PipelineInput | dict[str, Any], settings: Settings | None = None,
                       run_id: str | None = None) -> PipelineOutput:
    inp = inp if isinstance(inp, PipelineInput) else PipelineInput.model_validate(inp)
    settings = settings or load_settings()
    cache = AgentCache(inp.cache.dir or settings.cache_dir, inp.cache.enabled, inp.cache.refresh)
    rt = Runtime(settings=settings, cache=cache, inp=inp, skills=load_run_skills(settings, inp))
    run_id = run_id or new_run_id(inp)
    out_dir = Path(inp.output.dir or settings.output_dir) / f"{run_id}_{safe_name(inp.target.display_name)}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "input.json").write_text(inp.model_dump_json(indent=1))  # for gold labels / reproducibility
    state = await graph().ainvoke(
        {"input": inp.model_dump(mode="json"), "run_id": run_id, "out_dir": str(out_dir), "errors": []},
        config={"configurable": {"runtime": rt}, "max_concurrency": max(2, inp.options.max_parallel_cves + 1),
                "recursion_limit": 50},
    )
    out = PipelineOutput.model_validate(state["output"])
    learn = inp.options.learn if inp.options.learn is not None else settings.skills.auto_learn
    if learn:
        from .agents.reflector import reflect_runs

        try:
            props = await reflect_runs([Path(out.output_dir)], settings)
            log.info("reflector staged %d pending skill(s): %s", len(props), ", ".join(props) or "-")
        except Exception as e:
            log.warning("reflector failed: %s", e)
    return out


def load_run_skills(settings: Settings, inp: PipelineInput) -> list[Skill]:
    """Active skills (+ pending candidates under trial by the gate), unless disabled for this run."""
    if not settings.skills.enabled or not inp.options.use_skills:
        return []
    store = SkillStore(settings.skills_dir)
    skills = {s.name: s for s in store.list("active")}
    for name in settings.skills.include_pending:
        cand = store.get(name, "pending")
        if cand is not None:
            skills[name] = cand  # the candidate replaces the active version it patches
    if skills:
        log.info("skills: %d loaded (%s)", len(skills), ", ".join(sorted(skills)))
    return list(skills.values())
