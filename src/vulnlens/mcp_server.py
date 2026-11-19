"""vulnlens as an MCP server, so Hermes Agent (or Claude Code, or any MCP client) can drive analyses.

    vulnlens mcp                    # stdio; Hermes: mcp_servers.vulnlens = {command: vulnlens, args: [mcp]}
    vulnlens mcp --transport streamable-http --port 8765   # binds 127.0.0.1

Tools start scans as background jobs (persisted in <cache_dir>/jobs.sqlite), read finished reports, record analyst
feedback and stage learned playbooks. Deliberately NOT exposed: approving playbooks (human-only CLI step), replay
(costly), and live verification unless the server is started with VULNLENS_MCP_ALLOW_LIVE=1.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .config import Settings, load_settings
from .models import PipelineInput

log = logging.getLogger(__name__)

PARTS = {"research": "cve_research.md", "exploitability": "exploitability.md", "vex": "vex.md",
         "vex_json": "vex.json", "container": "../container_analysis.md", "runtime": "../runtime_verification.md",
         "index": "../index.md"}
MAX_TEXT = 20000
_SAFE = re.compile(r"[\w.\-]+")


def _clip(s: str, n: int = MAX_TEXT) -> str:
    return s if len(s) <= n else s[:n] + f"\n…[truncated {len(s) - n} chars]"


class VulnlensTools:
    """Plain async methods (testable without MCP); build_server registers them as MCP tools."""

    def __init__(self, settings: Settings, examples_dir: Path | None = None, allow_live: bool | None = None):
        from .server.jobs import JobStore

        self.settings = settings
        self.examples = examples_dir or Path.cwd() / "examples"
        self.allow_live = allow_live if allow_live is not None else os.environ.get("VULNLENS_MCP_ALLOW_LIVE") == "1"
        self.jobs = JobStore(Path(settings.cache_dir) / "jobs.sqlite")
        self.tasks: dict[str, asyncio.Task] = {}

    @property
    def out_root(self) -> Path:
        return Path(self.settings.output_dir).resolve()

    def _run_dir(self, run: str) -> Path:
        """Resolve a run id / run directory name inside the output dir (no path traversal)."""
        if not _SAFE.fullmatch(run or ""):
            raise ValueError("run must be a run id or run directory name")
        for c in [self.out_root / run] + sorted(self.out_root.glob(f"{run}_*")):
            if (c / "summary.json").exists() and c.resolve().parent == self.out_root:
                return c
        raise FileNotFoundError(f"no finished run '{run}' under {self.out_root}")

    # ---- scans --------------------------------------------------------------------------------------
    async def list_examples(self) -> list[dict]:
        """Example PipelineInput files that start_scan can run by name."""
        out = []
        for p in sorted(self.examples.glob("*.json")):
            try:
                d = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            tgt = d.get("target") or {k: d.get(k) for k in ("image_name", "image_tag", "filesystem_path")}
            out.append({"example": p.stem, "target": {k: v for k, v in tgt.items() if k != "deployment_notes"},
                        "vulnerabilities": [v.get("vuln_id") if isinstance(v, dict) else str(v)
                                            for v in d.get("vulnerabilities", [])]})
        return out

    async def start_scan(self, example: str | None = None, input: dict | None = None,
                         vulnerabilities: list[str] | None = None, llm_profile: str | None = None,
                         skip_web_research: bool = False, live_verification: bool = False) -> dict:
        """Start an analysis in the background. Give an example name (see list_examples) or a full PipelineInput
        object; `vulnerabilities` replaces its CVE list. Returns job_id and the run directory it will write.
        Poll scan_status; a scan takes minutes."""
        from .graph import new_run_id, run_pipeline
        from .reports.render import safe_name

        if bool(example) == bool(input):
            raise ValueError("give exactly one of example or input")
        if example:
            if not _SAFE.fullmatch(example):
                raise ValueError("bad example name")
            doc = json.loads((self.examples / f"{example}.json").read_text())
        else:
            doc = dict(input or {})
        if vulnerabilities:
            doc["vulnerabilities"] = [{"vuln_id": v} for v in vulnerabilities]
        inp = PipelineInput.model_validate(doc)
        inp.options.skip_web_research = skip_web_research or inp.options.skip_web_research
        if llm_profile:
            if llm_profile not in self.settings.llms:
                raise ValueError(f"unknown LLM profile {llm_profile}; have {sorted(self.settings.llms)}")
            inp.options.llm_profile = llm_profile
        want_live = live_verification or inp.options.live_verification
        if want_live and not self.allow_live:
            raise PermissionError("live verification over MCP is disabled (start the server with "
                                  "VULNLENS_MCP_ALLOW_LIVE=1)")
        inp.options.live_verification = want_live
        run_id = new_run_id(inp)
        run_dir = Path(inp.output.dir or self.settings.output_dir) / f"{run_id}_{safe_name(inp.target.display_name)}"
        job_id = self.jobs.create(inp.model_dump(mode="json"), run_id)

        async def _go() -> None:
            self.jobs.update(job_id, "running")
            try:
                out = await run_pipeline(inp, self.settings, run_id=run_id)
                self.jobs.update(job_id, "success", output={"run_dir": out.output_dir, "results": [
                    {"cve": r.vex.cve_id, "status": r.vex.status.value, "justification": r.vex.justification.value,
                     "verdict": r.vex.exploitability_verdict.value if r.vex.exploitability_verdict else None,
                     "confidence": r.vex.confidence} for r in out.results]})
            except Exception as e:  # noqa: BLE001
                log.exception("mcp scan failed")
                self.jobs.update(job_id, "failure", error=str(e))

        self.tasks[job_id] = asyncio.create_task(_go())
        return {"job_id": job_id, "run_id": run_id, "run_dir": str(run_dir),
                "vulnerabilities": [v.vuln_id for v in inp.vulnerabilities]}

    async def scan_status(self, job_id: str) -> dict:
        """Status of a scan job: submitted | running | success | failure | interrupted (+ results when done)."""
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(f"unknown job {job_id}")
        return job

    async def list_runs(self, limit: int = 10) -> list[dict]:
        """Most recent finished runs with their VEX outcomes."""
        out = []
        for p in sorted(self.out_root.glob("*/summary.json"), reverse=True)[:max(1, min(limit, 50))]:
            s = json.loads(p.read_text())
            out.append({"run": p.parent.name, "target": s.get("target"),
                        "results": [{"cve": r["cve_id"], "status": r["status"], "justification": r["justification"]}
                                    for r in s.get("results", [])]})
        return out

    async def get_summary(self, run: str) -> dict:
        """summary.json of a run (VEX status, justification, verdict, confidence, reasoning per CVE)."""
        return json.loads((self._run_dir(run) / "summary.json").read_text())

    async def get_report(self, run: str, part: str = "vex", vuln: str | None = None) -> str:
        """Report text of a run. part: research | exploitability | vex | vex_json (these need vuln) or
        container | runtime | index."""
        if part not in PARTS:
            raise ValueError(f"part must be one of {sorted(PARTS)}")
        d = self._run_dir(run)
        rel = PARTS[part]
        if rel.startswith("../"):
            p = d / rel[3:]
        else:
            if not vuln or not _SAFE.fullmatch(vuln):
                raise ValueError("this part needs vuln (e.g. CVE-2024-1234)")
            p = d / vuln / rel
        if not p.exists():
            raise FileNotFoundError(f"{p.name} not in run {d.name}")
        return _clip(p.read_text())

    # ---- deterministic helpers (no LLM) -------------------------------------------------------------
    async def inventory(self, filesystem_path: str, name_regex: str = "") -> dict:
        """Software inventory of an extracted root filesystem (counts, distro, matching OS packages)."""
        from .tools import Jail, build_inventory

        inv = await asyncio.to_thread(build_inventory, Jail(filesystem_path))
        d = inv.to_dict()
        rx = re.compile(name_regex, re.I) if name_regex else None
        pk = [p for p in d.get("os_packages", []) if not rx or rx.search(p.get("name", ""))][:200]
        return {"counts": inv.counts(), "distro": d.get("distro"), "os_packages": pk}

    async def pretriage(self, vuln_id: str, filesystem_path: str) -> dict:
        """Deterministic pre-triage of one CVE (public advisories + inventory, version/backport checks)."""
        from .agents.cve_researcher import deterministic_affected, gather_intel
        from .agents.exploitability import pretriage as _pretriage
        from .models import VulnerabilityReport
        from .tools import Jail, ToolContext, build_inventory

        def _go() -> dict:
            jail = Jail(filesystem_path)
            inv = build_inventory(jail)
            affected, funcs = deterministic_affected(gather_intel(self.settings, vuln_id))
            vr = VulnerabilityReport(vuln_id=vuln_id, affected_packages=affected, vulnerable_functions=funcs)
            res, early = _pretriage(vr, inv, ToolContext(settings=self.settings, jail=jail, inventory=inv))
            return {"early_exit": [early[0].value, early[1]] if early else None,
                    "results": [r.model_dump(mode="json") for r in res]}

        return await asyncio.to_thread(_go)

    async def discover(self, container: str | None = None, image: str | None = None,
                       filesystem_path: str | None = None, engine: str = "docker", cpes: list[str] | None = None,
                       max_results: int = 30, min_cvss: float | None = None, refresh: bool = False) -> dict:
        """Find candidate CVEs for ONE target (give exactly one): `container` = a running docker/podman container
        (its current filesystem is exported read-only), `image` = "name:tag", or `filesystem_path` = an extracted
        rootfs. Queries OSV for every inventoried package (plus NVD for optional CPEs). Returns ranked candidates
        and `pipeline_input`, a ready start_scan(input=...) object with the top candidates (live verification
        wired to the container when one was given). Candidates are leads, not findings: run start_scan to triage."""
        from .discover import discover as _discover, package_hint
        from .rootfs.resolver import export_running_container, resolve_target
        from .models import Target
        from .tools import Jail, build_inventory

        if sum(bool(x) for x in (container, image, filesystem_path)) != 1:
            raise ValueError("give exactly one of container, image or filesystem_path")
        max_results = max(1, min(int(max_results), 200))
        src: dict[str, Any] = {}
        if container:
            src = await asyncio.to_thread(export_running_container, container, self.settings, engine, refresh)
            root = src["path"]
            name, tag = (src.get("image") or container), None
            if src.get("image") and ":" in src["image"].rsplit("/", 1)[-1]:
                name, tag = src["image"].rsplit(":", 1)
            target = {"kind": "container", "name": container, "filesystem_path": root,
                      "image_name": name if src.get("image") else None, "image_tag": tag or "latest",
                      "runtime": {"engine": engine, "container": container}}
        elif image:
            if not re.fullmatch(r"[\w./:@-]+", image):
                raise ValueError("bad image reference")
            name, _, tag = image.rpartition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "latest")
            t = Target(image_name=name, image_tag=tag or "latest")
            rf = await asyncio.to_thread(resolve_target, t, self.settings)
            root = rf.path
            target = {"kind": "container", "image_name": name, "image_tag": tag or "latest"}
        else:
            root = filesystem_path
            target = {"kind": "container", "filesystem_path": root}
        inv = await asyncio.to_thread(build_inventory, Jail(root))
        cpes = list(cpes or [])
        guessed = guess_cpe(target.get("image_name"), target.get("image_tag"))
        if guessed and guessed not in cpes:
            cpes.append(guessed)  # the image's main app is often built from source, invisible to package DBs
        cands = await asyncio.to_thread(_discover, self.settings, inv, cpes)
        prio_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0}
        rows = []
        for cid, c in cands.items():
            if c.get("withdrawn"):
                continue
            if min_cvss is not None and (c.get("cvss") or 0) < min_cvss:
                continue
            app = any(p.startswith("nvd:") for p in c.get("pkgs", []))
            rows.append({"vuln_id": cid, "package_hint": package_hint(c), "cvss": c.get("cvss"), "main_app": app,
                         "distro_priority": max(c.get("prio") or [""], key=lambda x: prio_rank.get(x, -1)) or None,
                         "packages": c.get("pkgs", [])[:5], "advisories": c.get("src", [])[:4],
                         "summary": c.get("summary", "")})
        rows.sort(key=lambda r: (not r["main_app"], -(r["cvss"] or 0), -prio_rank.get(r["distro_priority"] or "", -1),
                                 -_cve_year(r["vuln_id"]), r["vuln_id"]))
        top = rows[:max_results]
        return {"target": {k: v for k, v in target.items() if k != "runtime"}, "export": src or None,
                "cpes_queried": cpes,
                "inventory": inv.counts(), "distro": inv.distro.get("PRETTY_NAME"),
                "candidates_total": len(rows), "candidates": top,
                "pipeline_input": {"target": target,
                                   "vulnerabilities": [{"vuln_id": r["vuln_id"],
                                                        **({"package_hint": r["package_hint"]}
                                                           if r["package_hint"] else {})} for r in top]},
                "note": "Trim pipeline_input.vulnerabilities to what matters before start_scan; each CVE costs a "
                        "full analysis."}

    # ---- learning loop ------------------------------------------------------------------------------
    async def record_feedback(self, run: str, vuln: str, note: str, status: str | None = None,
                              justification: str | None = None) -> str:
        """Record an analyst correction/comment on one CVE of a run; it feeds `learn`."""
        from .skills.signals import add_feedback

        items = add_feedback(self._run_dir(run), vuln, status, justification, note)
        return f"recorded ({len(items)} feedback entries for this run)"

    async def learn(self, runs: list[str]) -> dict:
        """Reflect on finished runs and stage proposed playbooks as PENDING (a human approves them via CLI)."""
        from .agents.reflector import reflect_runs

        names = await reflect_runs([self._run_dir(r) for r in runs], self.settings)
        return {"pending": names, "next": "human review: vulnlens skills diff/replay/approve <name>"}

    async def skills_list(self, state: str = "active") -> list[dict]:
        """Playbooks in a state: active | pending | rejected."""
        from .skills.store import SkillStore

        return [{"name": s.name, "version": s.version, "description": s.description, "agents": s.agents,
                 "packages": s.packages, "cwes": s.cwes, "distros": s.distros, "locked": s.locked}
                for s in SkillStore(self.settings.skills_dir).list(state)]

    async def skill_show(self, name: str) -> str:
        """Full SKILL.md text of a playbook."""
        from .skills.store import SkillStore

        sk = SkillStore(self.settings.skills_dir).get(name)
        if sk is None:
            raise KeyError(f"no skill {name}")
        return f"[{sk.state}]\n{sk.to_markdown()}"


def _cve_year(vid: str) -> int:
    m = re.match(r"CVE-(\d{4})-", vid)
    return int(m.group(1)) if m else 0


def guess_cpe(image_name: str | None, tag: str | None) -> str | None:
    """'redis' + '8.10.1' -> cpe:2.3:a:redis:redis:8.10.1 (vendor = product = last path element). Only for tags that
    look like a version; a wrong guess just returns no NVD matches."""
    if not image_name or not tag:
        return None
    m = re.match(r"^v?(\d+(?:\.\d+){1,3})", tag)
    if not m:
        return None
    prod = re.sub(r"[^a-z0-9_]+", "_", image_name.rsplit("/", 1)[-1].lower()).strip("_")
    return f"cpe:2.3:a:{prod}:{prod}:{m.group(1)}:*:*:*:*:*:*:*" if prod else None


TOOL_NAMES = ("list_examples", "discover", "start_scan", "scan_status", "list_runs", "get_summary", "get_report", "inventory",
              "pretriage", "record_feedback", "learn", "skills_list", "skill_show")


def build_server(settings: Settings | None = None, tools: VulnlensTools | None = None) -> Any:
    from mcp.server.mcpserver import MCPServer

    vt = tools or VulnlensTools(settings or load_settings())
    srv = MCPServer("vulnlens", instructions=(
        "Container/host vulnerability exploitability and VEX analysis. Typical flow: discover (candidate CVEs for "
        "a container/image/rootfs) or list_examples -> start_scan -> poll scan_status -> get_summary / get_report -> record_feedback when the "
        "analysis was wrong -> learn (stages playbooks for human approval). Scans take minutes; poll sparingly."))
    for name in TOOL_NAMES:
        fn = getattr(vt, name)
        srv.add_tool(fn, name=name, description=(fn.__doc__ or "").strip())
    return srv
