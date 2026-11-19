"""vulnlens CLI: run | serve | eval | report | discover | inventory | pretriage | llm-cache | feedback | learn |
skills | mcp."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import typer

from .config import load_settings
from .models import PipelineInput

app = typer.Typer(add_completion=False, help="LangGraph vulnerability exploitability & VEX analysis (Claude / Ollama)")


def _setup(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "httpx2", "httpcore", "openai", "anthropic"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


@app.command()
def run(
    input_file: Path = typer.Argument(..., help="PipelineInput JSON"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    llm: Optional[str] = typer.Option(None, help="Force an LLM profile for every agent (e.g. 'local')"),
    relaxed: Optional[bool] = typer.Option(None, "--relaxed/--strict", help="VEX categorization mode"),
    skip_web: Optional[bool] = typer.Option(None, "--skip-web/--web", help="Skip container web research"),
    no_cache: bool = typer.Option(False, help="Disable the agent cache"),
    refresh: list[str] = typer.Option([], help="Ignore cached output of these agents (repeatable)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output directory"),
    live: Optional[bool] = typer.Option(None, "--live/--no-live",
                                        help="Read-only live checks against the running target (needs target.runtime)"),
    container: Optional[str] = typer.Option(None, help="Running container to probe (sets target.runtime)"),
    engine: str = typer.Option("docker", help="Container engine for --container: docker|podman|local"),
    verbose: bool = typer.Option(False, "-v"),
):
    """Run the full pipeline for one PipelineInput document."""
    _setup(verbose)
    from .graph import run_pipeline

    settings = load_settings(config)
    inp = PipelineInput.model_validate_json(input_file.read_text())
    if llm:
        inp.options.llm_profile = llm
    if relaxed is not None:
        inp.options.relaxed_vex = relaxed
    if skip_web is not None:
        inp.options.skip_web_research = skip_web
    if no_cache:
        inp.cache.enabled = False
    if refresh:
        inp.cache.refresh = list(refresh)
    if out:
        inp.output.dir = str(out)
    if container or engine == "local" and live:
        from .models import RuntimeSpec

        inp.target.runtime = RuntimeSpec(engine=engine, container=container)
        inp.options.live_verification = True if live is None else live
    elif live is not None:
        inp.options.live_verification = live
    result = asyncio.run(run_pipeline(inp, settings))
    typer.echo(f"\nTarget: {result.target}  ({result.container_report.container_type})")
    for r in result.results:
        v = r.vex
        live_tag = f" live={r.exploitability_report.verification.outcome}" if r.exploitability_report.verification else ""
        typer.echo(f"  {v.cve_id:<22} {v.status.value:<13} {v.justification.value:<30} "
                   f"verdict={v.exploitability_verdict.value if v.exploitability_verdict else 'n/a'} "
                   f"conf={v.confidence:.2f}{live_tag}")
    if result.runtime_report:
        rr = result.runtime_report
        typer.echo(f"\nLive checks: {len(rr.checks)} ({sum(c.status == 'issue' for c in rr.checks)} issues), "
                   f"{len(rr.probes)} probes" + (f", errors: {'; '.join(rr.errors)}" if rr.errors else ""))
        for c in rr.checks:
            if c.status == "issue":
                typer.echo(f"  [{c.severity}] {c.title}")
    typer.echo(f"\nReports: {result.output_dir}\nSummary: {result.summary_path}\nOpenVEX: {result.openvex_path}")
    if inp.output.write_html:
        typer.echo(f"HTML:    {Path(result.output_dir) / 'report.html'}")


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "-v"),
):
    """Serve /generate and /v1/workflow/async endpoints (NAT-compatible) with FastAPI."""
    _setup(verbose)
    import uvicorn

    from .server.app import create_app

    uvicorn.run(create_app(load_settings(config)), host=host, port=port)


@app.command("eval")
def eval_cmd(
    dataset: Path = typer.Argument(..., help="Benchmark dataset (json/jsonl/csv)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    out: Path = typer.Option(Path("output/eval/eval_report.json"), "--out", "-o"),
    limit: Optional[int] = typer.Option(None),
    relaxed: bool = typer.Option(False, "--relaxed"),
    skip_web: bool = typer.Option(False, "--skip-web"),
    llm: Optional[str] = typer.Option(None),
    verbose: bool = typer.Option(False, "-v"),
):
    """Run the benchmark and report status/justification accuracy."""
    _setup(verbose)
    from .eval.evaluators import run_benchmark

    rep = asyncio.run(run_benchmark(str(dataset), load_settings(config), str(out), limit, relaxed, skip_web, llm))
    typer.echo(json.dumps(rep["metrics"], indent=2))
    typer.echo(f"Full report: {out}")


@app.command("llm-cache")
def llm_cache_cmd(
    action: str = typer.Argument("info", help="info | clear"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask before clear"),
):
    """Show the LLM response cache backend (reachability, entries) or clear it."""
    from .llm_cache import build_backend, describe

    s = load_settings(config)
    if action == "info":
        typer.echo(json.dumps(describe(s.llm_cache, s.cache_dir), indent=2))
    elif action == "clear":
        inner, label = build_backend(s.llm_cache, s.cache_dir)
        if not yes:
            typer.confirm(f"Delete every cached LLM response in {label}?", abort=True)
        inner.clear()
        typer.echo(f"cleared {label}")
    else:
        raise typer.BadParameter("action must be info or clear")


@app.command()
def report(
    run_dir: Path = typer.Argument(..., help="A finished run directory (contains summary.json)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Default: <run_dir>/report.html"),
    fragment: bool = typer.Option(False, help="Omit <!doctype>/<html> (for hosts that add their own skeleton)"),
):
    """(Re)generate the self-contained HTML report for a finished run."""
    from .reports.html import load_run, write_html_report

    path = write_html_report(load_run(run_dir), out or run_dir / "report.html", standalone=not fragment)
    typer.echo(path)


@app.command()
def discover(
    rootfs: Path = typer.Argument(..., help="Extracted root filesystem"),
    out: Path = typer.Option(..., "--out", "-o", help="Candidates JSON (CVE -> packages, sources, summary)"),
    cpe: list[str] = typer.Option([], help="Also query NVD for this CPE (repeatable), for from-source components"),
    input_out: Optional[Path] = typer.Option(None, help="Also write a PipelineInput with every candidate"),
    target_name: Optional[str] = typer.Option(None, help="target.name for --input-out"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
):
    """Find candidate CVEs for a root filesystem via OSV (all inventoried ecosystems) and optional NVD CPEs."""
    _setup(False)
    from .discover import discover as _discover, to_vulnerabilities
    from .tools import Jail, build_inventory

    settings = load_settings(config)
    inv = build_inventory(Jail(rootfs))
    cands = _discover(settings, inv, list(cpe))
    out.write_text(json.dumps(cands, indent=1))
    typer.echo(f"{len(cands)} candidates -> {out}")
    if input_out:
        doc = {"vulnerabilities": to_vulnerabilities(cands),
               "target": {"filesystem_path": str(rootfs.resolve()), **({"name": target_name} if target_name else {})}}
        input_out.write_text(json.dumps(doc, indent=1))
        typer.echo(f"PipelineInput with {len(doc['vulnerabilities'])} vulnerabilities -> {input_out}")


@app.command()
def inventory(
    rootfs: Path = typer.Argument(..., help="Extracted root filesystem"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
):
    """Build the deterministic software inventory for a root filesystem (no LLM)."""
    _setup(False)
    from .tools import Jail, build_inventory

    inv = build_inventory(Jail(rootfs))
    data = json.dumps(inv.to_dict(), indent=1)
    if out:
        out.write_text(data)
        typer.echo(json.dumps(inv.counts()))
    else:
        typer.echo(data)


@app.command()
def pretriage(
    vuln_id: str,
    rootfs: Path = typer.Argument(..., help="Extracted root filesystem"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
):
    """Deterministic pre-triage only (public databases + inventory, no LLM)."""
    _setup(False)
    from .agents.cve_researcher import deterministic_affected, gather_intel
    from .agents.exploitability import pretriage as _pretriage
    from .models import VulnerabilityReport
    from .tools import Jail, ToolContext, build_inventory

    settings = load_settings(config)
    jail = Jail(rootfs)
    inv = build_inventory(jail)
    intel = gather_intel(settings, vuln_id)
    affected, funcs = deterministic_affected(intel)
    vr = VulnerabilityReport(vuln_id=vuln_id, affected_packages=affected, vulnerable_functions=funcs)
    ctx = ToolContext(settings=settings, jail=jail, inventory=inv)
    results, early = _pretriage(vr, inv, ctx)
    typer.echo(json.dumps({"early_exit": [early[0].value, early[1]] if early else None,
                           "results": [r.model_dump() for r in results]}, indent=2))


if __name__ == "__main__":
    app()


# ---------------------------------------------------------------------------
# Self-evolving harness: feedback -> learn -> skills replay/approve
# ---------------------------------------------------------------------------

skills_app = typer.Typer(add_completion=False, help="Learned playbooks (Hermes-compatible SKILL.md): review and gate")
app.add_typer(skills_app, name="skills")


@app.command()
def feedback(
    run_dir: Path = typer.Argument(..., help="Run directory"),
    vuln: str = typer.Argument(..., help="CVE / vulnerability id in that run"),
    status: Optional[str] = typer.Option(None, help="Correct VEX status: affected | not_affected | unknown"),
    justification: Optional[str] = typer.Option(None, help="Correct justification (e.g. code_not_reachable)"),
    note: str = typer.Option("", "--note", "-n", help="What was wrong or right in the analysis"),
    agent: Optional[str] = typer.Option(None, help="Agent the note is about (default exploitability)"),
    gold: bool = typer.Option(False, "--gold", help="Also add the label to the gold set (needs --status)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
):
    """Record an analyst correction or comment for one CVE of a run (input for `vulnlens learn`)."""
    from .skills.gold import add_gold_label
    from .skills.signals import add_feedback

    if not (run_dir / "summary.json").exists():
        raise typer.BadParameter(f"{run_dir} is not a finished run directory")
    items = add_feedback(run_dir, vuln, status, justification, note, agent)
    typer.echo(f"{run_dir / 'feedback.json'}: {len(items)} entr{'y' if len(items) == 1 else 'ies'}")
    if gold:
        if not status:
            raise typer.BadParameter("--gold needs --status")
        typer.echo(f"gold set: {add_gold_label(load_settings(config), run_dir, vuln, status, justification)}")


@app.command()
def learn(
    run_dirs: list[Path] = typer.Argument(..., help="One or more run directories"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    llm: Optional[str] = typer.Option(None, help="LLM profile for the reflector"),
    verbose: bool = typer.Option(False, "-v"),
):
    """Reflect on finished runs and stage proposed playbooks in skills/pending (never activates them)."""
    _setup(verbose)
    from .agents.reflector import reflect_runs

    s = load_settings(config)
    names = asyncio.run(reflect_runs(run_dirs, s, llm))
    if not names:
        typer.echo("no proposals staged (no actionable signals, or every proposal was rejected by the scanner)")
    for n in names:
        typer.echo(f"pending: {n}   ->  vulnlens skills diff {n}; vulnlens skills replay {n}")


def _skill_row(sk) -> str:
    who = ",".join(sk.agents) or "all"
    scope = ",".join(sk.packages + sk.cwes + sk.distros) or "general"
    lock = " [locked]" if sk.locked else ""
    return f"{sk.name:40} v{sk.version:<3} {sk.state:8} {who:28} {scope}{lock}\n    {sk.description}"


@skills_app.command("list")
def skills_list(state: str = typer.Option("active", help="active | pending | rejected | all"),
                config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """List playbooks."""
    from .skills.store import STATES, SkillStore

    s = load_settings(config)
    store = SkillStore(s.skills_dir)
    rows = [sk for st in (STATES if state == "all" else [state]) for sk in store.list(st)]
    typer.echo(f"skills dir: {s.skills_dir}")
    for sk in rows:
        typer.echo(_skill_row(sk))
    if not rows:
        typer.echo(f"(no {state} skills)")


@skills_app.command("pending")
def skills_pending(config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """List proposals waiting for replay / approval, with their last replay result."""
    from .skills.store import SkillStore

    store = SkillStore(load_settings(config).skills_dir)
    for sk in store.list("pending"):
        rep = store.load_json(sk.name, "pending", "replay.json")
        res = "not replayed" if not rep else ("PASSED" if rep["passed"] else "FAILED") + \
            ("" if not rep or rep["digest"] == sk.content_digest() else " (stale: edited after replay)")
        typer.echo(f"{_skill_row(sk)}\n    replay: {res}")


@skills_app.command("show")
def skills_show(name: str, config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Print a playbook (active, pending or rejected)."""
    from .skills.store import SkillStore

    store = SkillStore(load_settings(config).skills_dir)
    sk = store.get(name)
    if sk is None:
        raise typer.BadParameter(f"no skill '{name}'")
    typer.echo(f"# {sk.state}: {sk.path}\n{sk.to_markdown()}")
    for f in ("replay.json", "scan.json", "rejection.json"):
        data = store.load_json(name, sk.state, f)
        if data:
            typer.echo(f"# {f}\n{json.dumps({k: v for k, v in data.items() if k != 'arms'}, indent=1)}")


@skills_app.command("diff")
def skills_diff(name: str, config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Unified diff of a pending proposal against the active version it would replace."""
    from .skills.gate import diff

    typer.echo(diff(load_settings(config), name) or "(identical)")


@skills_app.command("replay")
def skills_replay(name: str, repeats: Optional[int] = typer.Option(None, "-k", help="Runs per arm"),
                  llm: Optional[str] = typer.Option(None), config: Optional[Path] = typer.Option(None, "--config", "-c"),
                  verbose: bool = typer.Option(False, "-v")):
    """Trial a pending playbook on the gold set: baseline vs candidate (spends LLM calls)."""
    _setup(verbose)
    from .skills.gate import replay

    r = asyncio.run(replay(load_settings(config), name, repeats, llm))
    typer.echo(json.dumps({k: v for k, v in r.items() if k != "arms"}, indent=1, default=str))
    typer.echo(("PASSED" if r["passed"] else "FAILED") + (" (in-sample: gold set overlaps the evidence runs)"
                                                          if r["in_sample"] else ""))


@skills_app.command("approve")
def skills_approve(name: str, force: bool = typer.Option(False, "--force", help="Approve without a passing replay"),
                   config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Promote a pending playbook to active (requires a passing replay of its current text)."""
    from .skills.gate import approve

    try:
        sk = approve(load_settings(config), name, force)
    except PermissionError as e:
        raise typer.BadParameter(str(e))
    typer.echo(f"active: {sk.name} v{sk.version} ({sk.path})")


@skills_app.command("reject")
def skills_reject(name: str, reason: str = typer.Option("", "--reason", "-r"),
                  config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Move a pending playbook to rejected."""
    from .skills.gate import reject

    typer.echo(f"rejected: {reject(load_settings(config), name, reason).name}")


@skills_app.command("lock")
def skills_lock(name: str, unlock: bool = typer.Option(False, "--unlock"),
                config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Make an active playbook read-only to the reflector (or writable again with --unlock)."""
    from .skills.store import SkillStore

    sk = SkillStore(load_settings(config).skills_dir).set_locked(name, not unlock)
    typer.echo(f"{sk.name}: {'locked' if sk.locked else 'unlocked'}")


@skills_app.command("rollback")
def skills_rollback(name: str, config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Restore the previous version of an active playbook."""
    from .skills.store import SkillStore

    sk = SkillStore(load_settings(config).skills_dir).rollback(name)
    typer.echo(f"{sk.name}: back to v{sk.version}")


@skills_app.command("add")
def skills_add(path: Path = typer.Argument(..., help="A SKILL.md file to stage as pending"),
               config: Optional[Path] = typer.Option(None, "--config", "-c")):
    """Stage a hand-written (or Hermes-made) SKILL.md as pending; it goes through the same scan and gate."""
    from .skills.safety import scan
    from .skills.store import Skill, SkillStore, valid_name

    sk = Skill.from_markdown(path.read_text(), "pending")
    if not valid_name(sk.name):
        raise typer.BadParameter(f"invalid skill name '{sk.name}'")
    issues = scan(sk)
    if issues:
        raise typer.BadParameter("rejected by the scanner: " + "; ".join(issues))
    typer.echo(f"pending: {SkillStore(load_settings(config).skills_dir).write(sk, 'pending')}")


@app.command()
def mcp(config: Optional[Path] = typer.Option(None, "--config", "-c"),
        transport: str = typer.Option("stdio", help="stdio | streamable-http"),
        port: int = typer.Option(8765, help="Port for streamable-http (binds 127.0.0.1)")):
    """Serve vulnlens as an MCP server (for Hermes Agent, Claude Code or any MCP client)."""
    from .mcp_server import build_server

    srv = build_server(load_settings(config))
    if transport == "stdio":
        srv.run("stdio")
    else:
        srv.run("streamable-http", host="127.0.0.1", port=port)
