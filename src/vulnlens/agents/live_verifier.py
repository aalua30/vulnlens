"""Live Verifier: empirical, read-only checks against the *running* target that complement static analysis.

Two passes:
* `assess_posture` runs once per target: default accounts, which interfaces need authentication, what is actually
  listening, TLS, enabled plugins/modules, runtime privileges and who can reach the target.
* `verify_cve` runs per CVE whose static verdict hinges on runtime facts (CONDITIONALLY_EXPLOITABLE, EXPLOITABLE,
  MITIGATED, ENVIRONMENT_ISOLATED by default). It tests the exploitation conditions and the claims the static verdict
  rests on, then confirms or refutes it. `apply_verification` folds the result into the exploitability report so the
  VEX flowchart sees it; the static verdict is kept for audit.

Probes are bounded by tools/runtime.py (allowlisted read-only commands, benign requests to the target only).
"""

from __future__ import annotations

import asyncio
import json
import logging

from ..config import Settings
from ..llm import LLMHandle, react_steps, run_react
from ..models import (ContainerReport, Evidence, ExploitabilityReport, PostureAssessment, RuntimeReport,
                      VerificationAssessment, VerificationReport, Verdict, VulnerabilityReport)
from ..tools.runtime import LiveTarget, runtime_tools

log = logging.getLogger(__name__)

RULES = """Hard rules (the target is a live system):
- Read-only. Never try to change state, write files, create/delete users, restart services or toggle settings.
- Never send exploit payloads, malformed protocol data, floods or brute force. Benign requests only: use the
  probe tools to establish facts (is it listening, does it negotiate protocol X, does it require auth, which
  version/config is loaded), not to trigger the vulnerability.
- Only the configured default credentials may be tried, through http_request(default_user=...).
- run_command takes one command, no shell features; call allowed_commands once if unsure what is permitted.
- Report what you observed with the exact probe and its result. If something cannot be tested, say so."""

POSTURE_SYSTEM = f"""You are a security engineer doing empirical checks on a running workload, to complement a static
review of its filesystem. Establish facts that static analysis cannot see:
1. runtime_facts: user, privileged mode, capabilities, read-only rootfs, published ports, networks and peers.
2. What actually listens (ss/netstat, tcp_connect on the documented ports), and whether each listener uses TLS.
3. Authentication: which HTTP endpoints answer without credentials, whether well-known default accounts exist
   and are accepted (application CLIs such as `rabbitmqctl list_users`, http_request with default_user), and
   whether default accounts are restricted to loopback.
4. Enabled plugins/modules and the effective runtime configuration where an allowlisted CLI shows it.
Produce one check per fact: status=issue (a weakness, with severity and a concrete recommendation), ok (verified
safe) or info. Be targeted: about 8-15 probes.

{RULES}"""

VERIFY_SYSTEM = f"""You are verifying ONE static exploitability verdict against the running target. The static analyst
read the filesystem only; you can observe the live process. For each exploitation condition and each runtime claim
the verdict depends on (listener up, protocol/feature enabled, module loaded, auth required, config value in
effect, reachable from peers), test it with the probe tools and record condition / method / observed / holds.

Outcome: confirmed (live evidence supports the static verdict), refuted (it contradicts it — then give the
corrected verdict and conditions_met), or inconclusive (could not test the deciding facts).
Verdict meanings are the static analyst's: NOT_APPLICABLE, ENVIRONMENT_ISOLATED, NOT_REACHABLE, MITIGATED,
CONDITIONALLY_EXPLOITABLE (list conditions; conditions_met says whether they hold), EXPLOITABLE.
Use at most about 6 probes; reuse the posture results you are given instead of re-probing.

Observe config gates instead of assuming them. When the verdict says a protocol or feature is not enabled, probe
the negotiation itself; when it relies on a size/limit value, measure the limit rather than trusting a default:
- HTTP/2 claims: http2_cleartext_probe (prior knowledge) AND h2c_upgrade_probe (Upgrade: h2c) on each cleartext
  HTTP port, tls_probe for the ALPN path on TLS ports.
- Request-size limits (e.g. "LimitRequestFieldSize 8190 blocks it"): header_limit_probe just below and just above
  the claimed value. It uses a padding header, never the header the vulnerable code parses.

{RULES}"""


def needs_verification(er: ExploitabilityReport, settings: Settings) -> bool:
    if not er.complete or er.early_exit or er.verdict is None:
        return False
    return er.verdict.value in settings.live_probes.verify_verdicts or (
        er.verdict == Verdict.CONDITIONALLY_EXPLOITABLE and er.conditions_met is None)


async def assess_posture(cr: ContainerReport, live: LiveTarget, settings: Settings, llm: LLMHandle) -> RuntimeReport:
    rep = RuntimeReport(engine=live.spec.engine, container=live.spec.container)
    try:
        rep.facts = await asyncio.to_thread(live.inspect)
        rep.available = True
    except Exception as e:  # noqa: BLE001
        rep.errors.append(f"runtime unavailable: {e}")
        return rep
    task = json.dumps({"target_profile": cr.model_dump(exclude={"web_findings", "security_controls"}),
                       "runtime_facts": rep.facts}, default=str)[:30000]
    start = len(live.probes)
    try:
        pa, _ = await run_react(
            llm, POSTURE_SYSTEM, f"Run empirical posture checks on this running target.\n{task}",
            runtime_tools(live), PostureAssessment,
            max_steps=react_steps(settings, llm, "live_posture", 16),
            max_tool_chars=settings.max_tool_output_chars,
            final_instruction="Stop probing. Report each check with its evidence.",
            label="live posture",
        )
        rep.summary, rep.checks = pa.summary, pa.checks
    except Exception as e:  # noqa: BLE001
        log.exception("posture assessment failed")
        rep.errors.append(f"posture assessment failed: {e}")
    rep.probes = live.probes[start:]
    return rep


async def verify_cve(vr: VulnerabilityReport, er: ExploitabilityReport, cr: ContainerReport,
                     runtime: RuntimeReport | None, live: LiveTarget, settings: Settings,
                     llm: LLMHandle) -> VerificationReport:
    task = json.dumps({
        "vulnerability": {k: getattr(vr, k) for k in ("vuln_id", "summary", "attack_vector", "preconditions",
                                                      "vulnerable_functions", "affected_packages")},
        "static_analysis": er.model_dump(include={"verdict", "summary", "reachability_chain", "conditions",
                                                  "conditions_met", "mitigations", "confidence", "evidence"}),
        "target": {"name": cr.target, "type": cr.container_type, "exposed_ports": cr.exposed_ports,
                   "network_exposure": cr.network_exposure},
        "posture_results": runtime.model_dump(include={"summary", "checks", "facts"}) if runtime else None,
    }, default=str)[:36000]
    with live.recording() as sink:
        try:
            va, _ = await run_react(
                llm, VERIFY_SYSTEM, f"Verify this static verdict on the running target.\n{task}",
                runtime_tools(live), VerificationAssessment,
                max_steps=react_steps(settings, llm, "live_verify", 10),
                max_tool_chars=settings.max_tool_output_chars,
                final_instruction="Stop probing. Give the outcome with the condition checks.",
                label=f"live verify {vr.vuln_id}",
            )
            rep = VerificationReport(**va.model_dump(), static_verdict=er.verdict)
        except Exception as e:  # noqa: BLE001
            log.exception("live verification failed for %s", vr.vuln_id)
            rep = VerificationReport(outcome="inconclusive", summary="Live verification failed.", confidence=0.0,
                                     static_verdict=er.verdict, errors=[str(e)])
    rep.probes = list(sink)
    return rep


def apply_verification(er: ExploitabilityReport, ver: VerificationReport) -> ExploitabilityReport:
    """Return a copy of `er` with the live result folded in. Inconclusive results are recorded but change nothing."""
    upd: dict = {"verification": ver}
    if ver.outcome != "inconclusive":
        ev = [Evidence(kind="runtime", path=c.method[:200], detail=f"{c.condition}: {c.observed}"[:600])
              for c in ver.checks]
        upd["evidence"] = er.evidence + ev
        upd["summary"] = f"{er.summary}\nLive verification ({ver.outcome}): {ver.summary}"
        if ver.outcome == "refuted" and ver.verdict and ver.verdict != er.verdict:
            upd["verdict"] = ver.verdict
        if ver.conditions_met is not None:
            upd["conditions_met"] = ver.conditions_met
        # Live evidence is direct observation; let it raise (confirmed) or reset (refuted) the confidence.
        upd["confidence"] = max(er.confidence, ver.confidence) if ver.outcome == "confirmed" else ver.confidence
    return er.model_copy(update=upd)
