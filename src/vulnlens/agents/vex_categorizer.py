"""VEX Categorizer: precedence-ordered decision flowchart over the exploitability + target reports.

Status is decided deterministically by the flowchart; when a verdict maps to several sibling justifications the
LLM picks one (constrained to the allowed set) and writes the analyst-facing reasoning. If the LLM fails the
first allowed justification and a templated reasoning are used, so categorization never blocks on the model.
"""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel

from ..config import Settings
from ..llm import LLMHandle, invoke_structured, system_message
from ..models import (ContainerReport, DecisionStep, ExploitabilityReport, Justification as J, Verdict, VexResult,
                      VexStatus, VulnerabilityReport)

log = logging.getLogger(__name__)

SYSTEM = """You write the justification for a VEX (Vulnerability Exploitability eXchange) statement.
You are given the decided VEX status, the set of allowed justifications, and the analysis reports.
Pick the single best-supported justification FROM THE ALLOWED SET and write 2-5 sentences of reasoning for a
security analyst, citing the concrete evidence (paths, versions, symbols, controls). Do not change the status.

Justification meanings:
false_positive: scanner match is wrong (installed version not actually in the affected range / misidentified).
code_not_present: the vulnerable component or code is absent (not installed, patched/backported out).
code_not_reachable: vulnerable code is present but no execution path reaches it.
requires_configuration: exploitation needs a configuration that is not enabled here.
requires_dependency: exploitation needs another component/dependency that is absent.
requires_environment: exploitation needs an environment/attack surface (network, privilege, platform) not present.
compiler_protected: compiler/runtime hardening prevents exploitation.
perimeter_protected: network/perimeter controls prevent attacker access.
mitigating_control_protected: another in-target control (sandbox, MAC, config hardening) prevents exploitation.
vulnerable: the target is affected."""


class JustificationChoice(BaseModel):
    justification: J
    reasoning: str


def decide(er: ExploitabilityReport, relaxed: bool, threshold: float) -> tuple[VexStatus, list[J], list[DecisionStep]]:
    """Pure flowchart. Returns (status, allowed justifications ordered by default preference, trace)."""
    trace: list[DecisionStep] = []

    def step(node: str, q: str, a: str, ev: str = "") -> None:
        trace.append(DecisionStep(step=len(trace) + 1, node=node, question=q, answer=a, evidence=ev[:500]))

    complete = er.complete and er.verdict is not None
    step("completeness", "Is the exploitability analysis complete with a verdict?", "yes" if complete else "no",
         "; ".join(er.errors))
    if not complete:
        return VexStatus.UNKNOWN, [J.UNCERTAIN], trace

    v = er.verdict
    if er.verification is not None:
        ver = er.verification
        changed = ver.static_verdict and ver.static_verdict != v
        step("live_verification", "Was the static verdict checked against the running target?",
             ver.outcome + (f" (static {ver.static_verdict.value} -> {v.value})" if changed else ""), ver.summary)
    step("verdict", "What is the exploitability verdict?", v.value, er.summary)

    if v == Verdict.NOT_APPLICABLE:
        if er.early_exit and er.early_exit_justification:
            step("pretriage", "Did deterministic pre-triage resolve it?", "yes",
                 er.early_exit_justification.value)
            other = J.FALSE_POSITIVE if er.early_exit_justification == J.CODE_NOT_PRESENT else J.CODE_NOT_PRESENT
            return VexStatus.NOT_AFFECTED, [er.early_exit_justification, other], trace
        return VexStatus.NOT_AFFECTED, [J.CODE_NOT_PRESENT, J.FALSE_POSITIVE], trace
    if v == Verdict.ENVIRONMENT_ISOLATED:
        return VexStatus.NOT_AFFECTED, [J.REQUIRES_ENVIRONMENT, J.PERIMETER_PROTECTED, J.REQUIRES_DEPENDENCY], trace
    if v == Verdict.NOT_REACHABLE:
        return VexStatus.NOT_AFFECTED, [J.CODE_NOT_REACHABLE], trace
    if v == Verdict.MITIGATED:
        return VexStatus.NOT_AFFECTED, [J.MITIGATING_CONTROL_PROTECTED, J.COMPILER_PROTECTED, J.PERIMETER_PROTECTED], trace
    if v == Verdict.CONDITIONALLY_EXPLOITABLE:
        met = er.conditions_met
        step("conditions", "Are the exploitation conditions met in this target?",
             {True: "yes", False: "no", None: "undetermined"}[met], "; ".join(er.conditions))
        if met is False:
            return VexStatus.NOT_AFFECTED, [J.REQUIRES_CONFIGURATION, J.REQUIRES_DEPENDENCY, J.REQUIRES_ENVIRONMENT], trace
        if met is None and relaxed:
            step("relaxed_mode", "Relaxed mode: treat undetermined conditions as not met?", "yes")
            return VexStatus.NOT_AFFECTED, [J.REQUIRES_CONFIGURATION, J.REQUIRES_DEPENDENCY, J.REQUIRES_ENVIRONMENT], trace
        return VexStatus.AFFECTED, [J.VULNERABLE], trace
    # EXPLOITABLE
    if relaxed:
        weak = er.confidence < threshold and not er.reachability_chain
        step("relaxed_mode", f"Relaxed mode: is reachability evidence weak (confidence<{threshold} and no chain)?",
             "yes" if weak else "no", f"confidence={er.confidence}")
        if weak:
            return VexStatus.NOT_AFFECTED, [J.CODE_NOT_REACHABLE], trace
    return VexStatus.AFFECTED, [J.VULNERABLE], trace


def _template_reasoning(status: VexStatus, j: J, er: ExploitabilityReport) -> str:
    if status == VexStatus.UNKNOWN:
        return "Analysis incomplete; status cannot be determined. " + "; ".join(er.errors)[:500]
    return f"{er.summary} (verdict {er.verdict.value if er.verdict else 'n/a'}, justification {j.value})."


async def categorize(
    vr: VulnerabilityReport,
    cr: ContainerReport,
    er: ExploitabilityReport,
    settings: Settings,
    llm: LLMHandle | None,
    relaxed: bool,
) -> VexResult:
    status, allowed, trace = decide(er, relaxed, settings.relaxed_confidence_threshold)
    chosen, reasoning = allowed[0], _template_reasoning(status, allowed[0], er)
    errors: list[str] = []
    if llm is not None and status != VexStatus.UNKNOWN:
        payload = json.dumps({
            "status": status.value,
            "allowed_justifications": [a.value for a in allowed],
            "vulnerability": {k: getattr(vr, k) for k in ("vuln_id", "summary", "attack_vector", "preconditions",
                                                          "vulnerable_functions")},
            "exploitability": er.model_dump(exclude={"pretriage"}) | {"pretriage": [p.model_dump() for p in er.pretriage[:15]]},
            "target": {"name": cr.target, "type": cr.container_type, "summary": cr.summary,
                       "security_controls": [c.model_dump() for c in cr.security_controls][:20],
                       "network_exposure": cr.network_exposure},
        }, default=str)[:30000]
        try:
            choice = await invoke_structured(llm.model, [system_message(llm, SYSTEM)] +
                                             [_human(payload)], JustificationChoice,
                                             label=f"vex {vr.vuln_id}")
            if choice.justification in allowed:
                chosen = choice.justification
            else:
                errors.append(f"LLM chose disallowed justification {choice.justification.value}; kept {chosen.value}")
            reasoning = choice.reasoning
        except Exception as e:
            log.warning("VEX reasoning LLM failed: %s", e)
            errors.append(f"reasoning llm failed: {e}")
    trace.append(DecisionStep(step=len(trace) + 1, node="justification",
                              question=f"Which justification among {[a.value for a in allowed]}?",
                              answer=chosen.value))
    return VexResult(
        cve_id=vr.vuln_id, container=cr.target, status=status, justification=chosen, reasoning=reasoning,
        decision_trace=trace, exploitability_verdict=er.verdict, confidence=er.confidence,
        risk_level=er.risk_level if status != VexStatus.NOT_AFFECTED else "none",
        container_type=cr.container_type, relaxed_mode=relaxed, errors=errors,
    )


def _human(text: str):
    from langchain_core.messages import HumanMessage

    return HumanMessage(content=text)
