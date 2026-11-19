"""Pydantic data model for pipeline input, intermediate agent reports and final VEX output."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

import re

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ENVIRONMENT_ISOLATED = "ENVIRONMENT_ISOLATED"
    NOT_REACHABLE = "NOT_REACHABLE"
    MITIGATED = "MITIGATED"
    CONDITIONALLY_EXPLOITABLE = "CONDITIONALLY_EXPLOITABLE"
    EXPLOITABLE = "EXPLOITABLE"


class VexStatus(str, Enum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    UNKNOWN = "unknown"


class Justification(str, Enum):
    FALSE_POSITIVE = "false_positive"
    CODE_NOT_PRESENT = "code_not_present"
    CODE_NOT_REACHABLE = "code_not_reachable"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_DEPENDENCY = "requires_dependency"
    REQUIRES_ENVIRONMENT = "requires_environment"
    COMPILER_PROTECTED = "compiler_protected"
    PERIMETER_PROTECTED = "perimeter_protected"
    MITIGATING_CONTROL_PROTECTED = "mitigating_control_protected"
    VULNERABLE = "vulnerable"
    UNCERTAIN = "uncertain"


RiskLevel = Literal["critical", "high", "medium", "low", "none", "unknown"]

# ---------------------------------------------------------------------------
# Pipeline input
# ---------------------------------------------------------------------------


class VulnInput(BaseModel):
    vuln_id: str = Field(description="CVE / GHSA / OSV identifier")
    package_hint: str | None = Field(default=None, description="Package the scanner flagged, if known")
    notes: str | None = None


class RuntimeSpec(BaseModel):
    """How to reach the *running* workload for live verification (optional)."""

    engine: Literal["docker", "podman", "local"] = Field(
        default="docker", description="docker/podman: a running container; local: this host (target.kind=host)")
    container: str | None = Field(default=None, description="Container name or id (docker/podman)")


class Target(BaseModel):
    kind: Literal["container", "host"] = "container"
    name: str | None = Field(default=None, description="Display name (e.g. running container or host name)")
    image_name: str | None = None
    image_tag: str | None = "latest"
    image_digest: str | None = None
    filesystem_path: str | None = Field(default=None, description="Already-extracted root filesystem / host path")
    image_config_path: str | None = Field(default=None, description="OCI image config JSON (crane config output)")
    private: bool = Field(default=False, description="Private image: skip public web research")
    deployment_notes: str | None = Field(
        default=None, description="Free-text runtime context (network exposure, orchestrator, WAF, ...)"
    )
    runtime: RuntimeSpec | None = Field(default=None, description="Running workload, for live verification")

    @property
    def image_ref(self) -> str | None:
        if not self.image_name:
            return None
        if self.image_digest:
            return f"{self.image_name}@{self.image_digest}"
        return f"{self.image_name}:{self.image_tag or 'latest'}"

    @property
    def display_name(self) -> str:
        if self.name or self.image_ref:
            return self.name or self.image_ref
        if self.filesystem_path in ("/", "") and self.kind == "host":
            import socket
            return f"host-{socket.gethostname()}"
        return self.filesystem_path or "unknown-target"

    @model_validator(mode="after")
    def _check(self) -> "Target":
        if not self.image_name and not self.filesystem_path:
            raise ValueError("target needs image_name (+image_tag) or filesystem_path")
        return self


class Options(BaseModel):
    skip_web_research: bool = False
    relaxed_vex: bool = False
    max_parallel_cves: int = 4
    llm_profile: str | None = Field(default=None, description="Force one LLM profile for every agent")
    llm_overrides: dict[str, str] = Field(default_factory=dict, description="agent name -> llm profile")
    live_verification: bool = Field(
        default=False, description="Run read-only probes against target.runtime to confirm/refute static verdicts")
    use_skills: bool = Field(default=True, description="Inject approved learned playbooks into agent prompts")
    learn: bool | None = Field(default=None, description="Run the reflector after the run (default: skills.auto_learn)")


class OutputSettings(BaseModel):
    dir: str = "./output"
    write_markdown: bool = True
    write_html: bool = Field(default=True, description="Also write a self-contained report.html")


class CacheSettings(BaseModel):
    enabled: bool = True
    dir: str | None = None
    refresh: list[str] = Field(default_factory=list, description="Agents whose cached output is ignored")


class PipelineInput(BaseModel):
    vulnerabilities: list[VulnInput]
    target: Target
    options: Options = Field(default_factory=Options)
    output: OutputSettings = Field(default_factory=OutputSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)

    @model_validator(mode="before")
    @classmethod
    def _accept_flat(cls, data: Any) -> Any:
        """Accept the blueprint-style flat document (image_name/image_tag/... at top level)."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        flat_keys = ("image_name", "image_tag", "image_digest", "filesystem_path", "image_config_path")
        if "target" not in data:
            data["target"] = {k: data.pop(k) for k in flat_keys if k in data}
        vulns = data.get("vulnerabilities") or data.get("vulns") or []
        data["vulnerabilities"] = [{"vuln_id": v} if isinstance(v, str) else v for v in vulns]
        data.pop("vulns", None)
        return data

    @model_validator(mode="after")
    def _non_empty(self) -> "PipelineInput":
        if not self.vulnerabilities:
            raise ValueError("vulnerabilities must not be empty")
        seen: set[str] = set()
        uniq = []
        for v in self.vulnerabilities:
            v.vuln_id = v.vuln_id.strip().upper() if v.vuln_id.upper().startswith(("CVE-", "GHSA-")) else v.vuln_id.strip()
            if v.vuln_id not in seen:
                seen.add(v.vuln_id)
                uniq.append(v)
        self.vulnerabilities = uniq
        return self


# ---------------------------------------------------------------------------
# CVE research
# ---------------------------------------------------------------------------


class AffectedPackage(BaseModel):
    name: str = Field(description="Exact package/artifact name as installed (e.g. 'nginx', 'openssl', "
                                  "'org.apache.logging.log4j:log4j-core'); put module/component details elsewhere")
    ecosystem: str = Field(description="deb|rpm|apk|pypi|npm|maven|go|cargo|gem|nuget|generic")
    distro: str | None = Field(default=None, description="e.g. 'debian:12' for distro-specific ranges")
    ranges: list[dict[str, str]] = Field(
        default_factory=list,
        description="OSV-style events, e.g. [{'introduced':'0','fixed':'1.2.3'}] or [{'expr':'>=1.0,<1.2'}]",
    )
    fixed_versions: list[str] = Field(default_factory=list)
    source: str = "llm"
    component: str | None = Field(default=None, description="Optional sub-component/module, e.g. 'ngx_http_v2_module'")
    notes: list[str] = Field(default_factory=list, description="Free-text caveats that are not version constraints")

    @model_validator(mode="before")
    @classmethod
    def _split_component(cls, data):
        # LLMs often write "nginx (ngx_http_v2_module)"; keep the package name matchable against the inventory.
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            m = re.fullmatch(r"\s*([^\s()]+)\s*\((.+)\)\s*", data["name"])
            if m:
                data = {**data, "name": m.group(1), "component": data.get("component") or m.group(2).strip()}
            else:
                data = {**data, "name": data["name"].strip()}
        if isinstance(data, dict):
            data = _clean_versions(data)
        return data


_CLAUSE = re.compile(r"(>=|<=|==|!=|>|<|=)\s*v?(\d[\w.+~:-]*)")
_VERSIONISH = re.compile(r"^v?\d[\w.+~:-]*$")


def _clean_versions(data: dict) -> dict:
    """Keep version data machine-comparable: LLMs write prose into ranges ('< 1.25.3 (hardening; ...)') and
    product names into fixed_versions ('NGINX Plus R29 P1'), which made the comparator return 'unknown'."""
    notes = list(data.get("notes") or [])
    ranges = []
    for r in data.get("ranges") or []:
        if not isinstance(r, dict):
            continue
        r = {k: str(v).strip() for k, v in r.items() if v is not None}
        if "expr" in r:
            clauses = [f"{op if op != '=' else '=='}{v}" for op, v in _CLAUSE.findall(r["expr"])]
            leftover = _CLAUSE.sub("", r["expr"]).strip(" ,;()")
            if leftover:
                notes.append(f"range note: {r['expr']}")
            if not clauses:
                continue
            r["expr"] = ",".join(clauses)
        for k in ("introduced", "fixed", "last_affected", "limit"):
            if k in r and not (r[k] == "0" or _VERSIONISH.match(r[k])):
                notes.append(f"{k}: {r.pop(k)}")
        if r:
            ranges.append(r)
    fixed = []
    for v in data.get("fixed_versions") or []:
        v = str(v).strip()
        if _VERSIONISH.match(v):
            fixed.append(v)
        elif v:
            notes.append(f"fixed in: {v}")
    return {**data, "ranges": ranges, "fixed_versions": fixed, "notes": notes}


class VulnerabilityReport(BaseModel):
    vuln_id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    description: str = ""
    cwe: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    vulnerable_functions: list[str] = Field(default_factory=list, description="Functions / APIs / symbols")
    vulnerable_files: list[str] = Field(default_factory=list)
    attack_vector: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    exploit_available: bool | None = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    research_complete: bool = True
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Container / target analysis
# ---------------------------------------------------------------------------


class Entrypoint(BaseModel):
    kind: str = Field(description="entrypoint|cmd|systemd|init|supervisord|cron|other")
    command: str
    source: str = ""


class SecurityControl(BaseModel):
    name: str
    status: str = Field(description="present|absent|partial|unknown")
    detail: str = ""


class WebFindings(BaseModel):
    summary: str = ""
    image_purpose: str = ""
    vendor: str = ""
    documented_ports: list[str] = Field(default_factory=list)
    documented_security: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class ContainerReport(BaseModel):
    target: str
    kind: str = "container"
    digest: str = ""
    container_type: str = Field(
        default="unknown",
        description="base-os|language-runtime|web-server|web-app|database|message-queue|ml-inference|cli-tool|"
        "build-tool|proxy|host-system|other|unknown",
    )
    distro: dict[str, str] = Field(default_factory=dict)
    summary: str = ""
    purpose: str = ""
    package_counts: dict[str, int] = Field(default_factory=dict)
    key_dependencies: list[str] = Field(default_factory=list)
    language_runtimes: list[str] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    exposed_ports: list[str] = Field(default_factory=list)
    user: str = ""
    network_exposure: str = ""
    security_controls: list[SecurityControl] = Field(default_factory=list)
    web_findings: WebFindings | None = None
    notes: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Exploitability
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    kind: str = Field(description="file|package|binary|config|symbol|web|reasoning")
    path: str = ""
    detail: str = ""


class PretriageResult(BaseModel):
    package: str
    ecosystem: str
    found: bool
    installed: list[dict[str, str]] = Field(default_factory=list, description="[{name,version,location}]")
    vulnerable: bool | None = None
    backport_patched: bool | None = None
    reason: str = ""


class DeepAnalysis(BaseModel):
    """Schema the LLM fills during deep exploitability analysis."""

    verdict: Verdict
    summary: str
    reachability_chain: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list, description="Conditions required for exploitation")
    conditions_met: bool | None = Field(
        default=None, description="Are the conditions met in this target? null if undeterminable"
    )
    mitigations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    risk_level: RiskLevel = "unknown"


class ProbeRecord(BaseModel):
    """One live probe, kept verbatim for audit."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    ok: bool = True
    output: str = ""


class RuntimeCheck(BaseModel):
    """An empirical posture finding about the running target (not tied to one CVE)."""

    title: str
    status: Literal["issue", "ok", "info"] = Field(description="issue = weakness found; ok = check passed")
    severity: RiskLevel = "unknown"
    evidence: str = Field(default="", description="What was run and what it returned")
    recommendation: str = ""


class PostureAssessment(BaseModel):
    """Schema the live verifier fills for target-level checks."""

    summary: str
    checks: list[RuntimeCheck] = Field(default_factory=list)


class RuntimeReport(BaseModel):
    engine: str
    container: str | None = None
    available: bool = False
    summary: str = ""
    facts: dict[str, Any] = Field(default_factory=dict, description="docker inspect digest: networks, ports, user...")
    checks: list[RuntimeCheck] = Field(default_factory=list)
    probes: list[ProbeRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ConditionCheck(BaseModel):
    condition: str = Field(description="The static-analysis claim or exploitation condition being tested")
    method: str = Field(description="Probe(s) used")
    observed: str = Field(description="What the live target returned")
    holds: bool | None = Field(description="Does the condition hold on the running target? null = untestable")


class VerificationAssessment(BaseModel):
    """Schema the live verifier fills for one CVE."""

    outcome: Literal["confirmed", "refuted", "inconclusive"] = Field(
        description="confirmed: live evidence supports the static verdict; refuted: it contradicts it")
    summary: str
    checks: list[ConditionCheck] = Field(default_factory=list)
    conditions_met: bool | None = Field(default=None, description="Exploitation conditions met on the live target")
    verdict: Verdict | None = Field(default=None, description="Corrected verdict when refuted; else the same verdict")
    confidence: float = Field(ge=0, le=1)


class VerificationReport(VerificationAssessment):
    static_verdict: Verdict | None = None
    probes: list[ProbeRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ExploitabilityReport(BaseModel):
    vuln_id: str
    verdict: Verdict | None = None
    early_exit: bool = False
    early_exit_justification: Justification | None = None
    pretriage: list[PretriageResult] = Field(default_factory=list)
    summary: str = ""
    reachability_chain: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    conditions_met: bool | None = None
    mitigations: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    risk_level: RiskLevel = "unknown"
    complete: bool = False
    verification: VerificationReport | None = Field(default=None, description="Live verification, if it ran")
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# VEX
# ---------------------------------------------------------------------------


class DecisionStep(BaseModel):
    step: int
    node: str
    question: str
    answer: str
    evidence: str = ""


class VexResult(BaseModel):
    cve_id: str
    container: str
    status: VexStatus
    justification: Justification
    reasoning: str
    decision_trace: list[DecisionStep] = Field(default_factory=list)
    exploitability_verdict: Verdict | None = None
    confidence: float = 0.0
    risk_level: RiskLevel = "unknown"
    container_type: str = "unknown"
    relaxed_mode: bool = False
    report_paths: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class CveResult(BaseModel):
    vulnerability_report: VulnerabilityReport
    exploitability_report: ExploitabilityReport
    vex: VexResult


class PipelineOutput(BaseModel):
    run_id: str
    target: str
    digest: str
    container_report: ContainerReport
    results: list[CveResult]
    runtime_report: RuntimeReport | None = None
    output_dir: str
    summary_path: str
    openvex_path: str
