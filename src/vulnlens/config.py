"""Settings: YAML config file + environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

AGENTS = ("cve_researcher", "container_analyzer", "exploitability", "vex_categorizer", "live_verifier", "reflector")


class LLMSpec(BaseModel):
    provider: Literal["anthropic", "ollama", "deepseek", "zai"]
    model: str
    max_tokens: int = 16000
    # Anthropic: output_config.effort (low|medium|high|xhigh|max). Z.ai GLM: reasoning_effort
    # (none|minimal|low|medium|high|xhigh|max). None = model default.
    effort: str | None = None
    # Ollama only
    base_url: str | None = None
    temperature: float | None = None
    num_ctx: int | None = 32768
    timeout: float = 600.0
    # Ollama / Z.ai: thinking on/off for reasoning models (qwen3.x, gemma4, GLM...). None = model default.
    reasoning: bool | None = None
    keep_alive: str | None = "30m"
    # DeepSeek only (OpenAI-compatible API). Key comes from DEEPSEEK_API_KEY; base_url defaults to the public API.
    # extra_body is passed verbatim to the API (e.g. to toggle thinking mode).
    extra_body: dict | None = None
    # Per-profile step budgets for the agent loops (merged over the global max_react_steps). Fast hosted models
    # can afford more steps; slow local ones may need fewer.
    max_react_steps: dict[str, int] | None = None
    # Max simultaneous requests to this profile within one process. None = unlimited.
    # Local Ollama defaults to 1: parallel agents otherwise load several KV caches and can OOM small machines.
    max_concurrency: int | None = None

    def effective_concurrency(self) -> int | None:
        if self.max_concurrency is not None:
            return self.max_concurrency
        return 1 if self.provider == "ollama" else None


def _default_llms() -> dict[str, LLMSpec]:
    return {
        "default": LLMSpec(provider="anthropic", model="claude-opus-5-5", effort="high"),
        "fast": LLMSpec(provider="anthropic", model="claude-haiku-5-5", effort="medium", max_tokens=8000),
        "local": LLMSpec(provider="ollama", model="llama3.2:latest", base_url=None, temperature=0.0, num_ctx=8192),
    }


# Read-only commands the live verifier may run inside the target. Each regex must fully match the shell-quoted
# argv (no shell is used). Paths that look like secret stores are refused separately (tools/runtime.py).
_PATH = r"/[\w./@+-]*"
DEFAULT_ALLOWLIST = [
    r"id(?: [\w.-]+)?", r"whoami", r"uname -a", r"hostname", r"cat /etc/os-release",
    r"ps(?: -?[aefuxwlo]+)*(?: -o [\w,%]+)?", r"ss -[tulpnHae]+", r"netstat -[tulpnae]+",
    rf"ls(?: -[alhdRtn1]+)? {_PATH}", rf"(?:cat|head|tail(?: -n \d+)?) (?:/etc|/opt|/usr|/var/lib|/proc/1|/proc/self){_PATH}",
    r"getent (?:passwd|group)(?: [\w.-]+)?", r"mount", r"df -h", r"capsh --print", r"cat /proc/1/status",
    r"cat /proc/net/(?:tcp6?|udp6?)", rf"stat {_PATH}", rf"find {_PATH} -maxdepth [1-3](?: -name [\w.*?-]+)?(?: -type [fdl])?",
    r"(?:openssl version(?: -a)?|nginx -[vVT]|java -version|python3? --version|node --version|httpd -[vVM]|apache2ctl -[MS])",
    # RabbitMQ
    r"rabbitmqctl(?: -q)? (?:list_users|list_vhosts|list_permissions(?: -p [\w/%.-]+)?|list_user_permissions [\w.@-]+|"
    r"list_user_limits|list_policies|list_parameters|list_global_parameters|status|cluster_status|"
    r"authenticate_user guest guest)(?: --formatter (?:json|table))?",
    r"rabbitmq-plugins list(?: -[em]+)*",
    r"rabbitmq-diagnostics(?: -q)? (?:listeners|status|server_version|erlang_version|tls_versions|cipher_suites|"
    r"check_port_connectivity|check_running|check_local_alarms|environment)(?: --formatter (?:json|table))?",
    # PostgreSQL / Redis / Nginx-style config dumps
    r"redis-cli INFO(?: server| clients)?", r"redis-cli CONFIG GET (?:protected-mode|bind|port|tls-port|requirepass)",
    r"psql -At -c (?:'SHOW [a-z_]+'|'SELECT version\(\)')",
]


class LiveProbeSettings(BaseModel):
    allowlist: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    # Well-known default "user:password" pairs the verifier may try against the target's own HTTP endpoints.
    default_credentials: list[str] = Field(default_factory=list)
    timeout: float = 20.0
    connect_timeout: float = 4.0
    max_output_chars: int = 6000
    # Static verdicts worth checking live. NOT_REACHABLE is included because it often rests on a config gate
    # (protocol not enabled, directive absent) that a probe can observe; NOT_APPLICABLE rests on file evidence.
    verify_verdicts: list[str] = Field(default_factory=lambda: [
        "CONDITIONALLY_EXPLOITABLE", "EXPLOITABLE", "MITIGATED", "ENVIRONMENT_ISOLATED", "NOT_REACHABLE"])


class LLMCacheSettings(BaseModel):
    """Local LLM response cache (see vulnlens.llm_cache)."""
    backend: str = "sqlite"            # valkey | redis | sqlite | memory | none
    path: str | None = None            # sqlite file; default <cache_dir>/llm_cache.sqlite
    redis_url: str = "redis://127.0.0.1:6379/0"   # valkey/redis; VULNLENS_VALKEY_URL / VULNLENS_REDIS_URL override
    prefix: str = "vulnlens:llm"       # key namespace on the shared server
    ttl: int | None = None             # seconds (valkey/redis); None = keep forever
    fallback: str = "sqlite"           # when valkey/redis is unreachable: sqlite | none (= fail the run)
    # Agents whose LLM calls depend on live state and must always be fresh.
    exclude_agents: list[str] = Field(default_factory=lambda: ["live_verifier"])


class SkillsSettings(BaseModel):
    """Self-evolving harness (see vulnlens.skills): learned playbooks injected into agent prompts."""
    enabled: bool = True
    dir: str | None = None             # default <cache_dir>/skills; list <dir>/active in Hermes skills.external_dirs
    max_chars: int = 6000              # playbook text inlined per agent call; the rest via the skill_view tool
    max_skills: int = 6
    auto_learn: bool = False           # run the reflector at the end of every run (proposals still go to pending)
    require_replay: bool = True        # `skills approve` needs a passing gold-set replay (override with --force)
    gold_set: str = "eval/gold/vulnlens_local.jsonl"
    replay_repeats: int = 2            # k: runs per arm, to see through model nondeterminism
    include_pending: list[str] = Field(default_factory=list)  # set by the gate to trial candidates


class Settings(BaseModel):
    llms: dict[str, LLMSpec] = Field(default_factory=_default_llms)
    agents: dict[str, str] = Field(default_factory=lambda: {a: "default" for a in AGENTS})

    cache_dir: str = Field(default_factory=lambda: os.path.expanduser("~/.cache/vulnlens"))
    output_dir: str = "./output"

    max_react_steps: dict[str, int] = Field(
        default_factory=lambda: {"cve_researcher": 8, "container_web": 6, "container_fs": 14, "exploitability": 20,
                                 "live_posture": 16, "live_verify": 10}
    )
    live_probes: LiveProbeSettings = Field(default_factory=LiveProbeSettings)
    llm_cache: LLMCacheSettings = Field(default_factory=LLMCacheSettings)
    skills: SkillsSettings = Field(default_factory=SkillsSettings)
    max_tool_output_chars: int = 12000
    relaxed_confidence_threshold: float = 0.6

    # External binaries / services
    crane_bin: str = "crane"
    container_cli_fallbacks: list[str] = Field(default_factory=lambda: ["podman", "docker"])
    tavily_api_key: str | None = None
    github_token: str | None = None
    nvd_api_key: str | None = None
    http_timeout: float = 30.0
    allow_private_fetch: bool = False

    @property
    def skills_dir(self) -> str:
        return os.path.expanduser(self.skills.dir or os.path.join(self.cache_dir, "skills"))

    def llm_for(self, agent: str, profile_override: str | None = None) -> tuple[str, LLMSpec]:
        name = profile_override or self.agents.get(agent, "default")
        if name not in self.llms:
            raise KeyError(f"LLM profile '{name}' (agent {agent}) not defined in config")
        return name, self.llms[name]


def _find_default_config() -> Path | None:
    env = os.environ.get("VULNLENS_CONFIG")
    if env:
        return Path(env)
    for cand in (Path.cwd() / "configs" / "default.yml", Path.cwd() / "vulnlens.yml"):
        if cand.exists():
            return cand
    return None


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    cfg_path = Path(path) if path else _find_default_config()
    data: dict = {}
    if cfg_path and cfg_path.exists():
        data = yaml.safe_load(cfg_path.read_text()) or {}
    if "llms" in data:
        merged = {k: v.model_dump() for k, v in _default_llms().items()}
        merged.update(data["llms"])
        data["llms"] = merged
    if "agents" in data:
        data["agents"] = {**{a: "default" for a in AGENTS}, **data["agents"]}
    s = Settings(**data)
    # env vars win for secrets
    s.tavily_api_key = os.environ.get("TAVILY_API_KEY", s.tavily_api_key)
    s.github_token = os.environ.get("GITHUB_TOKEN", s.github_token)
    s.nvd_api_key = os.environ.get("NVD_API_KEY", s.nvd_api_key)
    if os.environ.get("VULNLENS_LLM_CACHE"):
        s.llm_cache.backend = os.environ["VULNLENS_LLM_CACHE"]
    if os.environ.get("VULNLENS_CACHE_DIR"):
        s.cache_dir = os.environ["VULNLENS_CACHE_DIR"]
    s.cache_dir = os.path.expanduser(s.cache_dir)
    ollama_host = os.environ.get("OLLAMA_HOST")
    for spec in s.llms.values():
        if spec.provider == "ollama" and not spec.base_url:
            spec.base_url = ollama_host if ollama_host and ollama_host.startswith("http") else "http://localhost:11434"
        elif spec.provider == "deepseek" and not spec.base_url:
            spec.base_url = os.environ.get("DEEPSEEK_API_BASE", "https://api.deepseek.com")
        elif spec.provider == "zai" and not spec.base_url:
            spec.base_url = os.environ.get("ZAI_BASE_URL", "https://api.z.ai/api/paas/v4")
    return s
