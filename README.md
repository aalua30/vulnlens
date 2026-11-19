# VulnLens

LangGraph-based vulnerability **exploitability and VEX analysis** for container images *and* standard
deployments (VMs, bare-metal hosts, extracted application trees). It follows the shape of NVIDIA's
"Vulnerability Analysis for Container Security" blueprint, but runs on **Claude** (default), **Ollama**, **DeepSeek** or **Z.ai GLM**,
uses **Tavily** plus NVD / GitHub Advisories / OSV for research, and treats the target filesystem as ground truth.

```
PipelineInput ─► resolve_target (crane│podman│docker → flattened rootfs, cached by digest; or filesystem_path)
                 │   └─ deterministic inventory: dpkg/rpm/apk, Python, npm, Java (nested jars), Go buildinfo, .so
                 ├─► Container/Target Analyzer  (phase A: web research · phase B: filesystem, isolated context)
                 │     └─ [Live Verifier: posture checks on the running target]      (opt-in)
                 └─► CVE Researcher ×N          (NVD + GHSA + OSV → LLM gap-filling with Tavily/fetch)
                         ▼ join
                 analyze_cve ×N:  Exploitability (deterministic pre-triage → LLM reachability)
                                  → [Live Verifier: confirm/refute runtime-dependent verdicts] (opt-in)
                                  → VEX Categorizer (precedence flowchart + decision trace)
                                  → Markdown + JSON reports
                 finalize: summary.json · openvex.json · index.md · report.html
```

## Install

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'            # add ,nat for NeMo Agent Toolkit (Python 3.11–3.13)
export ANTHROPIC_API_KEY=...        # Claude (default LLM profile)
export TAVILY_API_KEY=...           # web research
export GITHUB_TOKEN=...             # optional, raises GHSA rate limit
export NVD_API_KEY=...              # optional, raises NVD rate limit
```

Image acquisition uses `crane` if present (`go install github.com/google/go-containerregistry/cmd/crane@latest`),
otherwise falls back to `podman` / `docker` (`create` + `export`, which also flattens layers).

## Run

```bash
vulnlens run examples/nginx.json                # Claude for every agent
vulnlens run examples/nginx.json --llm local    # Ollama for every agent (profile "local")
vulnlens run examples/nginx.json --llm remote   # Ollama on another host (profile "remote", base_url in config)
DEEPSEEK_API_KEY=sk-... vulnlens run examples/nginx.json --llm deepseek   # DeepSeek API (pip install -e '.[deepseek]')
ZAI_API_KEY=... vulnlens run examples/nginx.json --llm glm               # Z.ai glm-5.3-flash (pip install -e '.[zai]')
vulnlens run examples/host.json                 # a standard (non-container) deployment
vulnlens run examples/nginx.json --relaxed      # relaxed VEX categorization
vulnlens run examples/nginx.json --refresh vex_categorizer   # recompute only one agent
vulnlens run input.json --container my-app-1    # + read-only live checks on a running container
vulnlens report output/<run_dir>                # regenerate report.html for a finished run
vulnlens discover /path/to/rootfs -o candidates.json --input-out input.json   # candidate CVEs via OSV (+ --cpe)
vulnlens inventory /path/to/rootfs              # deterministic inventory only, no LLM
vulnlens pretriage CVE-2024-6387 /path/to/rootfs   # databases + inventory only, no LLM
```

### PipelineInput

```json
{
  "vulnerabilities": [{"vuln_id": "CVE-2024-6387", "package_hint": "openssh", "notes": "optional"}],
  "target": {
    "kind": "container",                // or "host"
    "image_name": "docker.io/library/nginx", "image_tag": "1.25",
    "filesystem_path": null,            // already-extracted rootfs (skips pulling)
    "image_config_path": null,          // OCI config JSON (crane config) for user/entrypoint/ports
    "private": false,                   // private image → no public web research
    "deployment_notes": "behind WAF, port 443 only",
    "runtime": {"engine": "docker", "container": "my-app-1"}   // optional: running workload for live checks
  },
  "options": {"skip_web_research": false, "relaxed_vex": false, "max_parallel_cves": 4,
              "llm_profile": null, "llm_overrides": {"vex_categorizer": "fast"}, "live_verification": false},
  "output": {"dir": "./output", "write_markdown": true, "write_html": true},
  "cache":  {"enabled": true, "dir": null, "refresh": []}
}
```

The blueprint's flat form (`image_name`, `image_tag`, `filesystem_path`, … at top level, `vulnerabilities` as
plain strings) is also accepted.

### Outputs (`output/<run_id>_<target>/`)

| File | Contents |
|---|---|
| `container_analysis.md/.json` | target type, entrypoints, dependencies, security controls, web findings |
| `<CVE>/cve_research.md/.json` | affected packages and ranges, vulnerable functions, attack vector, remediation |
| `<CVE>/exploitability.md/.json` | pre-triage table, verdict, reachability chain, evidence, conditions |
| `<CVE>/vex.md`, `<CVE>/vex.json` | `cve_id, container, status, justification, reasoning, decision_trace, exploitability_verdict, confidence, risk_level, container_type, report_paths` |
| `summary.json`, `openvex.json`, `index.md` | all results; an OpenVEX v0.2.0 document |
| `report.html` | self-contained analyst report: summary, actions, exposure, live checks, every finding |
| `runtime_verification.md/.json` | live posture checks, runtime facts and the full probe log (live runs only) |
| `inventory.json` | the deterministic software inventory |

## Agents

**Exploitability verdicts:** `NOT_APPLICABLE`, `ENVIRONMENT_ISOLATED`, `NOT_REACHABLE`, `MITIGATED`,
`CONDITIONALLY_EXPLOITABLE`, `EXPLOITABLE`.

**Pre-triage** (no LLM) finds each affected package in the inventory, compares versions with the right
comparator for each ecosystem (dpkg, rpm, apk, PEP 440, semver, Maven), and checks distro backports (OSV distro
advisories queried at the installed version, plus the package changelog). It exits early on:
- package absent → `NOT_APPLICABLE` / `code_not_present`
- distro backport present → `NOT_APPLICABLE` / `code_not_present`
- installed version outside all affected ranges → `NOT_APPLICABLE` / `false_positive`

**VEX flowchart** (precedence order, every step recorded in `decision_trace`):

1. Incomplete analysis → `unknown` / `uncertain`
2. NOT_APPLICABLE → `not_affected` / `code_not_present` or `false_positive`
3. ENVIRONMENT_ISOLATED → `not_affected` / `requires_environment`, `perimeter_protected`, or `requires_dependency`
4. NOT_REACHABLE → `not_affected` / `code_not_reachable`
5. MITIGATED → `not_affected` / `mitigating_control_protected`, `compiler_protected`, or `perimeter_protected`
6. CONDITIONALLY_EXPLOITABLE → `not_affected` / `requires_*` if the conditions are not met, otherwise
   `affected` / `vulnerable`. In **relaxed** mode, undetermined conditions also give `requires_*`.
7. EXPLOITABLE → `affected` / `vulnerable`. In **relaxed** mode, low confidence with no reachability chain
   gives `code_not_reachable`.

The flowchart sets the status. The LLM only picks a justification from the allowed set and writes the
reasoning. If the LLM fails, a fallback justification and a templated reasoning are used.

### Live Verifier (opt-in)

Static analysis reads files; some questions need the running process. With `options.live_verification: true`
and `target.runtime` set (or `vulnlens run --container NAME`), the Live Verifier agent probes the running target:

- **Posture checks, once per target**: run-as user, privileges and capabilities, published ports and peer
  containers, what actually listens, TLS, which HTTP endpoints answer without auth, default accounts (e.g.
  `rabbitmqctl list_users`, and whether `guest:guest` is accepted from a non-loopback address), and enabled
  plugins. Issues show up as recommended actions in `report.html`.
- **Per-CVE re-checks** for verdicts that depend on runtime facts (`live_probes.verify_verdicts`, by default
  CONDITIONALLY_EXPLOITABLE, EXPLOITABLE, MITIGATED, ENVIRONMENT_ISOLATED). The agent tests each condition and
  either confirms, refutes (with a corrected verdict / `conditions_met`), or reports inconclusive. Refuted
  results change the VEX outcome, and the static verdict is kept in `verification.static_verdict` and in the
  decision trace. Inconclusive results change nothing.

Probe tools: `runtime_facts` (from `docker inspect`; environment *names* only), `run_command`,
`tcp_connect`, `http_request` (GET/HEAD/OPTIONS), `http2_cleartext_probe`, `tls_probe`. Safety limits:

- `run_command` uses no shell. The argv must fully match a regex in `live_probes.allowlist` (read-only inspection
  commands only), and paths that look like secret stores (`shadow`, `.erlang.cookie`, `*/environ`, keys) are
  refused.
- Network probes connect only to the target's own addresses and send benign requests: no exploit payloads, no
  floods, no brute force. The only credentials tried are those in `live_probes.default_credentials`; the model
  names the user, and the password never passes through it.
- Output is truncated and secrets are redacted. Every probe, refused ones included, is logged in the report.
- Live results are never cached, because the running target can change independently of its image.

## Serving

```bash
vulnlens serve --port 8000
curl -s localhost:8000/generate -H 'content-type: application/json' -d @examples/nginx.json
curl -s localhost:8000/v1/workflow/async -H 'content-type: application/json' -d @examples/nginx.json
curl -s localhost:8000/v1/workflow/async/job/<job_id>
curl -s -X POST localhost:8000/v1/workflow/async/job/<job_id>/resume   # after a crash / failure
```

**With NAT** (`pip install -e '.[nat]'`): the package registers workflow `_type: vulnlens` (and evaluator
`vex_accuracy`) through the `nat.components` entry point:

```bash
nat serve --config_file configs/nat_workflow.yml
nat eval  --config_file configs/nat_workflow.yml
```

## Evaluation

```bash
vulnlens eval data/eval/morpheus_25.06.json --limit 10 -o output/eval/report.json
```

The loader accepts JSON, JSONL, or CSV. Each record needs an image (or `filesystem_path`), a CVE id, and the
expected `status` (and optionally `justification`). Records that carry a whole PipelineInput under `input` work
too. Common label synonyms are normalized. Metrics are status accuracy, justification accuracy, per-class
precision/recall/F1, a confusion matrix, and the unknown rate.

## Self-evolving harness (learned playbooks)

VulnLens learns from its own runs in the style of Hermes Agent's learning loop, but every lesson is gated:

```
run ─► experience.json (signals) ─► vulnlens learn ─► skills/pending ─► skills replay (gold set) ─► skills approve ─► skills/active
                                                                                                                   │
next run: playbooks matched by agent / package / CWE / distro (+ FTS5) are appended to the agent's system prompt ◄─┘
```

- **Signals.** Every run writes `experience.json`. Its signals come from several sources:
  - live verification that refuted or confirmed a static verdict;
  - analyst feedback;
  - exhausted step budgets, failing tool calls, invalid JSON;
  - unknown or low-confidence verdicts;
  - verdict flips against earlier runs of the same digest;
  - gold-set mismatches.
- **Feedback.** Record it with `vulnlens feedback <run_dir> <CVE> --note "…" [--status … --justification …] [--gold]`.
  `--gold` also adds the label to the gold set (`eval/gold/vulnlens_local.jsonl`).
- **Reflection.** `vulnlens learn <run_dir>…` runs the `reflector` agent, which proposes at most 3 playbooks
  (create or patch). Proposals are handled as follows:
  - **scrubbed** of IPs, host and target names, home-directory user names, e-mails and credentials;
  - **scanned**, and rejected if they contain prompt-injection phrasing, prescribe a verdict unconditionally, link
    to URLs outside advisory sources, carry a shell command that is not read-only, or are oversized;
  - **staged** in `skills/pending`, never activated directly.
- **Gate.**
  - `vulnlens skills replay <name> [-k N]` runs the gold set with and without the candidate. It passes only if the
    candidate was actually injected and no metric regressed (status accuracy, justification accuracy, unknown
    rate, exhausted budgets). Fewer exploitability steps count as an improvement.
  - Gold records listing the skill's `evidence_runs` are held out. If nothing would be left, the replay runs on
    the whole set and is marked in-sample.
  - `vulnlens skills approve <name>` requires a passing replay of the playbook's *current* text; `--force`
    overrides this.
  - Other commands: `skills list|pending|show|diff|reject|lock|rollback|add`.
- **Injection.** Approved playbooks are matched per agent call and appended to the system prompt under
  "Playbooks from earlier analyses", within a budget (`skills.max_chars`). Skills that don't fit are reachable
  through a `skill_view` tool. The selected set's hash goes into the agent-cache key, so a new or edited playbook
  re-runs exactly the agents it applies to. Playbooks are advisory text only: they cannot change tool allowlists,
  the jail, live-probe rules, or the deterministic VEX flowchart.
- **Disable.** `options.use_skills: false` turns playbooks off for one run; `skills.enabled: false` turns them off
  everywhere. `skills.auto_learn: true` (or `options.learn`) runs the reflector after every run, which still only
  stages proposals.

Storage is `~/.cache/vulnlens/skills/{active,pending,rejected}/<name>/SKILL.md`, with `history/` for rollback. The
format is Hermes/agentskills.io `SKILL.md`; routing fields live under `metadata.vulnlens`.

## Hermes Agent integration

`vulnlens mcp` (extra `mcp`: `pip install -e '.[mcp]'`) serves vulnlens over MCP (stdio, or
`--transport streamable-http`, which binds 127.0.0.1). Its tools are:
- `list_examples`, `start_scan`, `scan_status` (background jobs in `jobs.sqlite`);
- `list_runs`, `get_summary`, `get_report`;
- `discover` (candidate CVEs for a running container, an image or a rootfs, ranked main-application first, with a
  ready `start_scan` input; it guesses the application's NVD CPE from the image name and tag);
- `inventory`, `pretriage` (deterministic, no LLM);
- `record_feedback`, `learn`, `skills_list`, `skill_show`.

Approval and replay stay human-only CLI steps. `start_scan(live_verification=true)` is refused unless the server
runs with `VULNLENS_MCP_ALLOW_LIVE=1`.

To set it up:
1. Install Hermes: `curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash`. Check the current command in the
   Hermes docs.
2. Merge `integrations/hermes/config.example.yaml` into `~/.hermes/config.yaml`. This adds the `mcp_servers.vulnlens`
   entry and `skills.external_dirs`, so Hermes reads vulnlens' approved playbooks and the bundled
   `vulnlens-triage` skill.
3. Example: `hermes -z "Use vulnlens to check examples/httpd_host.json and summarize the VEX results"`.

Skills written by Hermes can come back through the same gate with `vulnlens skills add path/to/SKILL.md`.

## Caching and resume

- RootFS: `~/.cache/vulnlens/rootfs/<digest>/`, with a lock so concurrent runs extract only once.
- Inventory: `~/.cache/vulnlens/inventory/<digest>.json`.
- Agent outputs: `~/.cache/vulnlens/agents/<agent>/…`, keyed by agent inputs, digest, and model. Writes are
  atomic, and failed or incomplete results are not cached, so a re-run redoes only the missing work.
  CVE research is keyed by CVE only, so it is reused across targets.
- LLM responses: a local Valkey (`valkey.service`, `redis://127.0.0.1:6379/0`, keys `vulnlens:llm:*`, 30-day
  TTL) as shipped in `configs/default.yml`, or SQLite at `~/.cache/vulnlens/llm_cache.sqlite` with
  `llm_cache.backend: sqlite`. When an agent's output cache misses, for example because the container profile
  changed, its identical model requests are still answered locally. The run then pays only from the first ReAct step
  whose prompt, model parameters or tools differ. `--refresh <agent>` and `--no-cache` bypass this cache too, and
  `live_verifier` is excluded because live state changes. If Valkey is down, the run falls back to SQLite
  (`fallback: none` makes it fail instead).
  The Valkey/Redis backend uses plain `GET`/`SET EX` (no RedisJSON module needed) with the `redis` or `valkey`
  Python client (`pip install 'vulnlens[valkey]'`). Cached entries can only rebuild model-response objects.
  `vulnlens llm-cache info` shows the backend, server and entry count; `vulnlens llm-cache clear` empties it.
  Each run logs `LLM response cache …: hits= misses= writes=`.
- Provider prompt caching is separate and happens server-side. On Claude, the system prompt carries an explicit
  `cache_control` breakpoint and the request sets top-level automatic caching, so the growing tool-loop history
  is cached too. DeepSeek and Z.ai GLM cache prefixes automatically. The logs show `cache_read=` / `cache_creation=` tokens
  per step.

## Security notes

- Extraction rejects path traversal and writes through symlinks. It skips device nodes and strips
  setuid/setgid bits on disk, but records them in `manifest.json` for the security-controls tool.
- Filesystem tools resolve symlinks *inside* the rootfs jail and never touch host paths.
- `fetch_url` refuses non-public addresses on every redirect hop (SSRF guard). Set `allow_private_fetch: true` to
  turn this off.
- Image-config environment variables that look like secrets are redacted before they are sent to the LLM.
