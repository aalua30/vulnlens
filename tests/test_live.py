"""Live verifier: probe safety, verdict folding, VEX trace, graph wiring, HTML report and candidate discovery."""

import asyncio
import json
import subprocess

import httpx
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from test_graph import FakeChat, _intel

from vulnlens import graph as graph_mod
from vulnlens.agents import cve_researcher
from vulnlens.agents.live_verifier import apply_verification, needs_verification
from vulnlens.agents.vex_categorizer import decide
from vulnlens.config import LiveProbeSettings, LLMSpec, Settings
from vulnlens.discover import build_queries, discover, package_hint, to_vulnerabilities
from vulnlens.llm import LLMHandle
from vulnlens.models import (ConditionCheck, ExploitabilityReport, PipelineInput, RuntimeSpec, Verdict,
                             VerificationReport, VexStatus)
from vulnlens.reports.html import load_run, render_html
from vulnlens.tools import Jail, build_inventory
from vulnlens.tools import runtime as rt_mod
from vulnlens.tools.runtime import LiveTarget, digest_inspect, redact

INSPECT = [{
    "Name": "/mq-1", "Config": {"Image": "rabbitmq:4.3-management", "User": "",
                                "Env": ["RABBITMQ_DEFAULT_PASS=topsecret", "PATH=/usr/bin"],
                                "ExposedPorts": {"5672/tcp": {}, "15672/tcp": {}}},
    "HostConfig": {"Privileged": False, "ReadonlyRootfs": False, "NetworkMode": "app_default"},
    "NetworkSettings": {"Networks": {"app_default": {"IPAddress": "172.18.0.5", "Aliases": ["rabbitmq"]}},
                        "Ports": {"5672/tcp": None, "15672/tcp": None}},
    "State": {"Status": "running"}, "Mounts": [],
}]


class FakeProc:
    def __init__(self, calls):
        self.calls = calls

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[1] == "inspect":
            out = json.dumps(INSPECT)
        elif argv[1] == "network":
            out = json.dumps({"a": {"Name": "mq-1"}, "b": {"Name": "worker-1"}, "c": {"Name": "connector-1"}})
        elif argv[-1] == "list_users":
            out = "user\ttags\nguest\t[administrator]\nopencti\t[administrator]\n"
        else:
            out = "ok"
        return subprocess.CompletedProcess(argv, 0, out, "")


def _live(monkeypatch, calls=None):
    calls = [] if calls is None else calls
    monkeypatch.setattr(rt_mod.subprocess, "run", FakeProc(calls))
    return LiveTarget(RuntimeSpec(engine="docker", container="mq-1"), LiveProbeSettings()), calls


# --- probe safety -------------------------------------------------------------------------------------------------

def test_allowlist_and_secret_paths():
    lt = LiveTarget(RuntimeSpec(container="x"), LiveProbeSettings())
    assert lt.allowed(["rabbitmqctl", "list_users"])
    assert lt.allowed(["rabbitmqctl", "-q", "authenticate_user", "guest", "guest"])
    assert lt.allowed(["cat", "/etc/rabbitmq/rabbitmq.conf"]) and lt.allowed(["ps", "aux"])
    for bad in (["rabbitmqctl", "delete_user", "guest"], ["rm", "-rf", "/"], ["cat", "/etc/shadow"],
                ["cat", "/var/lib/rabbitmq/.erlang.cookie"], ["cat", "/proc/1/environ"], ["sh", "-c", "id"],
                ["rabbitmqctl", "list_users", ";", "reboot"], ["rabbitmqctl", "add_user", "x", "y"]):
        assert not lt.allowed(bad), bad


def test_redaction():
    out = redact("default_pass = s3cr3t\n{default_pass,<<\"abc\">>}\nRABBITMQ_DEFAULT_PASS=xyz token: t0k user=bob")
    assert "s3cr3t" not in out and "abc" not in out and "xyz" not in out and "t0k" not in out
    assert "user=bob" in out


def test_inspect_digest_hides_env_values():
    d = digest_inspect(INSPECT[0])
    assert d["env_names"] == ["PATH", "RABBITMQ_DEFAULT_PASS"]
    assert "topsecret" not in json.dumps(d)
    assert d["addresses"] == ["172.18.0.5"] and d["published_ports"] == {}


def test_run_command_uses_exec_and_logs_refusals(monkeypatch):
    lt, calls = _live(monkeypatch)
    assert "guest" in lt.run_command("rabbitmqctl list_users")
    assert calls[-1] == ["docker", "exec", "mq-1", "rabbitmqctl", "list_users"]
    n = len(calls)
    assert lt.run_command("rabbitmqctl delete_user guest").startswith("REFUSED")
    assert len(calls) == n  # nothing executed
    assert [p.ok for p in lt.probes] == [True, False]
    facts = lt.inspect()
    assert facts["networks"]["app_default"]["peer_count"] == 2


def test_http_probe_guards(monkeypatch):
    lt, _ = _live(monkeypatch)
    assert lt.http_request(15672, "/api/overview", method="POST").startswith("REFUSED")
    assert lt.http_request(15672, "http://evil/", method="GET").startswith("REFUSED")
    assert "default_credentials" in lt.http_request(15672, "/api/whoami", default_user="admin")


# --- verdict folding and VEX ----------------------------------------------------------------------------------------

def _er(**kw):
    base = dict(vuln_id="CVE-1", verdict=Verdict.CONDITIONALLY_EXPLOITABLE, complete=True, confidence=0.6,
                summary="static", conditions=["peer can reach 15672"], conditions_met=False)
    return ExploitabilityReport(**{**base, **kw})


def test_needs_verification():
    s = Settings()
    assert needs_verification(_er(), s)
    assert needs_verification(_er(verdict=Verdict.NOT_REACHABLE), s)  # config gates are observable live
    assert not needs_verification(_er(verdict=Verdict.NOT_APPLICABLE), s)
    assert not needs_verification(_er(early_exit=True), s)
    assert not needs_verification(_er(complete=False), s)


def test_refuted_verification_flips_vex_and_is_traced():
    er = _er()
    assert decide(er, False, 0.6)[0] == VexStatus.NOT_AFFECTED
    ver = VerificationReport(outcome="refuted", summary="15672 reachable from 2 peers", conditions_met=True,
                             verdict=Verdict.CONDITIONALLY_EXPLOITABLE, confidence=0.85,
                             static_verdict=er.verdict, checks=[ConditionCheck(
                                 condition="peer can reach 15672", method="tcp_connect 15672",
                                 observed="open", holds=True)])
    er2 = apply_verification(er, ver)
    assert er.conditions_met is False  # original untouched
    assert er2.conditions_met is True and er2.confidence == 0.85 and er2.evidence[-1].kind == "runtime"
    status, _, trace = decide(er2, False, 0.6)
    assert status == VexStatus.AFFECTED
    assert any(s.node == "live_verification" and s.answer.startswith("refuted") for s in trace)


def test_inconclusive_verification_changes_nothing():
    er = _er()
    er2 = apply_verification(er, VerificationReport(outcome="inconclusive", summary="x", confidence=0.1,
                                                    conditions_met=True))
    assert er2.conditions_met is False and er2.confidence == 0.6 and er2.verification is not None


# --- graph + HTML ---------------------------------------------------------------------------------------------------

class LiveFakeChat(FakeChat):
    def _generate(self, messages, stop=None, run_manager=None, **kw):
        last = messages[-1].content if isinstance(messages[-1].content, str) else json.dumps(messages[-1].content)
        system = messages[0].content if isinstance(messages[0].content, str) else messages[0].content[0]["text"]
        if "JSON Schema" not in last and messages[-1].type == "human" and "running workload" in system:
            msg = AIMessage(content="", tool_calls=[{"name": "run_command", "id": "p1",
                                                     "args": {"command": "rabbitmqctl list_users"}}])
            return ChatResult(generations=[ChatGeneration(message=msg)])
        if "JSON Schema:\n" in last:
            title = json.loads(last.split("JSON Schema:\n", 1)[1])["title"]
            if title == "PostureAssessment":
                payload = {"summary": "Default guest account present.", "checks": [
                    {"title": "Default guest account exists", "status": "issue", "severity": "medium",
                     "evidence": "rabbitmqctl list_users -> guest [administrator] <script>x</script>",
                     "recommendation": "Delete the guest user."}]}
                return ChatResult(generations=[ChatGeneration(message=AIMessage(content=json.dumps(payload)))])
            if title == "VerificationAssessment":
                payload = {"outcome": "confirmed", "summary": "server.js running", "confidence": 0.9,
                           "verdict": "EXPLOITABLE", "checks": [{"condition": "node serves /app/server.js",
                                                                  "method": "ps aux", "observed": "node /app/server.js",
                                                                  "holds": True}]}
                return ChatResult(generations=[ChatGeneration(message=AIMessage(content=json.dumps(payload)))])
        return super()._generate(messages, stop, run_manager, **kw)


def test_pipeline_with_live_verification_and_html(rootfs, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(rt_mod.subprocess, "run", FakeProc(calls))
    monkeypatch.setattr(cve_researcher, "gather_intel", _intel)
    monkeypatch.setattr(cve_researcher, "web_tools", lambda s: [])
    monkeypatch.setattr(graph_mod, "get_llm", lambda s, a, p=None, **kw: LLMHandle(
        "fake", LLMSpec(provider="ollama", model="fake"), LiveFakeChat()))
    settings = Settings(cache_dir=str(tmp_path / "cache"), output_dir=str(tmp_path / "out"))
    inp = PipelineInput.model_validate({
        "vulnerabilities": ["CVE-2021-23337", "CVE-2024-26925"],
        "target": {"filesystem_path": str(rootfs), "name": "mq-1", "private": True,
                   "runtime": {"engine": "docker", "container": "mq-1"}},
        "options": {"live_verification": True},
        "output": {"dir": str(tmp_path / "out")},
    })
    out = asyncio.run(graph_mod.run_pipeline(inp, settings))
    rr = out.runtime_report
    assert rr and rr.available and rr.checks[0].status == "issue"
    assert any(p.tool == "run_command" for p in rr.probes)
    assert ["docker", "exec", "mq-1", "rabbitmqctl", "list_users"] in calls
    by = {r.vex.cve_id: r for r in out.results}
    lod = by["CVE-2021-23337"]
    assert lod.exploitability_report.verification.outcome == "confirmed"
    assert any(s.node == "live_verification" for s in lod.vex.decision_trace)
    assert by["CVE-2024-26925"].exploitability_report.verification is None  # pre-triage early exit: not probed

    html = (tmp_path / "out").glob("*/report.html").__next__().read_text()
    assert html.startswith("<!doctype html>")
    assert "Default guest account exists" in html and "Delete the guest user." in html
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "Live verification" in html and "CVE-2021-23337" in html
    # regenerate from disk
    again = load_run(out.output_dir)
    assert again.runtime_report.checks[0].title == "Default guest account exists"
    frag = render_html(again, standalone=False)
    assert frag.startswith("<title>") and "<html" not in frag


# --- discovery ------------------------------------------------------------------------------------------------------

def test_discover_queries_and_mapping(rootfs):
    inv = build_inventory(Jail(rootfs))
    labels = [l for l, _ in build_queries(inv)]
    assert "debian:openssl=3.0.11-1~deb12u2" in labels and "npm:lodash=4.17.20" in labels
    assert any(l.startswith("maven:") for l in labels) and "pypi:requests=2.31.0" in labels

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/querybatch":
            qs = json.loads(req.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "GHSA-35jh"}]} if q["package"]["name"] == "lodash" else
                {"vulns": [{"id": "DEBIAN-X"}]} if q["package"]["name"] == "openssl" else {} for q in qs]})
        if req.url.path.endswith("GHSA-35jh"):
            return httpx.Response(200, json={"id": "GHSA-35jh", "aliases": ["CVE-2021-23337"], "summary": "lodash"})
        return httpx.Response(200, json={"id": "DEBIAN-X", "summary": "** REJECT ** do not use"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        cands = discover(Settings(), inv, client=c)
    assert set(cands) == {"CVE-2021-23337", "DEBIAN-X"}
    assert package_hint(cands["CVE-2021-23337"]) == "lodash"
    assert [v["vuln_id"] for v in to_vulnerabilities(cands)] == ["CVE-2021-23337"]  # rejected one dropped


def _fake_http(behaviour):
    """One-shot local HTTP server on an ephemeral port; behaviour(request_bytes) -> response bytes."""
    import socket as _s
    import threading

    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        for _ in range(4):
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = b""
            c.settimeout(2)
            try:
                while b"\r\n\r\n" not in data:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                c.sendall(behaviour(data))
            finally:
                c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def _local_target():
    from vulnlens.config import LiveProbeSettings
    from vulnlens.models import RuntimeSpec
    from vulnlens.tools.runtime import LiveTarget

    lt = LiveTarget(RuntimeSpec(engine="local"), LiveProbeSettings())
    lt.addresses = lambda: ["127.0.0.1"]
    return lt


def test_h2c_upgrade_probe_detects_101_and_refusal():
    lt = _local_target()
    srv, port = _fake_http(lambda req: b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"
                           if b"Upgrade: h2c" in req and b"HTTP2-Settings:" in req else b"HTTP/1.1 400 x\r\n\r\n")
    assert "ACCEPTED" in lt.h2c_upgrade_probe(port)
    srv.close()
    srv, port = _fake_http(lambda req: b"HTTP/1.1 200 OK\r\nServer: t\r\nContent-Length: 0\r\n\r\n")
    assert "NOT accepted" in lt.h2c_upgrade_probe(port)
    assert "REFUSED" in lt.h2c_upgrade_probe(port, "/x\r\nEvil: 1")
    srv.close()


def test_header_limit_probe_brackets_limit_with_padding_header():
    lt = _local_target()
    seen = []

    def limit(req):
        line = next(l for l in req.split(b"\r\n") if l.startswith(b"X-Vulnlens-Limit-Probe:"))
        seen.append((len(line), b"\r\nHost: 127.0.0.1:" in req))
        return b"HTTP/1.1 400 Bad Request\r\n\r\nSize of a request header field exceeds server limit." \
            if len(line) > 8190 else b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    srv, port = _fake_http(limit)
    assert "ACCEPTED" in lt.header_limit_probe(port, 8190)
    assert "REJECTED" in lt.header_limit_probe(port, 8191)
    assert seen == [(8190, True), (8191, True)]  # exact field length; Host stays the normal short value
    assert "REFUSED" in lt.header_limit_probe(port, 10)
    srv.close()
    tools = {t.name for t in __import__("vulnlens.tools.runtime", fromlist=["x"]).runtime_tools(lt)}
    assert {"h2c_upgrade_probe", "header_limit_probe"} <= tools


def test_concurrent_verifications_keep_their_own_probes():
    import asyncio

    lt = _local_target()
    lt.tcp_connect = lt.tcp_connect  # real method; port 1 is closed, which is fine

    async def one(port):
        with lt.recording() as sink:
            for _ in range(3):
                await asyncio.to_thread(lt.tcp_connect, port)
                await asyncio.sleep(0)
        return sink

    async def both():
        return await asyncio.gather(one(1), one(2))

    a, b = asyncio.run(both())
    assert [r.args["port"] for r in a] == [1, 1, 1] and [r.args["port"] for r in b] == [2, 2, 2]
    assert len(lt.probes) == 6
