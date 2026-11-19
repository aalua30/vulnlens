"""End-to-end graph run with a scripted fake chat model and no network."""

import json

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from vulnlens import graph as graph_mod
from vulnlens.agents import cve_researcher
from vulnlens.config import LLMSpec, Settings
from vulnlens.llm import LLMHandle
from vulnlens.models import PipelineInput

CALLS: list[str] = []


class FakeChat(BaseChatModel):
    """Calls one tool on the first turn of an agent loop, then answers with JSON for the requested schema."""

    @property
    def _llm_type(self) -> str:
        return "fake"

    def bind_tools(self, tools, **kw):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kw):
        last = messages[-1].content if isinstance(messages[-1].content, str) else json.dumps(messages[-1].content)
        system = messages[0].content if isinstance(messages[0].content, str) else messages[0].content[0]["text"]
        if "JSON Schema" not in last:
            if messages[-1].type == "human" and "exploitability analyst" in system:
                CALLS.append("tool")
                msg = AIMessage(content="", tool_calls=[{"name": "grep_search", "id": "t1",
                                                         "args": {"pattern": "_\\.template", "path": "/app"}}])
                return ChatResult(generations=[ChatGeneration(message=msg)])
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done investigating"))])
        title = json.loads(last.split("JSON Schema:\n", 1)[1])["title"]
        CALLS.append(title)
        payload = {
            "ResearchFindings": {"summary": "Template injection in lodash.template", "vulnerable_functions": ["template"],
                                 "attack_vector": "network", "remediation": "upgrade to 4.17.21"},
            "FsAnalysis": {"container_type": "web-app", "summary": "Node app", "entrypoints": [
                {"kind": "cmd", "command": "node /app/server.js"}]},
            "DeepAnalysis": {"verdict": "EXPLOITABLE", "summary": "server.js passes user input to _.template",
                             "reachability_chain": ["node /app/server.js", "_.template(userInput)"],
                             "evidence": [{"kind": "file", "path": "/app/server.js", "detail": "line 2"}],
                             "confidence": 0.85, "risk_level": "high"},
            "JustificationChoice": {"justification": "vulnerable", "reasoning": "Reachable via server.js."},
        }[title]
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=json.dumps(payload)))])


def _intel(settings, vid):
    if vid == "CVE-2021-23337":
        return {"errors": [], "osv": [{"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "affected": [
            {"package": {"name": "lodash", "ecosystem": "npm"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}]}
    return {"errors": [], "osv": [{"id": vid, "affected": [
        {"package": {"name": "linux", "ecosystem": "Debian:12"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1.90-1"}]}]}]}]}


def test_pipeline_end_to_end(rootfs, tmp_path, monkeypatch):
    CALLS.clear()
    monkeypatch.setattr(cve_researcher, "gather_intel", _intel)
    monkeypatch.setattr(cve_researcher, "web_tools", lambda s: [])
    monkeypatch.setattr(graph_mod, "get_llm", lambda s, a, p=None, **kw: LLMHandle(
        "fake", LLMSpec(provider="ollama", model="fake"), FakeChat()))
    settings = Settings(cache_dir=str(tmp_path / "cache"), output_dir=str(tmp_path / "out"))
    inp = PipelineInput.model_validate({
        "vulnerabilities": ["CVE-2021-23337", "CVE-2024-26925"],
        "target": {"filesystem_path": str(rootfs), "image_name": "example/app", "private": True},
        "output": {"dir": str(tmp_path / "out")},
    })
    import asyncio

    out = asyncio.run(graph_mod.run_pipeline(inp, settings))
    by = {r.vex.cve_id: r.vex for r in out.results}
    lod = by["CVE-2021-23337"]
    assert lod.status.value == "affected" and lod.justification.value == "vulnerable"
    assert lod.container_type == "web-app" and lod.exploitability_verdict.value == "EXPLOITABLE"
    kern = by["CVE-2024-26925"]  # kernel CVE: package absent from a container → early exit, no deep LLM call
    assert kern.status.value == "not_affected" and kern.justification.value == "code_not_present"
    assert CALLS.count("DeepAnalysis") == 1 and "tool" in CALLS
    for key in ("cve_research", "exploitability", "vex_report", "vex_json", "container_report"):
        assert key in lod.report_paths
    summary = json.loads(open(out.summary_path).read())
    assert len(summary["results"]) == 2
    openvex = json.loads(open(out.openvex_path).read())
    assert {s["status"] for s in openvex["statements"]} == {"affected", "not_affected"}

    # second run: everything comes from the agent cache, no LLM calls
    CALLS.clear()
    out2 = asyncio.run(graph_mod.run_pipeline(inp, settings))
    assert CALLS == []
    assert {r.vex.status for r in out2.results} == {r.vex.status for r in out.results}
