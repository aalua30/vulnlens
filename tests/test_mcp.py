"""MCP server: tool registration, run lookup confinement, feedback, live-verification guard."""

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from vulnlens.config import Settings
from vulnlens.mcp_server import TOOL_NAMES, VulnlensTools, build_server


def _tools(tmp_path):
    out = tmp_path / "out"
    run = out / "20260101T000000Z-abc123_host-x"
    (run / "CVE-1").mkdir(parents=True)
    (run / "summary.json").write_text(json.dumps({"run_id": "20260101T000000Z-abc123", "target": "host-x",
                                                   "results": [{"cve_id": "CVE-1", "status": "affected",
                                                                "justification": "vulnerable"}]}))
    (run / "CVE-1" / "vex.md").write_text("# VEX")
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "flat.json").write_text(json.dumps({"image_name": "x", "vulnerabilities": ["CVE-2"]}))
    (ex / "demo.json").write_text(json.dumps({"target": {"filesystem_path": "/nonexistent"},
                                              "vulnerabilities": [{"vuln_id": "CVE-1"}]}))
    s = Settings(cache_dir=str(tmp_path / "cache"), output_dir=str(out), skills={"dir": str(tmp_path / "sk")})
    return VulnlensTools(s, examples_dir=ex, allow_live=False), run


def test_server_lists_tools(tmp_path):
    vt, _ = _tools(tmp_path)
    srv = build_server(tools=vt)
    names = [t.name for t in asyncio.run(srv.list_tools())]
    assert names == list(TOOL_NAMES) and "approve" not in " ".join(names)


def test_tools(tmp_path):
    vt, run = _tools(tmp_path)

    async def go():
        assert (await vt.list_runs())[0]["run"] == run.name
        assert (await vt.get_summary("20260101T000000Z-abc123"))["target"] == "host-x"
        assert await vt.get_report(run.name, "vex", "CVE-1") == "# VEX"
        with pytest.raises(ValueError):
            await vt.get_summary("../../etc")
        with pytest.raises(ValueError):
            await vt.get_report(run.name, "vex", "../x")
        assert "recorded" in await vt.record_feedback(run.name, "CVE-1", "wrong", "not_affected")
        assert json.loads((run / "feedback.json").read_text())[0]["status"] == "not_affected"
        exs = {e["example"]: e for e in await vt.list_examples()}
        assert exs["demo"]["vulnerabilities"] == ["CVE-1"] and exs["flat"]["vulnerabilities"] == ["CVE-2"]
        with pytest.raises(PermissionError):
            await vt.start_scan(example="demo", live_verification=True)
        with pytest.raises(ValueError):
            await vt.start_scan()
        assert await vt.skills_list() == []

    asyncio.run(go())


def test_guess_cpe():
    from vulnlens.mcp_server import guess_cpe

    assert guess_cpe("redis", "8.10.1") == "cpe:2.3:a:redis:redis:8.10.1:*:*:*:*:*:*:*"
    assert guess_cpe("library/nginx", "1.25.3-alpine").startswith("cpe:2.3:a:nginx:nginx:1.25.3:")
    assert guess_cpe("opencti/platform", "latest") is None and guess_cpe(None, "1.0") is None


def test_discover_ranks_and_builds_pipeline_input(tmp_path, rootfs, monkeypatch):
    import vulnlens.discover as disc

    vt, _ = _tools(tmp_path)
    seen = {}

    def fake(settings, inv, cpes):
        seen["cpes"] = cpes
        return {"CVE-2005-1": {"pkgs": ["debian:tar=1.3"], "src": ["DEBIAN-1"], "prio": [], "summary": "old"},
                "CVE-2026-9": {"pkgs": ["debian:openssl=3.0"], "src": ["DEBIAN-9"], "prio": [], "summary": "new"},
                "CVE-2025-5": {"pkgs": ["nvd:myapp"], "src": ["nvd"], "prio": [], "summary": "app", "cvss": 7.5},
                "CVE-2024-0": {"pkgs": ["debian:x=1"], "src": ["X"], "prio": [], "summary": "gone", "withdrawn": True}}

    monkeypatch.setattr(disc, "discover", fake)

    async def go():
        r = await vt.discover(filesystem_path=str(rootfs), cpes=["cpe:2.3:a:myapp:myapp:1.0:*:*:*:*:*:*:*"])
        assert [c["vuln_id"] for c in r["candidates"]] == ["CVE-2025-5", "CVE-2026-9", "CVE-2005-1"]
        assert r["candidates"][0]["main_app"] and r["candidates_total"] == 3
        vulns = r["pipeline_input"]["vulnerabilities"]
        assert vulns[0] == {"vuln_id": "CVE-2025-5", "package_hint": "myapp"}
        assert r["pipeline_input"]["target"]["filesystem_path"] == str(rootfs)
        r2 = await vt.discover(filesystem_path=str(rootfs), max_results=1, min_cvss=7)
        assert [c["vuln_id"] for c in r2["candidates"]] == ["CVE-2025-5"]
        with pytest.raises(ValueError):
            await vt.discover()
        with pytest.raises(ValueError):
            await vt.discover(container="x; rm -rf /")
        with pytest.raises(ValueError):
            await vt.discover(container="a", image="b:1")

    asyncio.run(go())
