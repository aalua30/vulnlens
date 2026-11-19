import asyncio
import time

from fastapi.testclient import TestClient

from vulnlens.config import Settings
from vulnlens.llm import LimitedModel
from vulnlens.models import ContainerReport, PipelineOutput
from vulnlens.server import app as app_mod

DOC = {"vulnerabilities": ["CVE-2024-6387"], "target": {"image_name": "nginx", "image_tag": "1.25"}}


def _fake_output(inp, settings, run_id=None):
    return PipelineOutput(run_id=run_id or "r1", target=inp.target.display_name, digest="sha256:x",
                          container_report=ContainerReport(target=inp.target.display_name), results=[],
                          output_dir="/tmp/x", summary_path="/tmp/x/summary.json", openvex_path="/tmp/x/openvex.json")


def test_endpoints(tmp_path, monkeypatch):
    async def fake_run(inp, settings, run_id=None):
        return _fake_output(inp, settings, run_id)

    monkeypatch.setattr(app_mod, "run_pipeline", fake_run)
    client = TestClient(app_mod.create_app(Settings(cache_dir=str(tmp_path))))
    assert client.get("/health").json() == {"status": "ok"}
    r = client.post("/generate", json=DOC)
    assert r.status_code == 200 and r.json()["target"] == "nginx:1.25"
    assert client.post("/generate", json={"vulnerabilities": []}).status_code == 422
    for prefix in ("/v1/workflow/async", "/generate/async"):
        job = client.post(prefix, json=DOC).json()
        assert job["status"] == "submitted"
        for _ in range(50):
            st = client.get(f"{prefix}/job/{job['job_id']}").json()
            if st["status"] == "success":
                break
            time.sleep(0.05)
        assert st["status"] == "success" and st["output"]["digest"] == "sha256:x"
    assert client.get("/v1/workflow/async/job/nope").status_code == 404


def test_limited_model_serializes():
    active = {"now": 0, "max": 0}

    class M:
        async def ainvoke(self, *a, **k):
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            await asyncio.sleep(0.01)
            active["now"] -= 1
            return "ok"

        def bind_tools(self, tools, **kw):
            return self

    async def main():
        lm = LimitedModel(M(), asyncio.Semaphore(1))
        await asyncio.gather(*[lm.bind_tools([]).ainvoke("x") for _ in range(5)])

    asyncio.run(main())
    assert active["max"] == 1
