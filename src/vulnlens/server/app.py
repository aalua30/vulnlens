"""FastAPI service exposing the workflow with NAT-compatible endpoints.

POST /generate                              synchronous run -> PipelineOutput
POST /v1/workflow/async  (alias /generate/async)          -> {job_id, status}
GET  /v1/workflow/async/job/{job_id}  (alias /generate/async/job/{job_id})
POST /v1/workflow/async/job/{job_id}/resume   re-run an interrupted/failed job (agent cache makes it cheap)
GET  /health
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..config import Settings, load_settings
from ..graph import run_pipeline
from ..models import PipelineInput, PipelineOutput
from .jobs import JobStore

log = logging.getLogger(__name__)


class AsyncSubmit(BaseModel):
    job_id: str
    status: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings(os.environ.get("VULNLENS_CONFIG"))
    store = JobStore(Path(settings.cache_dir) / "jobs.sqlite")
    sem = asyncio.Semaphore(int(os.environ.get("VULNLENS_MAX_JOBS", "2")))
    tasks: set[asyncio.Task] = set()
    app = FastAPI(title="VulnLens", version="0.1.0",
                  description="Vulnerability exploitability & VEX analysis for containers and hosts")

    async def _execute(job_id: str, inp: PipelineInput) -> None:
        async with sem:
            store.update(job_id, "running")
            try:
                out = await run_pipeline(inp, settings, run_id=job_id[:12])
                store.update(job_id, "success", output=out.model_dump(mode="json"))
            except Exception as e:
                log.exception("job %s failed", job_id)
                store.update(job_id, "failure", error=f"{type(e).__name__}: {e}")

    def _spawn(job_id: str, inp: PipelineInput) -> None:
        t = asyncio.create_task(_execute(job_id, inp))
        tasks.add(t)
        t.add_done_callback(tasks.discard)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/generate", response_model=PipelineOutput)
    async def generate(inp: PipelineInput) -> PipelineOutput:
        async with sem:
            return await run_pipeline(inp, settings)

    async def submit(inp: PipelineInput) -> AsyncSubmit:
        job_id = store.create(inp.model_dump(mode="json"))
        _spawn(job_id, inp)
        return AsyncSubmit(job_id=job_id, status="submitted")

    async def status(job_id: str) -> dict:
        job = store.get(job_id)
        if not job:
            raise HTTPException(404, f"job {job_id} not found")
        return job

    async def resume(job_id: str) -> AsyncSubmit:
        job = store.get(job_id)
        if not job:
            raise HTTPException(404, f"job {job_id} not found")
        if job["status"] in ("running", "submitted"):
            raise HTTPException(409, "job still running")
        inp = PipelineInput.model_validate(store.input(job_id))
        store.update(job_id, "submitted")
        _spawn(job_id, inp)
        return AsyncSubmit(job_id=job_id, status="submitted")

    for prefix in ("/v1/workflow/async", "/generate/async"):
        app.add_api_route(prefix, submit, methods=["POST"], response_model=AsyncSubmit)
        app.add_api_route(prefix + "/job/{job_id}", status, methods=["GET"])
        app.add_api_route(prefix + "/job/{job_id}/resume", resume, methods=["POST"], response_model=AsyncSubmit)
    return app
