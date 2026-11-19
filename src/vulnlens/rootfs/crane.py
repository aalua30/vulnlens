"""Image acquisition backends: crane (preferred), with podman/docker fallbacks.

All backends produce (digest, flattened rootfs tar, image config JSON).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


class ImageBackendError(RuntimeError):
    pass


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    log.debug("exec %s", " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        raise ImageBackendError(f"{' '.join(cmd[:3])} failed ({p.returncode}): {p.stderr.strip()[:2000]}")
    return p


class CraneBackend:
    name = "crane"

    def __init__(self, binary: str = "crane"):
        self.bin = shutil.which(binary)

    def available(self) -> bool:
        return self.bin is not None

    def digest(self, ref: str) -> str:
        return _run([self.bin, "digest", ref]).stdout.strip()

    def config(self, ref: str) -> dict:
        return json.loads(_run([self.bin, "config", ref]).stdout)

    def export(self, ref: str, tar_path: Path) -> None:
        # `crane export` flattens all layers (applying whiteouts) into a single tar stream.
        with open(tar_path, "wb") as f:
            p = subprocess.run([self.bin, "export", ref, "-"], stdout=f, stderr=subprocess.PIPE)
        if p.returncode != 0:
            raise ImageBackendError(f"crane export failed: {p.stderr.decode(errors='replace')[:2000]}")


class ContainerCliBackend:
    """podman / docker: pull, create (not start) a container, export its flattened filesystem."""

    def __init__(self, binary: str):
        self.name = binary
        self.bin = shutil.which(binary)

    def available(self) -> bool:
        return self.bin is not None

    def _ensure_pulled(self, ref: str) -> None:
        if subprocess.run([self.bin, "image", "inspect", ref], capture_output=True).returncode != 0:
            _run([self.bin, "pull", ref], timeout=3600)

    def digest(self, ref: str) -> str:
        self._ensure_pulled(ref)
        info = json.loads(_run([self.bin, "image", "inspect", ref]).stdout)[0]
        repo_digests = info.get("RepoDigests") or []
        if repo_digests:
            return repo_digests[0].split("@", 1)[1]
        return info.get("Id") or info.get("Digest") or ""

    def config(self, ref: str) -> dict:
        self._ensure_pulled(ref)
        info = json.loads(_run([self.bin, "image", "inspect", ref]).stdout)[0]
        cfg = info.get("Config") or {}
        return {"config": cfg, "architecture": info.get("Architecture"), "os": info.get("Os")}

    def export(self, ref: str, tar_path: Path) -> None:
        self._ensure_pulled(ref)
        cid = _run([self.bin, "create", ref, "/bin/true"]).stdout.strip().splitlines()[-1]
        try:
            _run([self.bin, "export", "-o", str(tar_path), cid], timeout=3600)
        finally:
            subprocess.run([self.bin, "rm", "-f", cid], capture_output=True)


def pick_backend(crane_bin: str, fallbacks: list[str]):
    candidates = [CraneBackend(crane_bin)] + [ContainerCliBackend(b) for b in fallbacks]
    for b in candidates:
        if b.available():
            return b
    raise ImageBackendError(
        "No image backend found. Install crane (https://github.com/google/go-containerregistry) "
        "or podman/docker, or pass filesystem_path."
    )
