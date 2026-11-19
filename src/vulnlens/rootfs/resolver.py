"""Resolve a Target into an on-disk root filesystem (cached by digest)."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import tarfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..config import Settings
from ..models import Target
from .crane import ImageBackendError, _run, pick_backend

log = logging.getLogger(__name__)

# Files whose content identifies the installed software set of an already-extracted rootfs.
_FINGERPRINT_FILES = (
    "etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed",
    "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite",
)


@dataclass
class ResolvedRootfs:
    path: str
    digest: str
    image_ref: str | None
    image_config: dict = field(default_factory=dict)
    manifest_path: str | None = None  # setuid/setgid/special-file records captured during extraction
    source: str = "provided"           # provided | cache | crane | podman | docker

    def to_dict(self) -> dict:
        return asdict(self)


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:120]


@contextmanager
def _lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def fingerprint_path(root: Path) -> str:
    h = hashlib.sha256(str(root.resolve()).encode())
    for rel in _FINGERPRINT_FILES:
        p = root / rel
        try:
            st = p.stat()
            h.update(f"{rel}:{st.st_size}:{int(st.st_mtime)}".encode())
        except OSError:
            continue
    return "path-sha256:" + h.hexdigest()


def safe_extract(tar_path: Path, dest: Path) -> dict:
    """Extract a flattened image tar defensively.

    * reject absolute / '..' member names and hardlinks escaping dest
    * reject members whose parent dir resolves (through already-extracted symlinks) outside dest
    * skip device nodes / fifos
    * strip setuid/setgid/sticky bits on disk but record them in the returned manifest
    * keep symlinks verbatim (tools resolve them inside the jail, never on the host)
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"setuid": [], "setgid": [], "world_writable": [], "skipped": [], "capabilities": []}
    dest_s = str(dest) + os.sep

    def inside(p: str) -> bool:
        rp = os.path.realpath(p)
        return rp == str(dest) or rp.startswith(dest_s)

    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf:
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            name = name.lstrip("/").rstrip("/")
            if not name or ".." in Path(name).parts:
                manifest["skipped"].append(m.name)
                continue
            if m.ischr() or m.isblk() or m.isfifo():
                continue
            target = dest / name
            if not inside(str(target.parent)):
                manifest["skipped"].append(m.name)
                continue
            if m.islnk():
                link = m.linkname.lstrip("/")
                if ".." in Path(link).parts or not inside(str(dest / link)):
                    manifest["skipped"].append(m.name)
                    continue
                m.linkname = link
            if m.pax_headers and any(k.endswith("security.capability") for k in m.pax_headers):
                manifest["capabilities"].append("/" + name)
            mode = m.mode
            if m.isfile():
                if mode & stat.S_ISUID:
                    manifest["setuid"].append("/" + name)
                if mode & stat.S_ISGID:
                    manifest["setgid"].append("/" + name)
                if mode & stat.S_IWOTH:
                    manifest["world_writable"].append("/" + name)
            m.name = name
            m.mode = (mode & 0o777 & ~0o022) | (0o700 if m.isdir() else 0o600)
            m.uid = m.gid = os.getuid()
            m.uname = m.gname = ""
            try:
                if target.is_symlink() or (target.exists() and not target.is_dir()):
                    target.unlink()
                tf.extract(m, dest, set_attrs=True, filter="fully_trusted")
            except (OSError, tarfile.TarError) as e:
                manifest["skipped"].append(f"{m.name}: {e}")
    return manifest


def resolve_target(target: Target, settings: Settings) -> ResolvedRootfs:
    cache_root = Path(settings.cache_dir) / "rootfs"
    image_config: dict = {}
    if target.image_config_path:
        image_config = json.loads(Path(target.image_config_path).read_text())

    if target.filesystem_path:
        root = Path(target.filesystem_path).expanduser()
        if not root.is_dir():
            raise FileNotFoundError(f"filesystem_path {root} is not a directory")
        digest = target.image_digest or fingerprint_path(root)
        manifest = root.parent / f".{root.name}.vulnlens-manifest.json"
        return ResolvedRootfs(
            path=str(root.resolve()), digest=digest, image_ref=target.image_ref, image_config=image_config,
            manifest_path=str(manifest) if manifest.exists() else None, source="provided",
        )

    ref = target.image_ref
    assert ref, "image_name required when filesystem_path is absent"
    backend = pick_backend(settings.crane_bin, settings.container_cli_fallbacks)
    digest = target.image_digest or backend.digest(ref)
    slot = cache_root / _slug(digest)
    rootfs_dir = slot / "rootfs"
    done_marker = slot / ".complete"
    manifest_path = slot / "manifest.json"
    config_path = slot / "image_config.json"

    with _lock(cache_root / f"{_slug(digest)}.lock"):
        if done_marker.exists():
            source = "cache"
        else:
            log.info("extracting %s (%s) via %s", ref, digest, backend.name)
            if slot.exists():
                shutil.rmtree(slot, ignore_errors=True)
            slot.mkdir(parents=True)
            tar_path = slot / "image.tar"
            backend.export(ref, tar_path)
            manifest = safe_extract(tar_path, rootfs_dir)
            tar_path.unlink(missing_ok=True)
            manifest_path.write_text(json.dumps(manifest, indent=1))
            config_path.write_text(json.dumps(backend.config(ref), indent=1))
            (slot / "ref.txt").write_text(ref)
            done_marker.touch()
            source = backend.name
    if not image_config and config_path.exists():
        image_config = json.loads(config_path.read_text())
    return ResolvedRootfs(
        path=str(rootfs_dir.resolve()), digest=digest, image_ref=ref, image_config=image_config,
        manifest_path=str(manifest_path), source=source,
    )


_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def export_running_container(name: str, settings: Settings, engine: str = "docker", refresh: bool = False) -> dict:
    """Export the *current* filesystem of a container (image + runtime changes) with `<engine> export` and extract
    it safely under <cache_dir>/rootfs/containers/<id>. Reused for the same container id unless refresh=True.
    Returns {path, container, container_id, image, state, source}; the extraction manifest (setuid, caps) is written
    next to the rootfs where resolve_target picks it up for filesystem_path targets."""
    if not _CONTAINER_NAME.match(name or ""):
        raise ValueError("invalid container name")
    if engine not in ("docker", "podman"):
        raise ValueError("engine must be docker or podman")
    binary = shutil.which(engine)
    if not binary:
        raise ImageBackendError(f"{engine} not found")
    info = json.loads(_run([binary, "inspect", "--type", "container", name]).stdout)[0]
    cid = (info.get("Id") or "")[:64]
    image = (info.get("Config") or {}).get("Image")
    state = (info.get("State") or {}).get("Status")
    base = Path(settings.cache_dir) / "rootfs" / "containers"
    slot = base / _slug(cid[:24] or name)
    rootfs_dir = slot / "rootfs"
    with _lock(base / f"{_slug(cid[:24] or name)}.lock"):
        source = "cache"
        if refresh or not (slot / ".complete").exists():
            log.info("exporting running container %s (%s) via %s", name, cid[:12], engine)
            shutil.rmtree(slot, ignore_errors=True)
            slot.mkdir(parents=True)
            tar_path = slot / "container.tar"
            _run([binary, "export", "-o", str(tar_path), name], timeout=3600)
            manifest = safe_extract(tar_path, rootfs_dir)
            tar_path.unlink(missing_ok=True)
            (slot / ".rootfs.vulnlens-manifest.json").write_text(json.dumps(manifest, indent=1))
            (slot / "inspect.json").write_text(json.dumps({"image": image, "state": state, "id": cid}, indent=1))
            (slot / ".complete").touch()
            source = engine
    return {"path": str(rootfs_dir.resolve()), "container": name, "container_id": cid[:12], "image": image,
            "state": state, "source": source}
