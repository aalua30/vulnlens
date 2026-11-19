"""Deterministic software inventory of a rootfs (the ground truth the agents verify against).

Built once per target digest and cached as JSON next to the agent cache.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .binaries import go_binaries, shared_libraries
from .fs import Jail
from .lang_pkgs import erlang_packages, java_packages, normalize_pypi, npm_packages, python_packages
from .packages import OsPackage, os_packages, os_release

log = logging.getLogger(__name__)
INVENTORY_VERSION = 4

# upstream project name -> package / library name hints
NAME_ALIASES = {
    "openssl": ["openssl", "libssl", "libssl3", "libssl1.1", "libcrypto", "openssl-libs", "libssl3t64"],
    "glibc": ["glibc", "libc6", "libc", "musl"],
    "zlib": ["zlib", "zlib1g", "libz"],
    "curl": ["curl", "libcurl", "libcurl4", "libcurl4t64"],
    "libxml2": ["libxml2"],
    "sqlite": ["sqlite", "sqlite3", "libsqlite3", "libsqlite3-0", "sqlite-libs"],
    "openssh": ["openssh", "openssh-server", "openssh-client", "openssh-clients"],
    "xz": ["xz", "xz-utils", "liblzma", "liblzma5", "xz-libs"],
    "linux_kernel": ["linux", "linux-image", "kernel"],
    "http_server": ["apache2", "httpd"],
    "erlang/otp": ["erlang/otp", "otp", "erlang", "erlang-base"],
    "erlang": ["erlang/otp", "otp", "erlang", "erlang-base"],
    "node.js": ["nodejs", "node"],
    "python": ["python3", "python", "libpython3"],
    "expat": ["expat", "libexpat", "libexpat1"],
    "pcre2": ["pcre2", "libpcre2-8-0"],
    "systemd": ["systemd", "libsystemd0", "libudev1"],
}


@dataclass
class Inventory:
    distro: dict[str, str] = field(default_factory=dict)
    os_packages: list[dict] = field(default_factory=list)
    python: list[dict] = field(default_factory=list)
    npm: list[dict] = field(default_factory=list)
    java: list[dict] = field(default_factory=list)
    go_binaries: list[dict] = field(default_factory=list)
    shared_libs: list[dict] = field(default_factory=list)
    erlang: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"version": INVENTORY_VERSION, **self.__dict__}

    @classmethod
    def from_dict(cls, d: dict) -> "Inventory":
        d = dict(d)
        d.pop("version", None)
        return cls(**d)

    def counts(self) -> dict[str, int]:
        return {"os_packages": len(self.os_packages), "python": len(self.python), "npm": len(self.npm),
                "java": len(self.java), "go_binaries": len(self.go_binaries),
                "go_modules": sum(len(g.get("deps", [])) for g in self.go_binaries),
                "shared_libs": len(self.shared_libs), "erlang": len(self.erlang)}

    def summary(self, max_items: int = 60) -> dict:
        """Compact view for LLM prompts."""
        return {
            "distro": {k: self.distro.get(k) for k in ("ID", "VERSION_ID", "PRETTY_NAME") if self.distro.get(k)},
            "counts": self.counts(),
            "os_packages_sample": [f"{p['name']}={p['version']}" for p in self.os_packages[:max_items]],
            "python": [f"{p['name']}=={p['version']}" for p in self.python[:max_items]],
            "npm": [f"{p['name']}@{p['version']}" for p in self.npm[:max_items]],
            "java": [f"{p['name']}:{p['version']}" for p in self.java[:max_items]],
            "erlang": [f"{p['name']}-{p['version']}" for p in self.erlang[:max_items]],
            "go_binaries": [{"binary": g["binary"], "go": g.get("go_version"),
                             "main": (g.get("main") or {}).get("path"), "deps": len(g.get("deps", []))}
                            for g in self.go_binaries[:30]],
        }

    # -- lookup -------------------------------------------------------------
    def find(self, name: str, ecosystem: str = "generic") -> list[dict]:
        """Find installed artifacts matching a package name. Returns
        [{name, version, ecosystem, location, kind, (source, source_version)}]."""
        n = name.lower()
        hits: list[dict] = []
        eco = ecosystem
        if eco in ("deb", "rpm", "apk", "generic"):
            names = {n, *NAME_ALIASES.get(n, [])}
            for p in self.os_packages:
                if p["ecosystem"] != eco and eco != "generic":
                    continue
                if p["name"].lower() in names or (p.get("source") or "").lower() in names:
                    hits.append({"name": p["name"], "version": p["version"], "ecosystem": p["ecosystem"],
                                 "location": p.get("db", ""), "kind": "os",
                                 "source": p.get("source", ""), "source_version": p.get("source_version", ""),
                                 "third_party": p.get("third_party", False), "vendor": p.get("vendor", "")})
        if eco == "generic":
            names = {n, *NAME_ALIASES.get(n, [])}
            for lib in self.shared_libs:
                base = lib["name"].lower()
                if base in names or base.removeprefix("lib") in names:
                    emb = lib.get("embedded") or {}
                    ver = emb.get(n) or next(iter(emb.values()), "") or lib.get("version", "")
                    hits.append({"name": lib["name"], "version": ver, "ecosystem": "generic", "location": lib["path"],
                                 "kind": "shared_lib", "version_source": "banner" if emb else "soname"})
                else:
                    for lib_name, ver in (lib.get("embedded") or {}).items():
                        if lib_name == n:
                            hits.append({"name": lib_name, "version": ver, "ecosystem": "generic",
                                         "location": lib["path"], "kind": "embedded_banner"})
        if eco in ("pypi", "generic"):
            nn = normalize_pypi(name)
            hits += [{**p, "ecosystem": "pypi", "kind": "python"} for p in self.python if normalize_pypi(p["name"]) == nn]
        if eco in ("npm", "generic"):
            hits += [{**p, "ecosystem": "npm", "kind": "npm"} for p in self.npm if p["name"].lower() == n]
        if eco in ("maven", "generic"):
            art = n.split(":")[-1]
            for p in self.java:
                pn = p["name"].lower()
                if pn == n or pn.split(":")[-1] == art:
                    hits.append({**p, "ecosystem": "maven", "kind": "java"})
        if eco in ("hex", "generic"):
            names = {n, *NAME_ALIASES.get(n, [])}
            for p in self.erlang:
                pn = p["name"].lower()
                if pn in names or (n.startswith("erlang-") and pn == n.removeprefix("erlang-")):
                    hits.append({**p, "ecosystem": "hex", "kind": "otp_release" if pn == "erlang/otp" else "erlang"})
        if eco in ("go", "generic"):
            for g in self.go_binaries:
                if n in ("go", "golang", "stdlib", "go stdlib") and g.get("go_version"):
                    hits.append({"name": "stdlib", "version": g["go_version"].removeprefix("go"), "ecosystem": "go",
                                 "location": g["binary"], "kind": "go_stdlib"})
                for dep in ([g["main"]] if g.get("main") else []) + g.get("deps", []):
                    dp = dep["path"].lower()
                    if dp == n or (eco == "go" and n.endswith(dp)) or (eco == "go" and dp.endswith("/" + n)):
                        v = (dep.get("replaced_by") or dep)["version"]
                        hits.append({"name": dep["path"], "version": v, "ecosystem": "go",
                                     "location": g["binary"], "kind": "go_module"})
        # dedupe
        seen, uniq = set(), []
        for h in hits:
            k = (h["name"], h["version"], h.get("location"))
            if k not in seen:
                seen.add(k)
                uniq.append(h)
        return uniq


def build_inventory(jail: Jail, include_java: bool = True) -> Inventory:
    inv = Inventory()
    inv.distro = os_release(jail)
    inv.os_packages = [p.to_dict() for p in os_packages(jail)]
    inv.python = [p.to_dict() for p in python_packages(jail)]
    inv.npm = [p.to_dict() for p in npm_packages(jail)]
    if include_java:
        inv.java = [p.to_dict() for p in java_packages(jail)]
    inv.go_binaries = go_binaries(jail)
    inv.erlang = [p.to_dict() for p in erlang_packages(jail)]
    inv.shared_libs = [lib.to_dict() for lib in shared_libraries(jail)]
    return inv


def load_or_build_inventory(jail: Jail, digest: str, cache_dir: str | Path, refresh: bool = False) -> Inventory:
    safe = re.sub(r"[^\w.\-]", "_", digest)[:150]
    p = Path(cache_dir) / "inventory" / f"{safe}.json"
    if p.exists() and not refresh:
        d = json.loads(p.read_text())
        if d.get("version") == INVENTORY_VERSION:
            return Inventory.from_dict(d)
    log.info("building inventory for %s", digest)
    inv = build_inventory(jail)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(inv.to_dict()))
    return inv


def os_package_obj(d: dict) -> OsPackage:
    return OsPackage(**{k: d.get(k, "") for k in ("name", "version", "ecosystem", "arch", "source", "source_version", "db")})
