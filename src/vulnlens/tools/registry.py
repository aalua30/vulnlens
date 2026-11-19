"""Expose the tool functions as LangChain tools bound to one target rootfs (and to settings for web tools)."""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from ..config import Settings
from . import binaries, fs, lang_pkgs, web
from . import security_controls as sc
from .backports import backport_check
from .inventory import Inventory, os_package_obj


def _j(obj: Any) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)


@dataclass
class ToolContext:
    settings: Settings
    jail: fs.Jail
    inventory: Inventory
    image_config: dict = field(default_factory=dict)
    manifest_path: str | None = None
    kind: str = "container"
    _special: dict | None = field(default=None, repr=False)


def special_bits(ctx: ToolContext) -> dict[str, set[str]]:
    """Original setuid/setgid/file-capability bits recorded at extraction. Safe extraction strips them on disk, so
    stat-based tools must overlay these or they report e.g. a setuid-root /usr/bin/su as -rwxr-xr-x."""
    if ctx._special is None:
        ctx._special = {}
        if ctx.manifest_path:
            try:
                m = json.loads(Path(ctx.manifest_path).read_text())
            except (OSError, ValueError):
                m = {}
            for key in ("setuid", "setgid", "capabilities"):
                for path in m.get(key) or []:
                    ctx._special.setdefault(path, set()).add(key)
    return ctx._special


def overlay_mode(info: dict, path: str, special: dict[str, set[str]]) -> dict:
    bits = special.get(path) if path else None
    if not bits or "mode" not in info:
        return info
    mode = list(info["mode"])
    if "setuid" in bits and len(mode) > 3:
        mode[3] = "s" if mode[3] == "x" else "S"
    if "setgid" in bits and len(mode) > 6:
        mode[6] = "s" if mode[6] == "x" else "S"
    note = ", ".join(sorted(bits)) + " recorded in the original image (bits stripped on the extracted copy only)"
    return {**info, "mode": "".join(mode), "special_bits": note}


def filesystem_tools(ctx: ToolContext) -> list[BaseTool]:
    j = ctx.jail

    def read_file(path: str, offset: int = 0) -> str:
        """Read a text file from the target root filesystem (absolute path inside the rootfs). Use offset to page."""
        return fs.read_file(j, path, offset)

    def list_directory(path: str = "/") -> str:
        """List a directory in the target root filesystem (name, type, size, mode, symlink target)."""
        sp = special_bits(ctx)
        base = "/" + path.strip("/") if path.strip("/") else ""
        return _j([overlay_mode(e, f"{base}/{e['name']}" if "name" in e else "", sp) for e in fs.list_dir(j, path)])

    def glob_files(pattern: str, start: str = "/") -> str:
        """Find files by glob, e.g. '**/nginx.conf', '/usr/lib/**/libssl*', '**/site-packages/requests/*.py'."""
        return _j(fs.glob_files(j, pattern, start))

    def grep_search(pattern: str, path: str = "/", file_glob: str = "", ignore_case: bool = False) -> str:
        """Regex search in text files under path. file_glob narrows files, e.g. '*.py' or '**/conf.d/*'.
        Returns [{path,line,text}]. Prefer a narrow path - searching '/' on large images is slow."""
        return _j(fs.grep(j, pattern, path, file_glob or None, ignore_case))

    def file_info(path: str) -> str:
        """Stat a path: existence, mode (including setuid/setgid bits from the original image), size, symlink target."""
        return _j(overlay_mode(fs.file_info(j, path), "/" + path.strip("/"), special_bits(ctx)))

    return [StructuredTool.from_function(f) for f in (read_file, list_directory, glob_files, grep_search, file_info)]


def package_tools(ctx: ToolContext) -> list[BaseTool]:
    j, inv = ctx.jail, ctx.inventory

    def find_package(name: str, ecosystem: str = "generic") -> str:
        """Look up an installed package/library in the precomputed inventory. ecosystem: generic (search all) |
        deb | rpm | apk | pypi | npm | maven | go. Returns name, version, location, kind."""
        return _j(inv.find(name, ecosystem) or {"found": False})

    def list_os_packages(name_regex: str = "") -> str:
        """List OS packages (dpkg/rpm/apk), optionally filtered by a regex on the name."""
        import re

        rx = re.compile(name_regex, re.I) if name_regex else None
        return _j([p for p in inv.os_packages if not rx or rx.search(p["name"])][:300])

    def python_packages(path: str = "/") -> str:
        """Discover installed Python distributions (dist-info / egg-info) under path."""
        return _j([p.to_dict() for p in lang_pkgs.python_packages(j, path)][:500])

    def npm_packages(path: str = "/") -> str:
        """Discover npm packages (node_modules/*/package.json and package-lock.json) under path."""
        return _j([p.to_dict() for p in lang_pkgs.npm_packages(j, path)][:500])

    def java_packages(path: str = "/") -> str:
        """Discover Java artifacts in jar/war/ear files (pom.properties, MANIFEST, nested fat-jar libs) under path."""
        return _j([p.to_dict() for p in lang_pkgs.java_packages(j, path)][:500])

    def distro_info() -> str:
        """Return /etc/os-release of the target."""
        return _j(inv.distro)

    def check_distro_backport(package_name: str, vuln_id: str) -> str:
        """Check if an installed OS package has a distro backported fix for vuln_id (OSV distro data + changelog)."""
        pk = next((p for p in inv.os_packages if p["name"] == package_name or p.get("source") == package_name), None)
        if not pk:
            return _j({"error": f"OS package {package_name} not installed"})
        return _j(backport_check(ctx.settings, j, inv.distro, os_package_obj(pk), [vuln_id]))

    return [StructuredTool.from_function(f) for f in (find_package, list_os_packages, python_packages, npm_packages,
                                                       java_packages, distro_info, check_distro_backport)]


def binary_tools(ctx: ToolContext) -> list[BaseTool]:
    j = ctx.jail

    def elf_info(path: str, symbol_filter: str = "") -> str:
        """ELF metadata: type, interpreter, DT_NEEDED deps, soname, rpath, imported/exported dynamic symbols
        (optionally regex-filtered), hardening (PIE/NX/RELRO/canary/fortify), whether it's a Go binary."""
        return _j(binaries.elf_info(j, path, symbol_filter=symbol_filter or None))

    def find_symbol_users(symbol_regex: str, path: str = "/") -> str:
        """Find ELF binaries/libraries under path that import or define dynamic symbols matching symbol_regex.
        Key reachability signal for C libraries, e.g. 'X509_verify_cert|SSL_CTX_set_verify'."""
        return _j(binaries.find_symbol_users(j, symbol_regex, path))

    def shared_libraries(name_regex: str = "") -> str:
        """List shared libraries (*.so) with versions from file names and embedded version banners."""
        return _j([lib.to_dict() for lib in binaries.shared_libraries(j, name_filter=name_regex or None)][:300])

    def go_binary_scan(path: str = "/") -> str:
        """Find Go binaries under path and return Go version + module dependency list from build info."""
        res = binaries.go_binaries(j, path, max_results=50)
        for r in res:
            r["deps"] = r.get("deps", [])[:200]
        return _j(res)

    def strings_search(path: str, regex: str) -> str:
        """Search printable strings in a (binary) file for a regex, e.g. version banners or function names."""
        return _j(binaries.strings_search(j, path, regex))

    return [StructuredTool.from_function(f) for f in (elf_info, find_symbol_users, shared_libraries, go_binary_scan,
                                                       strings_search)]


def security_tools(ctx: ToolContext) -> list[BaseTool]:
    j = ctx.jail

    def security_controls(sample_binaries: list[str] | None = None) -> str:
        """Inspect security controls: run-as user, shells/package managers present, setuid binaries, file caps,
        MAC (SELinux/AppArmor), sysctl hardening, sshd/firewall config, and ELF hardening of sample binaries."""
        return _j(sc.inspect_security_controls(j, ctx.image_config, ctx.manifest_path, ctx.kind, sample_binaries))

    def image_config() -> str:
        """Container image config: user, entrypoint, cmd, env (secrets redacted), exposed ports, volumes, labels."""
        return _j(sc.image_config_summary(ctx.image_config) if ctx.image_config else
                  {"note": "no image config (host target or not provided)"})

    def services_and_listeners() -> str:
        """Enumerate systemd services (hosts) and listen/bind directives in common server configs."""
        return _j({"systemd": sc.systemd_units(j),
                   "listen_directives": sc.listening_config_hints(j)})

    return [StructuredTool.from_function(f) for f in (security_controls, image_config, services_and_listeners)]


def web_tools(settings: Settings) -> list[BaseTool]:
    def web_search(query: str) -> str:
        """Search the web (Tavily). Good for vendor advisories, patch commits, registry/vendor docs."""
        return _j(web.tavily_search(settings, query))

    def fetch_url(url: str) -> str:
        """Fetch a public web page / JSON document and return its text (truncated)."""
        return web.fetch_url(settings, url)

    def osv_lookup(vuln_id: str) -> str:
        """Fetch an OSV.dev record (CVE-, GHSA-, PYSEC-, GO-, DEBIAN-, UBUNTU- ...)."""
        rec = web.osv_get(settings, vuln_id)
        if rec:
            rec.pop("database_specific", None)
        return _j(rec or {"error": "not found"})

    def nvd_lookup(cve_id: str) -> str:
        """Fetch a CVE record from NVD (description, CVSS, CWE, CPE ranges, references)."""
        rec = web.nvd_lookup(settings, cve_id)
        return _j(web.summarize_nvd(rec) if rec else {"error": "not found"})

    def github_advisory_lookup(vuln_id: str) -> str:
        """Fetch GitHub Security Advisories for a CVE or GHSA id (affected ecosystems, ranges, vulnerable functions)."""
        return _j(web.ghsa_lookup(settings, vuln_id))

    return [StructuredTool.from_function(f) for f in (web_search, fetch_url, osv_lookup, nvd_lookup,
                                                       github_advisory_lookup)]


def analysis_tools(ctx: ToolContext) -> list[BaseTool]:
    """Everything that reads the target (no web)."""
    return filesystem_tools(ctx) + package_tools(ctx) + binary_tools(ctx) + security_tools(ctx)
