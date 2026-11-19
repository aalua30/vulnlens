"""Language package discovery: Python, npm, Java (jar/war/ear incl. nested fat-jar libs)."""

from __future__ import annotations

import io
import json
import os
import re
import stat
import zipfile
from dataclasses import asdict, dataclass

from .fs import Jail


@dataclass
class LangPackage:
    name: str
    version: str
    ecosystem: str  # pypi | npm | maven
    location: str
    extra: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _parse_metadata(text: str) -> tuple[str | None, str | None]:
    name = ver = None
    for line in text.splitlines():
        if not line.strip():
            break  # headers end at first blank line
        if line.startswith("Name:"):
            name = line[5:].strip()
        elif line.startswith("Version:"):
            ver = line[8:].strip()
    return name, ver


def python_packages(jail: Jail, start: str = "/") -> list[LangPackage]:
    out: list[LangPackage] = []
    seen: set[tuple[str, str, str]] = set()
    for rel, hp, st in jail.walk(start):
        parent = os.path.basename(os.path.dirname(rel))
        fn = os.path.basename(rel)
        meta_path = None
        if fn == "METADATA" and parent.endswith(".dist-info"):
            meta_path = hp
        elif fn == "PKG-INFO" and parent.endswith(".egg-info"):
            meta_path = hp
        elif fn.endswith(".egg-info") and stat.S_ISREG(st.st_mode):
            meta_path = hp
        if not meta_path:
            continue
        try:
            with open(meta_path, "r", errors="replace") as f:
                name, ver = _parse_metadata(f.read(64_000))
        except OSError:
            continue
        if name and ver:
            loc = os.path.dirname(os.path.dirname(rel)) if not fn.endswith(".egg-info") else os.path.dirname(rel)
            key = (normalize_pypi(name), ver, loc)
            if key not in seen:
                seen.add(key)
                out.append(LangPackage(name, ver, "pypi", loc))
    return out


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def npm_packages(jail: Jail, start: str = "/") -> list[LangPackage]:
    out: list[LangPackage] = []
    seen: set[tuple[str, str, str]] = set()
    for rel, hp, st in jail.walk(start):
        if not rel.endswith("/package.json") or "/node_modules/" not in rel:
            continue
        parts = rel.split("/")
        # only the package root: .../node_modules/<name>/package.json or .../node_modules/@s/<name>/package.json
        if not (parts[-3] == "node_modules" or (len(parts) > 4 and parts[-4] == "node_modules" and parts[-3].startswith("@"))):
            continue
        try:
            with open(hp, "rb") as f:
                pj = json.loads(f.read(512_000))
        except (OSError, ValueError):
            continue
        name, ver = pj.get("name"), pj.get("version")
        if isinstance(name, str) and isinstance(ver, str):
            key = (name, ver, rel)
            if key not in seen:
                seen.add(key)
                out.append(LangPackage(name, ver, "npm", os.path.dirname(rel)))
    # lockfiles for apps whose node_modules were pruned
    for rel, hp, st in jail.walk(start):
        if not rel.endswith("/package-lock.json") or "/node_modules/" in rel:
            continue
        try:
            with open(hp, "rb") as f:
                lock = json.loads(f.read(20_000_000))
        except (OSError, ValueError):
            continue
        for path, meta in (lock.get("packages") or {}).items():
            if not path or not isinstance(meta, dict) or "version" not in meta:
                continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            if not any(p.name == name and p.version == meta["version"] for p in out):
                out.append(LangPackage(name, meta["version"], "npm", rel, extra="lockfile"))
    return out


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------

_JAR_EXT = (".jar", ".war", ".ear", ".hpi", ".jpi")
_JAR_NAME_VER = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[\w.\-+]*?)(?:\.(?:jar|war|ear))$")


def _scan_archive(zf: zipfile.ZipFile, location: str, depth: int, out: list[LangPackage]) -> None:
    found_pom = False
    for info in zf.infolist():
        n = info.filename
        if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
            try:
                props = dict(
                    line.split("=", 1) for line in zf.read(n).decode("utf-8", "replace").splitlines()
                    if "=" in line and not line.startswith("#")
                )
            except (KeyError, zipfile.BadZipFile, ValueError):
                continue
            g, a, v = props.get("groupId", "").strip(), props.get("artifactId", "").strip(), props.get("version", "").strip()
            if a and v:
                out.append(LangPackage(f"{g}:{a}" if g else a, v, "maven", location))
                found_pom = True
        elif depth < 2 and n.lower().endswith(_JAR_EXT) and info.file_size < 200_000_000:
            try:
                with zf.open(info) as inner:
                    data = inner.read()
                _scan_archive(zipfile.ZipFile(io.BytesIO(data)), f"{location}!/{n}", depth + 1, out)
            except (zipfile.BadZipFile, OSError, RuntimeError):
                continue
    if not found_pom:
        title = ver = None
        try:
            mf = zf.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            for line in mf.splitlines():
                if line.startswith(("Implementation-Title:", "Bundle-SymbolicName:")) and not title:
                    title = line.split(":", 1)[1].strip().split(";")[0]
                elif line.startswith(("Implementation-Version:", "Bundle-Version:")) and not ver:
                    ver = line.split(":", 1)[1].strip()
        except KeyError:
            pass
        m = _JAR_NAME_VER.match(os.path.basename(location.split("!/")[-1]))
        if m:
            title = title or m.group("name")
            ver = ver or m.group("ver")
        if title and ver:
            out.append(LangPackage(title, ver, "maven", location, extra="manifest/filename"))


def java_packages(jail: Jail, start: str = "/") -> list[LangPackage]:
    out: list[LangPackage] = []
    for rel, hp, st in jail.walk(start):
        if not rel.lower().endswith(_JAR_EXT) or not stat.S_ISREG(st.st_mode):
            continue
        try:
            with zipfile.ZipFile(hp) as zf:
                _scan_archive(zf, rel, 0, out)
        except (zipfile.BadZipFile, OSError):
            continue
    return out


# ---------------------------------------------------------------------------
# Erlang / Elixir (OTP applications, Hex dependencies, RabbitMQ-style .ez plugins)
# ---------------------------------------------------------------------------

_APP_NAME = re.compile(r"\{\s*application\s*,\s*'?([a-z][\w@]*)'?\s*,", re.S)
_APP_VSN = re.compile(r"\{\s*vsn\s*,\s*\"([^\"]+)\"")


def _parse_app(text: str) -> tuple[str | None, str | None]:
    n, v = _APP_NAME.search(text), _APP_VSN.search(text)
    return (n.group(1) if n else None), (v.group(1) if v else None)


def erlang_packages(jail: Jail, start: str = "/") -> list[LangPackage]:
    """OTP applications and Hex packages from `<app>-<vsn>/ebin/<app>.app` resource files and `.ez` archives,
    plus the Erlang/OTP release itself (`releases/<n>/OTP_VERSION`) as package `erlang/otp`."""
    out: list[LangPackage] = []
    seen: set[tuple[str, str, str]] = set()

    def add(name: str | None, ver: str | None, loc: str, extra: str = "") -> None:
        if name and ver and (name, ver, loc) not in seen:
            seen.add((name, ver, loc))
            out.append(LangPackage(name, ver, "hex", loc, extra))

    for rel, hp, st in jail.walk(start):
        fn = os.path.basename(rel)
        if not stat.S_ISREG(st.st_mode):
            continue
        if fn.endswith(".app") and os.path.basename(os.path.dirname(rel)) == "ebin":
            try:
                with open(hp, "r", errors="replace") as f:
                    name, ver = _parse_app(f.read(64_000))
            except OSError:
                continue
            add(name, ver, os.path.dirname(os.path.dirname(rel)))
        elif fn.endswith(".ez") and st.st_size < 200_000_000:
            try:
                with zipfile.ZipFile(hp) as zf:
                    for member in zf.namelist():
                        if member.endswith(".app") and "/ebin/" in member:
                            name, ver = _parse_app(zf.read(member)[:64_000].decode("utf-8", "replace"))
                            add(name, ver, rel, "ez")
            except (OSError, zipfile.BadZipFile, KeyError):
                continue
        elif fn == "OTP_VERSION" and "/releases/" in rel:
            try:
                with open(hp, "r", errors="replace") as f:
                    ver = f.read(64).strip()
            except OSError:
                continue
            add("erlang/otp", ver, os.path.dirname(rel), "otp-release")
    return out
