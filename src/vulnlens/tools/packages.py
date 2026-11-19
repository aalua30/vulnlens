"""OS package database inspection: dpkg, apk, rpm (sqlite rpmdb parsed natively; BDB via `rpm --root`)."""

from __future__ import annotations

import gzip
import re
import shutil
import sqlite3
import struct
import subprocess
from dataclasses import asdict, dataclass, field

from .fs import Jail


@dataclass
class OsPackage:
    name: str
    version: str
    ecosystem: str  # deb | rpm | apk
    arch: str = ""
    source: str = ""  # source package name (deb Source:, rpm SOURCERPM name, apk origin)
    source_version: str = ""
    db: str = ""
    extra: dict = field(default_factory=dict)
    vendor: str = ""  # deb Maintainer / rpm Vendor
    # Built by a third party (e.g. nginx.org, Docker, PGDG repos) rather than the distro: distro advisory data
    # (Debian tracker, RHSA, ...) does not describe this build, upstream version data does.
    third_party: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d["extra"]:
            d.pop("extra")
        return d


_CODENAMES = ("buzz|rex|bo|hamm|slink|potato|woody|sarge|etch|lenny|squeeze|wheezy|jessie|stretch|buster|bullseye|"
              "bookworm|trixie|forky|duke|sid|trusty|xenial|bionic|focal|jammy|kinetic|lunar|mantic|noble|oracular|"
              "plucky|questing")
# "1.25.5-1~bookworm", "5:24.0.7-1~debian.12~bookworm", "16.2-1.pgdg120+1", "1.2.3-1~jammy1"
_DEB_THIRD_PARTY_VER = re.compile(rf"(?:~(?:debian|ubuntu)\.[\d.]+)|[~+.](?:{_CODENAMES})\d*(?:$|[~+.])|pgdg",
                                  re.IGNORECASE)
_DEB_DISTRO_VER = re.compile(r"(?:\+deb\d+u\d+|~deb\d+u\d+|~bpo\d+|ubuntu\d|\+esm|\+really)", re.IGNORECASE)
_DEB_VENDOR_DOMAINS = re.compile(r"@(?:[\w.-]+\.)?(?:f5\.com|nginx\.com|docker\.com|nodesource\.com|mongodb\.com|"
                                 r"elastic\.co|grafana\.com|hashicorp\.com|redis\.io|mariadb\.(?:org|com)|"
                                 r"percona\.com|influxdata\.com|treasuredata\.com|haproxy\.com|caddyserver\.com|"
                                 r"envoyproxy\.io|google\.com|microsoft\.com|oracle\.com|azul\.com|adoptium\.net)>?",
                                 re.IGNORECASE)
_RPM_DISTRO_VENDORS = re.compile(r"red hat|centos|fedora|rocky|alma|cloudlinux|oracle america|amazon|suse|opensuse|"
                                 r"microsoft corporation|mariner|vmware|broadcom|photon|mageia|openela|circle|navy|"
                                 r"eurolinux|scientific|openeuler|anolis|openmandriva|koji", re.IGNORECASE)


def deb_is_third_party(version: str, maintainer: str) -> bool:
    if _DEB_DISTRO_VER.search(version):
        return False
    return bool(_DEB_THIRD_PARTY_VER.search(version) or _DEB_VENDOR_DOMAINS.search(maintainer or ""))


def rpm_is_third_party(vendor: str) -> bool:
    return bool(vendor) and not _RPM_DISTRO_VENDORS.search(vendor)


# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------


def os_release(jail: Jail) -> dict[str, str]:
    for cand in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            p = jail.resolve(cand)
        except ValueError:
            continue
        if p.is_file():
            out = {}
            for line in p.read_text(errors="replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
            return out
    for cand, distro in (("/etc/alpine-release", "alpine"), ("/etc/debian_version", "debian"),
                         ("/etc/redhat-release", "rhel")):
        p = jail.resolve(cand)
        if p.is_file():
            return {"ID": distro, "VERSION_ID": p.read_text(errors="replace").strip().split()[0]}
    return {}


# ---------------------------------------------------------------------------
# dpkg
# ---------------------------------------------------------------------------


def _parse_deb822(text: str):
    para: dict[str, str] = {}
    last = None
    for line in text.splitlines():
        if not line.strip():
            if para:
                yield para
            para, last = {}, None
            continue
        if line[0] in " \t" and last:
            para[last] += "\n" + line.strip()
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            last = k.strip()
            para[last] = v.strip()
    if para:
        yield para


def dpkg_packages(jail: Jail) -> list[OsPackage]:
    texts: list[tuple[str, str]] = []
    status = jail.resolve("/var/lib/dpkg/status")
    if status.is_file():
        texts.append(("/var/lib/dpkg/status", status.read_text(errors="replace")))
    status_d = jail.resolve("/var/lib/dpkg/status.d")  # distroless
    if status_d.is_dir():
        for f in sorted(status_d.iterdir()):
            if f.is_file() and not f.name.endswith(".md5sums"):
                texts.append((f"/var/lib/dpkg/status.d/{f.name}", f.read_text(errors="replace")))
    pkgs = []
    for db, text in texts:
        for p in _parse_deb822(text):
            if "Package" not in p or "Version" not in p:
                continue
            if "Status" in p and "installed" not in p["Status"].split()[-1:]:
                continue
            src, src_ver = p.get("Package"), p["Version"]
            if p.get("Source"):
                m = re.match(r"(\S+)(?:\s+\((.+)\))?", p["Source"])
                src = m.group(1)
                src_ver = m.group(2) or p["Version"]
            maint = p.get("Maintainer", "")
            pkgs.append(OsPackage(p["Package"], p["Version"], "deb", p.get("Architecture", ""), src, src_ver, db,
                                  vendor=maint, third_party=deb_is_third_party(p["Version"], maint)))
    return pkgs


def deb_changelog(jail: Jail, pkg: str, source: str | None = None, max_bytes: int = 4_000_000) -> str | None:
    for name in filter(None, (pkg, source)):
        for fn in ("changelog.Debian.gz", "changelog.gz", "changelog.Debian"):
            try:
                p = jail.resolve(f"/usr/share/doc/{name}/{fn}")
            except ValueError:
                continue
            if p.is_file():
                raw = p.read_bytes()[:max_bytes]
                try:
                    return gzip.decompress(raw).decode("utf-8", "replace") if fn.endswith(".gz") else raw.decode(
                        "utf-8", "replace")
                except (OSError, EOFError):
                    continue
    return None


# ---------------------------------------------------------------------------
# apk
# ---------------------------------------------------------------------------


def apk_packages(jail: Jail) -> list[OsPackage]:
    p = jail.resolve("/lib/apk/db/installed")
    if not p.is_file():
        return []
    pkgs, cur = [], {}
    for line in p.read_text(errors="replace").splitlines() + [""]:
        if not line.strip():
            if "P" in cur and "V" in cur:
                pkgs.append(OsPackage(cur["P"], cur["V"], "apk", cur.get("A", ""), cur.get("o", cur["P"]), cur["V"],
                                      "/lib/apk/db/installed"))
            cur = {}
            continue
        if len(line) > 2 and line[1] == ":":
            cur.setdefault(line[0], line[2:])
    return pkgs


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------

_RPMTAG = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1011: "vendor", 1022: "arch", 1044: "sourcerpm",
           1081: "changelogname", 1082: "changelogtext"}


def parse_rpm_header(blob: bytes) -> dict:
    il, dl = struct.unpack(">II", blob[:8])
    idx_start = 8
    data_start = idx_start + il * 16
    data = blob[data_start : data_start + dl]
    out: dict = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack(">iiii", blob[idx_start + i * 16 : idx_start + (i + 1) * 16])
        key = _RPMTAG.get(tag)
        if not key:
            continue
        if typ == 4:  # INT32
            out[key] = struct.unpack(">i", data[off : off + 4])[0]
        elif typ in (6, 9):  # STRING / I18N
            out[key] = data[off : data.index(b"\x00", off)].decode("utf-8", "replace")
        elif typ == 8:  # STRING_ARRAY
            vals, pos = [], off
            for _ in range(cnt):
                end = data.index(b"\x00", pos)
                vals.append(data[pos:end].decode("utf-8", "replace"))
                pos = end + 1
            out[key] = vals
    return out


def _rpm_from_header(h: dict, db: str) -> OsPackage:
    epoch = h.get("epoch")
    ver = f"{h.get('version', '')}-{h.get('release', '')}"
    if epoch:
        ver = f"{epoch}:{ver}"
    srpm = h.get("sourcerpm") or ""
    m = re.match(r"(.+)-([^-]+)-([^-]+)\.src\.rpm$", srpm)
    src = m.group(1) if m else h.get("name", "")
    vendor = h.get("vendor") or ""
    return OsPackage(h.get("name", ""), ver, "rpm", h.get("arch", ""), src, ver, db,
                     vendor=vendor, third_party=rpm_is_third_party(vendor))


def rpm_packages(jail: Jail, with_changelog: bool = False) -> list[OsPackage]:
    for rel in ("/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite"):
        p = jail.resolve(rel)
        if p.is_file():
            pkgs = []
            con = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
            try:
                for (blob,) in con.execute("SELECT blob FROM Packages"):
                    try:
                        h = parse_rpm_header(bytes(blob))
                    except (struct.error, ValueError, IndexError):
                        continue
                    if h.get("name") == "gpg-pubkey":
                        continue
                    pkg = _rpm_from_header(h, rel)
                    if with_changelog:
                        pkg.extra["changelog"] = "\n".join(h.get("changelogtext", []) or [])
                    pkgs.append(pkg)
            finally:
                con.close()
            return pkgs
    # BDB / ndb databases: delegate to the rpm binary if present on the host
    for rel in ("/var/lib/rpm/Packages", "/var/lib/rpm/Packages.db", "/usr/lib/sysimage/rpm/Packages.db"):
        if jail.resolve(rel).is_file() and shutil.which("rpm"):
            fmt = "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"
            dbpath = str(jail.resolve(rel).parent)
            proc = subprocess.run(["rpm", "--dbpath", dbpath, "-qa", "--qf", fmt], capture_output=True, text=True)
            pkgs = []
            for line in proc.stdout.splitlines():
                name, ver, arch, srpm = (line.split("\t") + ["", "", "", ""])[:4]
                if name == "gpg-pubkey":
                    continue
                ver = ver[2:] if ver.startswith("0:") else ver
                m = re.match(r"(.+)-([^-]+)-([^-]+)\.src\.rpm$", srpm)
                pkgs.append(OsPackage(name, ver, "rpm", arch, m.group(1) if m else name, ver, rel))
            return pkgs
    return []


def rpm_changelog(jail: Jail, name: str) -> str | None:
    for p in rpm_packages(jail, with_changelog=True):
        if p.name == name or p.source == name:
            return p.extra.get("changelog")
    return None


def os_packages(jail: Jail) -> list[OsPackage]:
    return dpkg_packages(jail) + apk_packages(jail) + rpm_packages(jail)
