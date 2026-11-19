"""Distro backport checks: was a CVE fixed in the installed distro package even though the upstream
version string looks vulnerable?

Evidence sources, strongest first:
1. OSV distro advisories (Debian, Ubuntu, Alpine, Red Hat, Rocky, Alma, SUSE, Wolfi...) queried with the
   exact installed version - authoritative "is this version affected" from the distro's own data.
2. Local package changelog mentions the CVE (deb changelog.Debian.gz, rpm %changelog in rpmdb).
"""

from __future__ import annotations

import logging

from ..config import Settings
from .fs import Jail
from .packages import OsPackage, deb_changelog, rpm_changelog
from .web import osv_get, osv_query

log = logging.getLogger(__name__)


def osv_distro_ecosystem(distro: dict[str, str]) -> str | None:
    did = (distro.get("ID") or "").lower()
    ver = distro.get("VERSION_ID", "")
    major = ver.split(".")[0]
    if did == "debian" and major:
        return f"Debian:{major}"
    if did == "ubuntu" and ver:
        lts = ":LTS" if ver.endswith(".04") and int(ver.split(".")[0]) % 2 == 0 else ""
        return f"Ubuntu:{ver}{lts}"
    if did == "alpine" and ver:
        return f"Alpine:v{'.'.join(ver.split('.')[:2])}"
    if did in ("rhel", "redhat") or "rhel" in distro.get("ID_LIKE", "") and did not in ("rocky", "almalinux"):
        return "Red Hat"
    if did == "rocky" and major:
        return f"Rocky Linux:{major}"
    if did == "almalinux" and major:
        return f"AlmaLinux:{major}"
    if did in ("opensuse-leap", "opensuse-tumbleweed", "sles"):
        return "SUSE"
    if did == "wolfi":
        return "Wolfi"
    if did == "chainguard":
        return "Chainguard"
    return None


def changelog_mentions(jail: Jail, pkg: OsPackage, vuln_ids: list[str]) -> dict | None:
    text = None
    if pkg.ecosystem == "deb":
        text = deb_changelog(jail, pkg.name, pkg.source)
    elif pkg.ecosystem == "rpm":
        text = rpm_changelog(jail, pkg.name)
    if not text:
        return None
    for vid in vuln_ids:
        idx = text.find(vid)
        if idx >= 0:
            start = max(0, text.rfind("\n", 0, max(0, idx - 300)))
            return {"id": vid, "excerpt": text[start : idx + 200].strip()}
    return {"id": None, "excerpt": ""}


def backport_check(settings: Settings, jail: Jail, distro: dict[str, str], pkg: OsPackage,
                   vuln_ids: list[str]) -> dict:
    """Return {'patched': True|False|None, 'method': str, 'evidence': str}."""
    result = {"package": pkg.name, "version": pkg.version, "patched": None, "method": "none", "evidence": ""}
    eco = osv_distro_ecosystem(distro)
    if eco:
        names = list(dict.fromkeys(filter(None, [pkg.source, pkg.name])))
        version = pkg.source_version or pkg.version
        try:
            for name in names:
                affecting = osv_query(settings, name, eco, version if name == pkg.source else pkg.version)
                ids = {v.get("id") for v in affecting} | {a for v in affecting for a in v.get("aliases", [])}
                ids |= {u for v in affecting for u in v.get("upstream", [])}
                if ids & set(vuln_ids):
                    result.update(patched=False, method=f"osv:{eco}",
                                  evidence=f"OSV lists {sorted(ids & set(vuln_ids))} as affecting {name} {version}")
                    return result
                if affecting is not None and _distro_tracks(settings, vuln_ids, eco, name):
                    result.update(patched=True, method=f"osv:{eco}",
                                  evidence=f"{eco} tracks {vuln_ids[0]} for {name}; installed {version} not affected")
                    return result
        except Exception as e:  # network trouble shouldn't kill the triage
            log.warning("OSV backport query failed: %s", e)
            result["evidence"] = f"osv error: {e}"
    cl = changelog_mentions(jail, pkg, vuln_ids)
    if cl and cl["id"]:
        result.update(patched=True, method="changelog", evidence=cl["excerpt"][:1200])
    elif cl is not None and result["patched"] is None:
        result.update(method="changelog", evidence="changelog present; CVE not mentioned")
    return result


def _distro_tracks(settings: Settings, vuln_ids: list[str], eco: str, name: str) -> bool:
    """True if any OSV record for these ids has an `affected` entry for (eco, name) - i.e. the distro
    assessed this CVE for the package, so absence from the query result means 'fixed'."""
    base = eco.split(":")[0].lower()
    for vid in vuln_ids:
        candidates = [vid]
        if base == "debian":
            candidates.append(f"DEBIAN-{vid}")
        elif base == "ubuntu":
            candidates.append(f"UBUNTU-{vid}")
        for cid in candidates:
            rec = osv_get(settings, cid)
            if not rec:
                continue
            for a in rec.get("affected") or []:
                p = a.get("package") or {}
                if p.get("name") == name and p.get("ecosystem", "").lower().startswith(base):
                    return True
    return False
