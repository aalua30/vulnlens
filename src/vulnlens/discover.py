"""Candidate CVE discovery: query OSV for every inventoried package (and optionally NVD for CPEs), so a full scan
can feed the pipeline without an external scanner.

    vulnlens discover <rootfs> -o candidates.json [--cpe cpe:2.3:a:openssl:openssl:3.5.8] [--input-out input.json]
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from .config import Settings
from .tools.backports import osv_distro_ecosystem
from .tools.inventory import Inventory
from .tools.web import UA

log = logging.getLogger(__name__)

LANG_ECOSYSTEMS = {"python": "PyPI", "npm": "npm", "java": "Maven", "erlang": "Hex"}
OSV_BATCH = 500


def build_queries(inv: Inventory) -> list[tuple[str, dict]]:
    """(label, OSV query) for each distinct package/version in the inventory."""
    out: list[tuple[str, dict]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(eco: str, name: str, version: str, label: str) -> None:
        key = (eco, name, version)
        if name and version and key not in seen:
            seen.add(key)
            out.append((label, {"package": {"name": name, "ecosystem": eco}, "version": version}))

    distro_eco = osv_distro_ecosystem(inv.distro)
    if distro_eco:
        prefix = distro_eco.split(":")[0].lower()
        for p in inv.os_packages:
            if p.get("third_party"):
                continue  # vendor builds are not covered by distro advisories
            name, ver = p.get("source") or p["name"], p.get("source_version") or p["version"]
            add(distro_eco, name, ver, f"{prefix}:{name}={ver}")
    for attr, eco in LANG_ECOSYSTEMS.items():
        for p in getattr(inv, attr):
            name = p["name"]
            if attr == "erlang" and name == "erlang/otp":
                continue  # OTP itself is tracked by CPE (see --cpe), not Hex
            add(eco, name, p.get("version", ""), f"{eco.lower()}:{name}={p.get('version', '')}")
    for g in inv.go_binaries:
        if g.get("go_version", "").startswith("go"):
            add("Go", "stdlib", g["go_version"].removeprefix("go"), f"go:stdlib={g['go_version']}")
        for dep in ([g["main"]] if g.get("main") else []) + g.get("deps", []):
            d = dep.get("replaced_by") or dep
            if d.get("version") and d["version"] != "(devel)":
                add("Go", dep["path"], d["version"], f"go:{dep['path']}={d['version']}")
    return out


def _entry(cands: dict, cid: str, summary: str) -> dict:
    return cands.setdefault(cid, {"pkgs": set(), "src": set(), "prio": set(), "summary": summary[:160]})


def discover(settings: Settings, inv: Inventory, cpes: list[str] | None = None,
             client: httpx.Client | None = None) -> dict[str, dict[str, Any]]:
    """Map CVE id (or the advisory id when it has no CVE alias) -> {pkgs, src, prio, summary, cvss?}."""
    queries = build_queries(inv)
    own = client is None
    c = client or httpx.Client(timeout=60, headers={"User-Agent": UA})
    hits: dict[str, set[str]] = {}
    try:
        for i in range(0, len(queries), OSV_BATCH):
            chunk = queries[i:i + OSV_BATCH]
            r = c.post("https://api.osv.dev/v1/querybatch", json={"queries": [q for _, q in chunk]})
            r.raise_for_status()
            for (label, _), res in zip(chunk, r.json().get("results", [])):
                for v in res.get("vulns") or []:
                    hits.setdefault(v["id"], set()).add(label)
        log.info("OSV: %d queries -> %d advisories", len(queries), len(hits))
        cands: dict[str, dict] = {}
        for vid, pkgs in hits.items():
            r = c.get(f"https://api.osv.dev/v1/vulns/{vid}")
            if r.status_code != 200:
                continue
            rec = r.json()
            ids = [a for a in [vid, *rec.get("aliases", []), *rec.get("upstream", [])] if a.startswith("CVE-")]
            e = _entry(cands, ids[0] if ids else vid, rec.get("summary") or rec.get("details", ""))
            e["pkgs"] |= pkgs
            e["src"].add(vid)
            for a in rec.get("affected", []):
                prio = (a.get("ecosystem_specific") or {}).get("ubuntu_priority")
                if prio:
                    e["prio"].add(prio)
            text = (rec.get("summary") or "") + (rec.get("details") or "")
            if (rec.get("withdrawn") or "").strip() or "** REJECT **" in text or text.startswith("Rejected reason"):
                e["withdrawn"] = True
        for cpe in cpes or []:
            time.sleep(0 if settings.nvd_api_key else 6.5)  # public NVD rate limit: 5 requests / 30 s
            headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
            r = c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                      params={"virtualMatchString": cpe, "resultsPerPage": 2000}, headers=headers)
            if r.status_code != 200:
                log.warning("NVD %s -> %s", cpe, r.status_code)
                continue
            for v in r.json().get("vulnerabilities", []):
                cv = v["cve"]
                if cv.get("vulnStatus") == "Rejected":
                    continue
                desc = next((d["value"] for d in cv.get("descriptions", []) if d.get("lang") == "en"), "")
                m = cv.get("metrics", {})
                score = next((m[k][0]["cvssData"].get("baseScore")
                              for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30") if m.get(k)), None)
                e = _entry(cands, cv["id"], desc)
                e["pkgs"].add("nvd:" + cpe.split(":")[4])
                e["src"].add("nvd")
                if score is not None:
                    e["cvss"] = score
    finally:
        if own:
            c.close()
    return {k: {**v, "pkgs": sorted(v["pkgs"]), "src": sorted(v["src"]), "prio": sorted(v["prio"])}
            for k, v in sorted(cands.items())}


def package_hint(entry: dict) -> str | None:
    """'ubuntu:openssl=3.0.13' -> 'openssl'; prefers ecosystem hits over NVD CPE product names."""
    pkgs = sorted(entry.get("pkgs") or [], key=lambda p: p.startswith("nvd:"))
    if not pkgs:
        return None
    return pkgs[0].split(":", 1)[1].split("=", 1)[0]


def to_vulnerabilities(cands: dict[str, dict], include_withdrawn: bool = False) -> list[dict]:
    return [{"vuln_id": k, "package_hint": package_hint(v)} for k, v in cands.items()
            if include_withdrawn or not v.get("withdrawn")]
