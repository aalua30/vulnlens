"""Public vulnerability sources (NVD, GitHub Advisories, OSV), Tavily web search and a guarded URL fetcher."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from ..config import Settings

log = logging.getLogger(__name__)
UA = "vulnlens/0.1 (vulnerability-analysis)"


def _client(settings: Settings) -> httpx.Client:
    return httpx.Client(timeout=settings.http_timeout, headers={"User-Agent": UA}, follow_redirects=True)


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------


def nvd_lookup(settings: Settings, cve_id: str) -> dict | None:
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    with _client(settings) as c:
        r = c.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve_id}, headers=headers)
        if r.status_code != 200:
            log.warning("NVD %s -> %s", cve_id, r.status_code)
            return None
        vulns = r.json().get("vulnerabilities") or []
        return vulns[0]["cve"] if vulns else None


def summarize_nvd(cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    score = vector = severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            score, vector = d.get("baseScore"), d.get("vectorString")
            severity = d.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    cpes = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    cpes.append({k: m[k] for k in ("criteria", "versionStartIncluding", "versionStartExcluding",
                                                   "versionEndIncluding", "versionEndExcluding") if k in m})
    refs = [r["url"] for r in cve.get("references", [])][:40]
    return {"id": cve.get("id"), "description": desc, "cvss_score": score, "cvss_vector": vector,
            "severity": severity, "cwe": cwes, "cpe_matches": cpes[:60], "references": refs,
            "published": cve.get("published"), "status": cve.get("vulnStatus")}


def cpe_to_affected(cpes: list[dict]) -> list[dict]:
    """Translate NVD CPE matches into generic AffectedPackage dicts (upstream versions)."""
    out: dict[str, dict] = {}
    for m in cpes:
        parts = m["criteria"].split(":")
        if len(parts) < 6 or parts[2] not in ("a", "o"):
            continue
        product, version = parts[4].replace("\\", ""), parts[5]
        # OS platform and appliance-firmware CPEs describe where a product ships, not a component that can be
        # located in a filesystem; keep only the kernel among OS CPEs.
        if (parts[2] == "o" and product not in ("linux_kernel",)) or product.endswith("_firmware"):
            continue
        rng: dict[str, str] = {}
        exprs = []
        if "versionStartIncluding" in m:
            exprs.append(f">={m['versionStartIncluding']}")
        if "versionStartExcluding" in m:
            exprs.append(f">{m['versionStartExcluding']}")
        if "versionEndExcluding" in m:
            exprs.append(f"<{m['versionEndExcluding']}")
        if "versionEndIncluding" in m:
            exprs.append(f"<={m['versionEndIncluding']}")
        if exprs:
            rng = {"expr": ",".join(exprs)}
        elif version not in ("*", "-", ""):
            rng = {"expr": f"=={version}"}
        entry = out.setdefault(product, {"name": product, "ecosystem": "generic", "ranges": [], "fixed_versions": [],
                                         "source": "nvd-cpe", "vendor": parts[3]})
        if rng and rng not in entry["ranges"]:
            entry["ranges"].append(rng)
        if "versionEndExcluding" in m and m["versionEndExcluding"] not in entry["fixed_versions"]:
            entry["fixed_versions"].append(m["versionEndExcluding"])
    for e in out.values():
        e.pop("vendor", None)
    return list(out.values())


# ---------------------------------------------------------------------------
# GitHub advisories
# ---------------------------------------------------------------------------


def ghsa_lookup(settings: Settings, vuln_id: str) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    params = {"cve_id": vuln_id} if vuln_id.startswith("CVE-") else {"ghsa_id": vuln_id}
    with _client(settings) as c:
        r = c.get("https://api.github.com/advisories", params=params, headers=headers)
        if r.status_code != 200:
            log.warning("GHSA %s -> %s", vuln_id, r.status_code)
            return []
        out = []
        for a in r.json():
            out.append({
                "ghsa_id": a.get("ghsa_id"), "summary": a.get("summary"),
                "description": (a.get("description") or "")[:4000], "severity": a.get("severity"),
                "cwes": [w.get("cwe_id") for w in a.get("cwes") or []],
                "references": (a.get("references") or [])[:20],
                "vulnerabilities": [
                    {"ecosystem": (v.get("package") or {}).get("ecosystem"), "name": (v.get("package") or {}).get("name"),
                     "vulnerable_version_range": v.get("vulnerable_version_range"),
                     "first_patched_version": v.get("first_patched_version"),
                     "vulnerable_functions": v.get("vulnerable_functions") or []}
                    for v in a.get("vulnerabilities") or []
                ],
            })
        return out


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

OSV_ECO_MAP = {
    "pypi": "pypi", "npm": "npm", "maven": "maven", "go": "go", "hex": "hex", "crates.io": "cargo", "rubygems": "gem",
    "nuget": "nuget", "packagist": "composer", "debian": "deb", "ubuntu": "deb", "alpine": "apk",
    "red hat": "rpm", "rocky linux": "rpm", "almalinux": "rpm", "opensuse": "rpm", "suse": "rpm",
    "mageia": "rpm", "photon os": "rpm", "wolfi": "apk", "chainguard": "apk", "azure linux": "rpm",
}


def osv_eco(ecosystem: str) -> tuple[str, str | None]:
    """'Debian:12' -> ('deb', 'debian:12'); 'PyPI' -> ('pypi', None)."""
    base, _, rest = ecosystem.partition(":")
    eco = OSV_ECO_MAP.get(base.lower(), "generic")
    distro = f"{base.lower()}:{rest.lower()}" if rest and eco in ("deb", "rpm", "apk") else (
        base.lower() if eco in ("deb", "rpm", "apk") else None)
    return eco, distro


def osv_get(settings: Settings, vuln_id: str) -> dict | None:
    with _client(settings) as c:
        r = c.get(f"https://api.osv.dev/v1/vulns/{vuln_id}")
        return r.json() if r.status_code == 200 else None


def osv_query(settings: Settings, name: str, ecosystem: str, version: str) -> list[dict]:
    with _client(settings) as c:
        r = c.post("https://api.osv.dev/v1/query",
                   json={"package": {"name": name, "ecosystem": ecosystem}, "version": version})
        if r.status_code != 200:
            return []
        return r.json().get("vulns") or []


def osv_to_affected(rec: dict) -> list[dict]:
    out = []
    for a in rec.get("affected") or []:
        pkg = a.get("package") or {}
        if not pkg.get("name") or not pkg.get("ecosystem"):
            continue
        eco, distro = osv_eco(pkg["ecosystem"])
        ranges, fixed = [], []
        for r in a.get("ranges") or []:
            if r.get("type") == "GIT":
                continue
            cur: dict[str, str] = {}
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    if cur:
                        ranges.append(cur)
                    cur = {"introduced": ev["introduced"]}
                for k in ("fixed", "last_affected", "limit"):
                    if k in ev:
                        cur[k] = ev[k]
                        if k == "fixed":
                            fixed.append(ev[k])
                        ranges.append(cur)
                        cur = {}
            if cur:
                ranges.append(cur)
        if not ranges and a.get("versions"):
            ranges = [{"expr": f"=={v}"} for v in a["versions"][:200]]
        funcs = []
        for imp in ((a.get("ecosystem_specific") or {}).get("imports") or []):
            funcs += [f"{imp.get('path')}.{s}" for s in imp.get("symbols") or []]
        out.append({"name": pkg["name"], "ecosystem": eco, "distro": distro, "ranges": ranges,
                    "fixed_versions": fixed, "source": f"osv:{rec.get('id')}", "_functions": funcs})
    return out


# ---------------------------------------------------------------------------
# Tavily & URL fetch
# ---------------------------------------------------------------------------


def tavily_search(settings: Settings, query: str, max_results: int = 6, include_domains: list[str] | None = None) -> list[dict]:
    if not settings.tavily_api_key:
        return [{"error": "TAVILY_API_KEY not configured"}]
    from tavily import TavilyClient

    client = TavilyClient(api_key=settings.tavily_api_key)
    kw = {"include_domains": include_domains} if include_domains else {}
    res = client.search(query=query, max_results=max_results, search_depth="advanced", **kw)
    return [{"title": r.get("title"), "url": r.get("url"), "content": (r.get("content") or "")[:1500]}
            for r in res.get("results", [])]


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header"}

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in ("p", "br", "li", "tr", "h1", "h2", "h3", "h4", "pre", "div"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


@lru_cache(maxsize=512)
def _host_is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def fetch_url(settings: Settings, url: str, max_chars: int = 20000) -> str:
    with httpx.Client(timeout=settings.http_timeout, headers={"User-Agent": UA}, follow_redirects=False) as c:
        for _ in range(6):  # follow redirects manually so every hop passes the SSRF check
            u = urlparse(url)
            if u.scheme not in ("http", "https") or not u.hostname:
                return "ERROR: only http(s) URLs are allowed"
            if not settings.allow_private_fetch and not _host_is_public(u.hostname):
                return "ERROR: refusing to fetch non-public address"
            r = c.get(url)
            if r.is_redirect and r.headers.get("location"):
                url = str(r.url.join(r.headers["location"]))
                continue
            break
        else:
            return "ERROR: too many redirects"
        ctype = r.headers.get("content-type", "")
        if r.status_code >= 400:
            return f"ERROR: HTTP {r.status_code}"
        if "html" in ctype:
            p = _TextExtractor()
            p.feed(r.text)
            text = "".join(p.parts)
        elif "json" in ctype or "text" in ctype or not ctype:
            text = r.text
        else:
            return f"ERROR: unsupported content-type {ctype}"
    text = re.sub(r"\n\s*\n+", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()
    return text[:max_chars]
