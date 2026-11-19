"""Ecosystem-aware version comparison and range evaluation.

Implements dpkg and rpm comparison algorithms natively, PEP 440 via ``packaging``, semver-ish for
npm/go/cargo, and a tolerant generic comparator for everything else.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

# ---------------------------------------------------------------------------
# dpkg
# ---------------------------------------------------------------------------


def _dpkg_order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    r = _dpkg_verrevcmp(ua, ub)
    if r:
        return 1 if r > 0 else -1
    r = _dpkg_verrevcmp(ra, rb)
    return (r > 0) - (r < 0)


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------

_RPM_SEG = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    sa, sb = a, b
    while sa or sb:
        sa = re.sub(r"^[^a-zA-Z0-9~^]+", "", sa)
        sb = re.sub(r"^[^a-zA-Z0-9~^]+", "", sb)
        if sa.startswith("~") or sb.startswith("~"):
            if not sa.startswith("~"):
                return 1
            if not sb.startswith("~"):
                return -1
            sa, sb = sa[1:], sb[1:]
            continue
        if sa.startswith("^") or sb.startswith("^"):
            if not sa:
                return -1
            if not sb:
                return 1
            if not sa.startswith("^"):
                return 1
            if not sb.startswith("^"):
                return -1
            sa, sb = sa[1:], sb[1:]
            continue
        if not sa or not sb:
            break
        ma = re.match(r"\d+" if sa[0].isdigit() else r"[a-zA-Z]+", sa)
        isnum = sa[0].isdigit()
        mb = re.match(r"\d+" if isnum else r"[a-zA-Z]+", sb)
        if not mb:
            return 1 if isnum else -1
        xa, xb = ma.group(0), mb.group(0)
        sa, sb = sa[len(xa):], sb[len(xb):]
        if isnum:
            xa, xb = xa.lstrip("0"), xb.lstrip("0")
            if len(xa) != len(xb):
                return 1 if len(xa) > len(xb) else -1
        if xa != xb:
            return 1 if xa > xb else -1
    if not sa and not sb:
        return 0
    return 1 if sa else -1


def _rpm_split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ""
    return epoch, ver, rel


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    r = rpmvercmp(va, vb)
    if r or not ra or not rb:
        return r
    return rpmvercmp(ra, rb)


# ---------------------------------------------------------------------------
# apk (Alpine) - simplified apk-tools ordering
# ---------------------------------------------------------------------------

_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_key(v: str):
    v = v.strip()
    rel = 0
    m = re.search(r"-r(\d+)$", v)
    if m:
        rel = int(m.group(1))
        v = v[: m.start()]
    suffixes = []
    while True:
        m = re.search(r"_([a-z]+)(\d*)$", v)
        if not m:
            break
        suffixes.insert(0, (_APK_SUFFIX.get(m.group(1), 0), int(m.group(2) or 0)))
        v = v[: m.start()]
    letter = ""
    m = re.search(r"([a-z])$", v)
    if m:
        letter = m.group(1)
        v = v[:-1]
    nums = [int(x) if x.isdigit() else 0 for x in v.split(".")]
    return nums, letter, suffixes or [(0, 0)], rel


def apk_compare(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    return (ka > kb) - (ka < kb)


# ---------------------------------------------------------------------------
# semver / generic / maven
# ---------------------------------------------------------------------------


def _generic_tokens(v: str):
    v = v.strip().lstrip("vV")
    v = v.split("+", 1)[0]  # build metadata
    main, _, pre = v.partition("-")
    def toks(s):
        out = []
        for t in re.findall(r"\d+|[a-zA-Z]+", s):
            out.append((1, int(t), "") if t.isdigit() else (0, 0, t.lower()))
        return out
    return toks(main), toks(pre) if pre else None


def semver_compare(a: str, b: str) -> int:
    ma, pa = _generic_tokens(a)
    mb, pb = _generic_tokens(b)
    n = max(len(ma), len(mb))
    ma += [(1, 0, "")] * (n - len(ma))
    mb += [(1, 0, "")] * (n - len(mb))
    if ma != mb:
        return 1 if ma > mb else -1
    if pa is None and pb is None:
        return 0
    if pa is None:
        return 1  # release > pre-release
    if pb is None:
        return -1
    return (pa > pb) - (pa < pb)


_MAVEN_QUAL = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4,
               "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


def maven_compare(a: str, b: str) -> int:
    def key(v: str):
        parts = re.findall(r"\d+|[a-zA-Z]+", v.lower())
        nums, quals = [], []
        for p in parts:
            if p.isdigit() and not quals:
                nums.append(int(p))
            elif p.isdigit():
                quals.append((_MAVEN_QUAL.get("", 6), int(p)))
            else:
                quals.append((_MAVEN_QUAL.get(p, 0), 0))
        while nums and nums[-1] == 0:
            nums.pop()
        return nums, quals or [(6, 0)]
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


def pypi_compare(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        return semver_compare(a, b)


_CMP = {
    "deb": dpkg_compare,
    "rpm": rpm_compare,
    "apk": apk_compare,
    "pypi": pypi_compare,
    "npm": semver_compare,
    "go": semver_compare,
    "cargo": semver_compare,
    "gem": semver_compare,
    "nuget": semver_compare,
    "maven": maven_compare,
    "generic": semver_compare,
}


def compare(ecosystem: str, a: str, b: str) -> int:
    return _CMP.get(ecosystem, semver_compare)(a, b)


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    return sorted(versions, key=cmp_to_key(lambda x, y: compare(ecosystem, x, y)))


def upstream_version(ecosystem: str, version: str) -> str:
    """Strip epoch and distro revision so a distro version can be compared to upstream ranges."""
    v = version
    if ecosystem in ("deb", "rpm"):
        v = v.split(":", 1)[-1]
        v = v.rsplit("-", 1)[0]
        v = re.split(r"[+~](?:dfsg|deb|ubuntu|really)", v)[0]
    elif ecosystem == "apk":
        v = re.sub(r"-r\d+$", "", v)
    return v


# ---------------------------------------------------------------------------
# Ranges
# ---------------------------------------------------------------------------

_OP = re.compile(r"^\s*(<=|>=|<|>|==|=|!=)?\s*v?([^\s,<>=!]+)\s*$")


def _match_expr(ecosystem: str, version: str, expr: str) -> bool:
    """'>=1.0,<1.2' or '< 2.0' or '1.4.0' (exact)."""
    for clause in re.split(r"[,&]|\s+and\s+", expr):
        clause = clause.strip()
        if not clause or clause in ("*",):
            continue
        m = _OP.match(clause)
        if not m:
            raise ValueError(f"unparseable range clause {clause!r}")
        op, ref = m.group(1) or "==", m.group(2)
        c = compare(ecosystem, version, ref)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0, "=": c == 0, "!=": c != 0}[op]
        if not ok:
            return False
    return True


def in_range(ecosystem: str, version: str, rng: dict[str, str]) -> bool:
    """Evaluate one OSV-style event range ({'introduced','fixed'|'last_affected'}) or {'expr': ...}."""
    if "expr" in rng:
        return _match_expr(ecosystem, version, rng["expr"])
    intro = rng.get("introduced")
    if intro and intro != "0" and compare(ecosystem, version, intro) < 0:
        return False
    if rng.get("fixed"):
        return compare(ecosystem, version, rng["fixed"]) < 0
    if rng.get("last_affected"):
        return compare(ecosystem, version, rng["last_affected"]) <= 0
    if rng.get("limit"):
        return compare(ecosystem, version, rng["limit"]) < 0
    return bool(intro)  # introduced only -> all later versions affected


def is_vulnerable(ecosystem: str, version: str, ranges: list[dict[str, str]], fixed_versions: list[str] | None = None) -> bool | None:
    """True / False, or None when there's no usable range information."""
    try:
        if ranges:
            return any(in_range(ecosystem, version, r) for r in ranges)
        if fixed_versions:
            # vulnerable if below the lowest fixed version on the same "branch", else below all.
            fixed = sort_versions(ecosystem, fixed_versions)
            same_minor = [f for f in fixed if _branch(f, 2) == _branch(version, 2)]
            same_major = [f for f in fixed if _branch(f, 1) == _branch(version, 1)]
            branch = same_minor or same_major
            if branch:
                return compare(ecosystem, version, branch[0]) < 0
            # different branch than any fix: vulnerable only if older than the oldest fix
            return compare(ecosystem, version, fixed[0]) < 0
    except (ValueError, TypeError):
        return None
    return None


def _branch(v: str, n: int) -> tuple[str, ...]:
    v = v.split(":", 1)[-1].lstrip("vV")
    return tuple(re.split(r"[.\-]", v)[:n])
