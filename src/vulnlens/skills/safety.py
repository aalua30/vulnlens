"""Guards for learned skills. A playbook is text that later runs put into a system prompt, so it is an injection and
data-leak surface: everything the reflector proposes is scrubbed of host data and scanned before it is staged.

* ``scrub``: removes IPs, hostnames / target names of the source run, e-mails, home-directory user names and
  anything that looks like a credential, so skills generalize and never carry inventory or secrets.
* ``scan``: rejects prompt-injection phrasing, unconditional verdict prescriptions, URLs outside known advisory
  sources, shell commands that are not read-only, and oversized text.
"""

from __future__ import annotations

import re
from typing import Iterable

from .store import Skill

SECRET_PATTERNS = [
    re.compile(r"\btvly-[A-Za-z0-9_-]{16,}"),                       # Tavily
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),                         # OpenAI / DeepSeek / Anthropic style
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),                    # GitHub
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                            # AWS
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),  # JWT
    re.compile(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{12,}\b"),              # Z.ai id.secret
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(pass(word)?|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{6,}"),
]
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_HOME = re.compile(r"/home/[A-Za-z0-9._-]+")
_LOOPBACK = {"127.0.0.1", "0.0.0.0"}

ADVISORY_DOMAINS = ("nvd.nist.gov", "cve.org", "cve.mitre.org", "osv.dev", "github.com/advisories",
                    "httpd.apache.org", "security-tracker.debian.org", "ubuntu.com/security", "access.redhat.com",
                    "bodhi.fedoraproject.org", "security.alpinelinux.org", "cwe.mitre.org")

_INJECTION = [
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"disregard (the |all |your )?(system|previous|above|instructions|rules)",
    r"\byou are now\b", r"\bnew instructions\b", r"system prompt", r"\bjailbreak\b",
    r"do not (use|call) (any )?tools", r"(skip|bypass|disable) (the )?(live )?(verification|probes?|checks?|jail|allowlist)",
    r"without (checking|verifying|evidence)", r"(exfiltrate|send|post|upload) .{0,40}(to|at) https?://",
]
_PRESCRIBE = re.compile(
    r"(?i)\b(always|must|should always|unconditionally)\b.{0,40}\b(return|answer|conclude|report|set|mark|output|"
    r"classify)\b.{0,40}\b(not_affected|affected|not_applicable|not_reachable|environment_isolated|mitigated|"
    r"exploitable|code_not_present|code_not_reachable)\b")
_URL = re.compile(r"https?://[^\s)>\]'\"]+")
_SHELL = re.compile(
    r"(?im)^\s*(?:\$\s*)?(rm|curl|wget|nc|ncat|bash|sh|zsh|chmod|chown|sudo|su|dd|mkfs|kill|pkill|systemctl\s+(?:stop|"
    r"start|restart|disable|enable|mask)|docker\s+(?:run|exec|rm|stop|kill)|podman\s+(?:run|exec|rm)|python3?\s+-c|"
    r"perl\s+-e|eval|exec)\b")

MAX_BODY = 4000
MAX_DESCRIPTION = 300


def scrub(text: str, extra_terms: Iterable[str] = ()) -> str:
    out = text or ""
    for pat in SECRET_PATTERNS:
        out = pat.sub("<redacted-secret>", out)
    out = _EMAIL.sub("<email>", out)
    out = _IPV4.sub(lambda m: m.group(0) if m.group(0) in _LOOPBACK else "<ip>", out)
    out = _IPV6.sub("<ip>", out)
    out = _HOME.sub("/home/<user>", out)
    for term in sorted({t for t in extra_terms if t and len(t) >= 3}, key=len, reverse=True):
        out = re.sub(re.escape(term), "<target>", out, flags=re.I)
    return out


def scrub_skill(sk: Skill, extra_terms: Iterable[str] = ()) -> Skill:
    terms = list(extra_terms)
    sk.description = scrub(sk.description, terms)
    sk.body = scrub(sk.body, terms)
    sk.tags = [scrub(t, terms) for t in sk.tags]
    return sk


def scan(sk: Skill) -> list[str]:
    """Reasons to reject the skill (empty list = acceptable)."""
    text = f"{sk.description}\n{sk.body}"
    issues = []
    for pat in _INJECTION:
        if re.search(pat, text, re.I):
            issues.append(f"prompt-injection phrasing: /{pat}/")
    if _PRESCRIBE.search(text):
        issues.append("prescribes a verdict unconditionally (playbooks may guide checks, never fix outcomes)")
    for url in _URL.findall(text):
        if not any(d in url for d in ADVISORY_DOMAINS):
            issues.append(f"URL outside known advisory sources: {url[:120]}")
    if _SHELL.search(sk.body):
        issues.append("contains a shell command that is not read-only")
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            issues.append("looks like it contains a credential")
            break
    if len(sk.body) > MAX_BODY:
        issues.append(f"body too long ({len(sk.body)} > {MAX_BODY} chars)")
    if len(sk.description) > MAX_DESCRIPTION:
        issues.append(f"description too long ({len(sk.description)} > {MAX_DESCRIPTION} chars)")
    if not sk.description.strip() or not sk.body.strip():
        issues.append("empty description or body")
    return issues
