"""Security-control inspection for containers (image config + rootfs) and hosts (system config files)."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .binaries import elf_info
from .fs import Jail

SHELLS = ("/bin/sh", "/bin/bash", "/bin/ash", "/bin/dash", "/usr/bin/bash", "/bin/busybox")
PKG_MANAGERS = ("/usr/bin/apt", "/usr/bin/apt-get", "/sbin/apk", "/usr/bin/dnf", "/usr/bin/yum", "/usr/bin/microdnf",
                "/usr/bin/rpm", "/usr/bin/pip", "/usr/bin/pip3", "/usr/bin/npm", "/usr/bin/zypper")
NET_TOOLS = ("/usr/bin/curl", "/usr/bin/wget", "/bin/nc", "/usr/bin/nc", "/usr/bin/ncat", "/usr/bin/socat")
COMPILERS = ("/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/clang", "/usr/bin/make", "/usr/local/go/bin/go")


def _text(p: Path) -> str:
    """File text, or "" when unreadable (host scans run unprivileged: sshd_config, sudoers... are root-only)."""
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def _exists(jail: Jail, p: str) -> bool:
    try:
        return jail.resolve(p).exists()
    except (ValueError, OSError):  # outside the jail, or unreadable parent dir (unprivileged host scan)
        return False


def image_config_summary(cfg: dict) -> dict:
    c = cfg.get("config") or cfg.get("Config") or {}
    env = c.get("Env") or []
    sensitive = [e.split("=", 1)[0] for e in env if re.search(r"(?i)(pass|secret|token|key|cred)", e.split("=", 1)[0])]
    return {
        "user": c.get("User") or "",
        "entrypoint": c.get("Entrypoint"),
        "cmd": c.get("Cmd"),
        "working_dir": c.get("WorkingDir"),
        "exposed_ports": sorted((c.get("ExposedPorts") or {}).keys()),
        "volumes": sorted((c.get("Volumes") or {}).keys()),
        "env": [e if e.split("=", 1)[0] not in sensitive else e.split("=", 1)[0] + "=<redacted>" for e in env][:80],
        "env_secret_like_vars": sensitive,
        "healthcheck": bool(c.get("Healthcheck")),
        "labels": dict(list((c.get("Labels") or {}).items())[:40]),
        "stop_signal": c.get("StopSignal"),
        "architecture": cfg.get("architecture"),
        "os": cfg.get("os"),
    }


def _passwd_users(jail: Jail) -> list[dict]:
    try:
        p = jail.resolve("/etc/passwd")
    except ValueError:
        return []
    if not p.is_file():
        return []
    users = []
    for line in _text(p).splitlines():
        f = line.split(":")
        if len(f) >= 7:
            users.append({"name": f[0], "uid": f[2], "shell": f[6]})
    return users


def inspect_security_controls(jail: Jail, image_config: dict | None = None, manifest_path: str | None = None,
                              kind: str = "container", sample_binaries: list[str] | None = None) -> dict:
    out: dict = {"kind": kind}
    cfg = image_config_summary(image_config or {}) if image_config else {}
    if cfg:
        out["image_config"] = cfg
        user = cfg["user"]
        out["runs_as_root"] = user in ("", "0", "root", "0:0") or user.startswith(("0:", "root:"))
    out["shell_present"] = [s for s in SHELLS if _exists(jail, s)]
    out["package_managers"] = [s for s in PKG_MANAGERS if _exists(jail, s)]
    out["network_tools"] = [s for s in NET_TOOLS if _exists(jail, s)]
    out["compilers"] = [s for s in COMPILERS if _exists(jail, s)]
    out["distroless_like"] = not out["shell_present"] and not out["package_managers"]
    users = _passwd_users(jail)
    out["users_with_login_shell"] = [u["name"] for u in users if not u["shell"].endswith(("nologin", "false"))][:30]

    if manifest_path and Path(manifest_path).exists():
        m = json.loads(Path(manifest_path).read_text())
        out["setuid_binaries"] = m.get("setuid", [])[:100]
        out["setgid_binaries"] = m.get("setgid", [])[:100]
        out["file_capabilities"] = m.get("capabilities", [])[:100]
        out["world_writable_files"] = m.get("world_writable", [])[:50]
    else:
        suid, sgid = [], []
        for rel, _hp, st in jail.walk("/"):
            if stat.S_ISREG(st.st_mode):
                if st.st_mode & stat.S_ISUID:
                    suid.append(rel)
                if st.st_mode & stat.S_ISGID:
                    sgid.append(rel)
            if len(suid) + len(sgid) > 300:
                break
        out["setuid_binaries"], out["setgid_binaries"] = suid, sgid

    # MAC / kernel hardening hints (mostly meaningful for hosts)
    mac = {}
    if _exists(jail, "/etc/selinux/config"):
        txt = _text(jail.resolve("/etc/selinux/config"))
        m = re.search(r"^SELINUX=(\w+)", txt, re.M)
        mac["selinux"] = m.group(1) if m else "configured"
    if _exists(jail, "/etc/apparmor.d"):
        mac["apparmor_profiles"] = len(list(jail.resolve("/etc/apparmor.d").glob("*")))
    if mac:
        out["mac"] = mac
    sysctl = {}
    for d in ("/etc/sysctl.conf", "/etc/sysctl.d", "/usr/lib/sysctl.d"):
        if not _exists(jail, d):
            continue
        hp = jail.resolve(d)
        files = [hp] if hp.is_file() else sorted(hp.glob("*.conf"))
        for f in files:
            for line in _text(f).splitlines():
                m = re.match(r"\s*([\w.]+)\s*=\s*(\S+)", line)
                if m and any(k in m.group(1) for k in ("randomize_va_space", "kptr_restrict", "dmesg_restrict",
                                                         "unprivileged_bpf", "ptrace_scope", "unprivileged_userns")):
                    sysctl[m.group(1)] = m.group(2)
    if sysctl:
        out["sysctl"] = sysctl
    if _exists(jail, "/etc/ssh/sshd_config"):
        txt = _text(jail.resolve("/etc/ssh/sshd_config"))
        out["sshd"] = {k: v for k, v in re.findall(r"^\s*(PermitRootLogin|PasswordAuthentication|Port)\s+(\S+)", txt, re.M)}
    fw = [p for p in ("/etc/nftables.conf", "/etc/iptables/rules.v4", "/etc/firewalld/zones", "/etc/ufw/ufw.conf")
          if _exists(jail, p)]
    if fw:
        out["firewall_config"] = fw

    if sample_binaries:
        out["binary_hardening"] = {}
        for b in sample_binaries[:10]:
            info = elf_info(jail, b, max_symbols=2000)
            if info.get("elf"):
                out["binary_hardening"][b] = info.get("hardening")
    return out


def systemd_units(jail: Jail, max_units: int = 80) -> list[dict]:
    units = []
    for d in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"):
        if not _exists(jail, d):
            continue
        wanted = set()
        etc = jail.resolve("/etc/systemd/system")
        if etc.is_dir():
            for w in etc.glob("*.wants/*.service"):
                wanted.add(w.name)
        for f in sorted(jail.resolve(d).glob("*.service")):
            if not f.is_file():
                continue
            txt = _text(f)
            m = re.search(r"^ExecStart=(.+)$", txt, re.M)
            if m and (d == "/etc/systemd/system" or f.name in wanted):
                units.append({"unit": f.name, "exec": m.group(1).strip(), "enabled": f.name in wanted or d.startswith("/etc"),
                              "user": (re.search(r"^User=(.+)$", txt, re.M) or [None, ""])[1]})
            if len(units) >= max_units:
                return units
    return units


def listening_config_hints(jail: Jail) -> list[dict]:
    """Grep common server configs for listen/bind directives (static view of network exposure)."""
    patterns = {
        "/etc/nginx": r"^\s*listen\s+[^;]+;",
        "/etc/apache2": r"^\s*Listen\s+\S+",
        "/etc/httpd": r"^\s*Listen\s+\S+",
        "/etc/redis": r"^\s*(bind|port)\s+.+",
        "/etc/postgresql": r"^\s*listen_addresses\s*=.+",
        "/etc/mysql": r"^\s*(bind-address|port)\s*=.+",
        "/etc/ssh/sshd_config": r"^\s*(Port|ListenAddress)\s+\S+",
    }
    out = []
    for base, rx in patterns.items():
        if not _exists(jail, base):
            continue
        hp = jail.resolve(base)
        files = [hp] if hp.is_file() else [p for p in hp.rglob("*") if p.is_file() and not p.is_symlink()]
        for f in files[:200]:
            try:
                for m in re.finditer(rx, _text(f), re.M):
                    out.append({"file": jail.rel(f), "directive": m.group(0).strip()})
            except OSError:
                continue
    return out[:100]


def env_value(image_config: dict, name: str) -> str | None:
    for e in ((image_config.get("config") or image_config.get("Config") or {}).get("Env") or []):
        if e.split("=", 1)[0] == name:
            return e.split("=", 1)[1] if "=" in e else ""
    return None
