"""Read-only probes against the *running* target (container via docker/podman exec, or the local host).

Safety model — every probe is bounded so live verification cannot change the target:
* commands run without a shell, and the joined argv must fully match one regex in `live_probes.allowlist`
  (read-only inspection commands); paths that look like secret stores are refused even when a pattern matches;
* network probes only connect to the target's own addresses (from `docker inspect`, or loopback for `local`) and
  send benign requests (HTTP GET/HEAD/OPTIONS, an HTTP/2 preface, a TLS handshake) — never payloads or floods;
* credentials are used only if listed in `live_probes.default_credentials` (well-known defaults to test for);
  the model names the user, the password is filled in here and never echoed;
* output is truncated and secrets are redacted; every probe is logged verbatim into the report for audit.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import re
import shlex
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import Iterator
import httpx
from langchain_core.tools import BaseTool, StructuredTool

from ..config import LiveProbeSettings
from ..models import ProbeRecord, RuntimeSpec

_SECRET_KV = re.compile(
    r"(?i)((?:[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|cookie|private[_-]?key|credential)s?[\w.-]*)"
    r"[\"'>]*\s*(?:[:=]|,\s*<<|=>)\s*[\"'<]*)([^\s\"',}>]+)")
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_SECRET_PATH = re.compile(r"(?i)(shadow|gshadow|\.erlang\.cookie|secret|token|id_rsa|id_ed25519|\.pem$|\.key$|"
                          r"credentials|\.netrc|\.pgpass|/proc/\d+/environ|/proc/self/environ)")
_HDRS = ("server", "www-authenticate", "content-type", "location", "upgrade", "alt-svc", "connection",
         "strict-transport-security", "x-frame-options", "content-security-policy")


def redact(text: str) -> str:
    text = _PEM.sub("[REDACTED PRIVATE KEY]", text)
    return _SECRET_KV.sub(lambda m: m.group(1) + "***", text)


class ProbeRefused(Exception):
    pass


_PROBE_SINK: contextvars.ContextVar[list | None] = contextvars.ContextVar("vulnlens_probe_sink", default=None)


@dataclass
class LiveTarget:
    spec: RuntimeSpec
    cfg: LiveProbeSettings
    probes: list[ProbeRecord] = field(default_factory=list)
    _inspect: dict | None = None
    _patterns: list[re.Pattern] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._patterns = [re.compile(p) for p in self.cfg.allowlist]
        if self.spec.engine != "local" and not self.spec.container:
            raise ValueError("target.runtime.container is required for docker/podman")

    # -- bookkeeping ---------------------------------------------------------------------------------------------

    def _log(self, tool: str, args: dict, ok: bool, output: str) -> str:
        output = redact(output)[: self.cfg.max_output_chars]
        rec = ProbeRecord(tool=tool, args=args, ok=ok, output=output)
        self.probes.append(rec)
        sink = _PROBE_SINK.get()
        if sink is not None:  # per-verification log (several verifications run concurrently)
            sink.append(rec)
        return output

    @contextlib.contextmanager
    def recording(self) -> Iterator[list[ProbeRecord]]:
        """Collect only the probes made inside this block (and the tool threads it starts)."""
        sink: list[ProbeRecord] = []
        tok = _PROBE_SINK.set(sink)
        try:
            yield sink
        finally:
            _PROBE_SINK.reset(tok)

    # -- inspect -------------------------------------------------------------------------------------------------

    def _cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([self.spec.engine, *args], capture_output=True, text=True,
                              timeout=self.cfg.timeout, check=False)

    def inspect(self) -> dict:
        if self._inspect is not None:
            return self._inspect
        if self.spec.engine == "local":
            self._inspect = {"engine": "local", "addresses": ["127.0.0.1"]}
            return self._inspect
        r = self._cli("inspect", self.spec.container)
        if r.returncode != 0:
            raise RuntimeError(f"{self.spec.engine} inspect failed: {r.stderr.strip()[:300]}")
        self._inspect = digest_inspect(json.loads(r.stdout)[0])
        for net in self._inspect.get("networks", {}):
            n = self._cli("network", "inspect", net, "--format", "{{json .Containers}}")
            if n.returncode == 0 and n.stdout.strip() not in ("", "null"):
                names = sorted(c.get("Name", "") for c in json.loads(n.stdout).values())
                peers = [x for x in names if x and x != self._inspect.get("name")]
                self._inspect["networks"][net]["peer_containers"] = peers[:60]
                self._inspect["networks"][net]["peer_count"] = len(peers)
        return self._inspect

    def addresses(self) -> list[str]:
        return self.inspect().get("addresses") or []

    # -- probes --------------------------------------------------------------------------------------------------

    def allowed(self, argv: list[str]) -> bool:
        joined = shlex.join(argv)
        if any(_SECRET_PATH.search(a) for a in argv[1:]):
            return False
        return any(p.fullmatch(joined) for p in self._patterns)

    def run_command(self, command: str) -> str:
        args = {"command": command}
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return self._log("run_command", args, False, f"REFUSED: unparsable command ({e})")
        if not argv or not self.allowed(argv):
            return self._log("run_command", args, False,
                             "REFUSED: command is not on the read-only allowlist (see allowed_commands)")
        full = argv if self.spec.engine == "local" else [self.spec.engine, "exec", self.spec.container, *argv]
        try:
            r = subprocess.run(full, capture_output=True, text=True, timeout=self.cfg.timeout, check=False)
        except subprocess.TimeoutExpired:
            return self._log("run_command", args, False, f"ERROR: timed out after {self.cfg.timeout}s")
        except FileNotFoundError as e:
            return self._log("run_command", args, False, f"ERROR: {e}")
        out = f"exit={r.returncode}\n{r.stdout}" + (f"\n[stderr]\n{r.stderr}" if r.stderr.strip() else "")
        return self._log("run_command", args, r.returncode == 0, out)

    def _host(self, port: int) -> str:
        if not 0 < int(port) < 65536:
            raise ProbeRefused("port out of range")
        addrs = self.addresses()
        if not addrs:
            raise ProbeRefused("target has no reachable IP address (no bridge network?)")
        return addrs[0]

    def tcp_connect(self, port: int) -> str:
        args = {"port": port}
        try:
            host = self._host(port)
            with socket.create_connection((host, int(port)), timeout=self.cfg.connect_timeout) as s:
                s.settimeout(1.5)
                try:
                    banner = s.recv(256)
                except (socket.timeout, OSError):
                    banner = b""
            txt = banner.decode("latin-1")
            printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in txt)
            return self._log("tcp_connect", args, True, f"{host}:{port} open; banner={printable!r}")
        except ProbeRefused as e:
            return self._log("tcp_connect", args, False, f"REFUSED: {e}")
        except OSError as e:
            return self._log("tcp_connect", args, True, f"{port} closed/filtered: {e}")

    def http_request(self, port: int, path: str = "/", method: str = "GET", scheme: str = "http",
                     default_user: str = "") -> str:
        args = {"port": port, "path": path, "method": method, "scheme": scheme, "default_user": default_user}
        try:
            method = method.upper()
            if method not in ("GET", "HEAD", "OPTIONS"):
                raise ProbeRefused("only GET, HEAD and OPTIONS are allowed")
            if scheme not in ("http", "https"):
                raise ProbeRefused("scheme must be http or https")
            if not path.startswith("/") or "://" in path:
                raise ProbeRefused("path must be an absolute path on the target")
            auth = None
            if default_user:
                creds = dict(c.split(":", 1) for c in self.cfg.default_credentials if ":" in c)
                if default_user not in creds:
                    raise ProbeRefused("user is not in live_probes.default_credentials")
                auth = (default_user, creds[default_user])
            host = self._host(port)
            with httpx.Client(timeout=self.cfg.timeout, verify=False, follow_redirects=False) as c:
                r = c.request(method, f"{scheme}://{host}:{int(port)}{path}", auth=auth)
            hdrs = {k: v for k, v in r.headers.items() if k.lower() in _HDRS}
            body = r.text[:1500] if method != "HEAD" else ""
            return self._log("http_request", args, True,
                             f"{r.http_version} {r.status_code}\nheaders={json.dumps(hdrs)}\nbody={body}")
        except ProbeRefused as e:
            return self._log("http_request", args, False, f"REFUSED: {e}")
        except httpx.HTTPError as e:
            return self._log("http_request", args, True, f"connection error: {type(e).__name__}: {e}")

    def http2_cleartext_probe(self, port: int) -> str:
        """Send the HTTP/2 connection preface + an empty SETTINGS frame; report whether the server speaks h2c."""
        args = {"port": port}
        try:
            host = self._host(port)
            with socket.create_connection((host, int(port)), timeout=self.cfg.connect_timeout) as s:
                s.settimeout(3)
                s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
                data = s.recv(64)
            if len(data) >= 9 and data[3] == 0x04:
                res = f"h2c ACCEPTED: server answered with an HTTP/2 SETTINGS frame ({int.from_bytes(data[:3], 'big')} bytes)"
            elif data.startswith(b"HTTP/1"):
                res = f"h2c REJECTED: server answered HTTP/1.x: {data[:40]!r}"
            else:
                res = f"h2c not confirmed: first bytes {data[:16]!r}"
            return self._log("http2_cleartext_probe", args, True, res)
        except ProbeRefused as e:
            return self._log("http2_cleartext_probe", args, False, f"REFUSED: {e}")
        except OSError as e:
            return self._log("http2_cleartext_probe", args, True, f"connection error: {e}")

    def _raw_http(self, host: str, port: int, request: bytes, limit: int = 4096) -> bytes:
        with socket.create_connection((host, int(port)), timeout=self.cfg.connect_timeout) as s:
            s.settimeout(min(self.cfg.timeout, 8))
            s.sendall(request)
            data = b""
            try:
                while len(data) < limit and b"\r\n\r\n" not in data:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
        return data

    @staticmethod
    def _head(data: bytes) -> tuple[str, dict[str, str]]:
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
        hdrs = {}
        for line in head[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() in _HDRS:
                    hdrs[k.strip().lower()] = v.strip()[:200]
        return head[0] if head else "", hdrs

    def h2c_upgrade_probe(self, port: int, path: str = "/") -> str:
        """HTTP/1.1 request offering `Upgrade: h2c` (RFC 7540 3.2). 101 = the server would switch to cleartext
        HTTP/2; anything else = h2c upgrade not enabled. Only the handshake is sent, no HTTP/2 frames."""
        args = {"port": port, "path": path}
        try:
            if not path.startswith("/") or "://" in path or any(c in path for c in "\r\n "):
                raise ProbeRefused("path must be an absolute path on the target")
            host = self._host(port)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{int(port)}\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                   f"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nUser-Agent: vulnlens-probe\r\n\r\n")
            status, hdrs = self._head(self._raw_http(host, port, req.encode()))
            if " 101 " in f"{status} ":
                res = f"h2c upgrade ACCEPTED: {status}; headers={json.dumps(hdrs)}"
            elif status.startswith("HTTP/"):
                adv = hdrs.get("upgrade", "")
                res = (f"h2c upgrade NOT accepted: {status}; Upgrade header advertised={adv or 'none'}"
                       f"{' (server advertises h2c: it may be enabled for other hosts/paths)' if 'h2c' in adv else ''}")
            else:
                res = f"no HTTP/1.x answer: {status[:80]!r}"
            return self._log("h2c_upgrade_probe", args, True, res)
        except ProbeRefused as e:
            return self._log("h2c_upgrade_probe", args, False, f"REFUSED: {e}")
        except OSError as e:
            return self._log("h2c_upgrade_probe", args, True, f"connection error: {e}")

    def header_limit_probe(self, port: int, size: int = 8300, path: str = "/") -> str:
        """Measure the effective request-header-field size limit (e.g. Apache LimitRequestFieldSize) with ONE GET
        that carries a padding header line `X-Vulnlens-Limit-Probe: aaa…` of exactly `size` bytes (CRLF not counted). The padding header is not
        interpreted by any application or module (it is deliberately not Host), so the request tests only the
        server's header parser. 400 = the field exceeds the limit; 2xx/3xx/403/404 = a field of that size is
        accepted. Call with sizes just below and above a claimed limit to bracket it."""
        args = {"port": port, "size": size, "path": path}
        try:
            size = int(size)
            if not 256 <= size <= 65536:
                raise ProbeRefused("size must be between 256 and 65536 bytes")
            if not path.startswith("/") or "://" in path or any(c in path for c in "\r\n "):
                raise ProbeRefused("path must be an absolute path on the target")
            host = self._host(port)
            name = "X-Vulnlens-Limit-Probe"
            val = "a" * max(1, size - len(name) - 2)  # whole field line "Name: value" == size bytes
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{int(port)}\r\n{name}: {val}\r\n"
                   f"User-Agent: vulnlens-probe\r\nConnection: close\r\n\r\n").encode()
            data = self._raw_http(host, port, req, limit=8192)
            status, hdrs = self._head(data)
            body = data.split(b"\r\n\r\n", 1)[1][:400].decode("latin-1", "replace") if b"\r\n\r\n" in data else ""
            hint = re.sub(r"<[^>]+>", " ", body)
            hint = " ".join(hint.split())[:200]
            code = status.split(" ")[1] if status.startswith("HTTP/") and len(status.split(" ")) > 1 else ""
            verdict = ("REJECTED (field exceeds the server limit)" if code == "400" else
                       f"ACCEPTED (a {size}-byte field passes the header parser)" if code else "no HTTP answer")
            return self._log("header_limit_probe", args, True,
                             f"{size}-byte header field: {verdict}; {status}; server={hdrs.get('server', '?')}; "
                             f"body: {hint}")
        except ProbeRefused as e:
            return self._log("header_limit_probe", args, False, f"REFUSED: {e}")
        except OSError as e:
            return self._log("header_limit_probe", args, True, f"connection error: {e}")

    def tls_probe(self, port: int) -> str:
        args = {"port": port}
        try:
            host = self._host(port)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, int(port)), timeout=self.cfg.connect_timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    res = f"TLS ok: version={s.version()} cipher={s.cipher()[0]} alpn={s.selected_alpn_protocol()}"
            return self._log("tls_probe", args, True, res)
        except ProbeRefused as e:
            return self._log("tls_probe", args, False, f"REFUSED: {e}")
        except (OSError, ssl.SSLError) as e:
            return self._log("tls_probe", args, True, f"no TLS handshake: {type(e).__name__}: {e}")


def digest_inspect(d: dict) -> dict:
    """Keep the security-relevant parts of `docker inspect`; environment *names* only, never values."""
    cfg, host, ns = d.get("Config") or {}, d.get("HostConfig") or {}, d.get("NetworkSettings") or {}
    nets = {name: {"ip": n.get("IPAddress"), "aliases": (n.get("Aliases") or [])[:10]}
            for name, n in (ns.get("Networks") or {}).items()}
    published = {p: [f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}" for b in (bs or [])]
                 for p, bs in (ns.get("Ports") or {}).items()}
    return {
        "name": (d.get("Name") or "").lstrip("/"),
        "image": cfg.get("Image"),
        "state": (d.get("State") or {}).get("Status"),
        "user": cfg.get("User") or "root (image default)",
        "privileged": host.get("Privileged"),
        "read_only_rootfs": host.get("ReadonlyRootfs"),
        "cap_add": host.get("CapAdd"), "cap_drop": host.get("CapDrop"),
        "security_opt": host.get("SecurityOpt"),
        "network_mode": host.get("NetworkMode"), "pid_mode": host.get("PidMode") or "",
        "exposed_ports": sorted((cfg.get("ExposedPorts") or {}).keys()),
        "published_ports": {p: b for p, b in published.items() if b},
        "networks": nets,
        "addresses": [n["ip"] for n in nets.values() if n.get("ip")],
        "mounts": [{"type": m.get("Type"), "destination": m.get("Destination"), "rw": m.get("RW")}
                   for m in d.get("Mounts") or []],
        "env_names": sorted(e.split("=", 1)[0] for e in cfg.get("Env") or []),
        "restart_policy": (host.get("RestartPolicy") or {}).get("Name"),
    }


def runtime_tools(live: LiveTarget) -> list[BaseTool]:
    users = ", ".join(c.split(":", 1)[0] for c in live.cfg.default_credentials)
    def runtime_facts() -> str:
        """Security-relevant runtime facts: user, privileges, capabilities, networks, peer containers, published
        ports, mounts and environment variable names (values withheld)."""
        try:
            return json.dumps(live.inspect(), default=str)[:12000]
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    def allowed_commands() -> str:
        """Regexes a command must fully match to be run by run_command."""
        return "\n".join(live.cfg.allowlist)

    def run_command(command: str) -> str:
        """Run one read-only command inside the running target (no shell, no pipes). It must match the
        allowlist (call allowed_commands first). Output is redacted and truncated."""
        return live.run_command(command)

    def tcp_connect(port: int) -> str:
        """TCP connect to a port on the target's own address; reports open/closed and any banner."""
        return live.tcp_connect(port)

    def http_request(port: int, path: str = "/", method: str = "GET", scheme: str = "http",
                     default_user: str = "") -> str:
        return live.http_request(port, path, method, scheme, default_user)
    http_request.__doc__ = (f"Benign GET/HEAD/OPTIONS to the target. Set default_user to log in with that account's "
                            f"well-known default password (configured users: {users or 'none'}) to test whether "
                            f"defaults are accepted.")

    def http2_cleartext_probe(port: int) -> str:
        """Check whether a cleartext port negotiates HTTP/2 (h2c prior knowledge) by sending only the
        connection preface and an empty SETTINGS frame."""
        return live.http2_cleartext_probe(port)

    def tls_probe(port: int) -> str:
        """Attempt a TLS handshake; reports protocol version, cipher and ALPN or that the port is plaintext."""
        return live.tls_probe(port)

    def h2c_upgrade_probe(port: int, path: str = "/") -> str:
        return live.h2c_upgrade_probe(port, path)
    h2c_upgrade_probe.__doc__ = LiveTarget.h2c_upgrade_probe.__doc__

    def header_limit_probe(port: int, size: int = 8300, path: str = "/") -> str:
        return live.header_limit_probe(port, size, path)
    header_limit_probe.__doc__ = LiveTarget.header_limit_probe.__doc__

    fns = [runtime_facts, allowed_commands, run_command, tcp_connect, http_request, http2_cleartext_probe,
           h2c_upgrade_probe, header_limit_probe, tls_probe]
    return [StructuredTool.from_function(f) for f in fns]


__all__ = ["LiveTarget", "runtime_tools", "redact", "digest_inspect"]
