"""Jailed filesystem access to a target root filesystem.

Every path is interpreted relative to the rootfs; symlinks (absolute or relative) are resolved
*inside* the rootfs, so `/etc/alternatives/x -> /usr/bin/y` works and nothing can escape to the host.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath

DEFAULT_SKIP_DIRS = {"proc", "sys", "dev", "run"}


class JailError(ValueError):
    pass


class Jail:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root).resolve()

    # -- path resolution --------------------------------------------------
    def resolve(self, path: str, follow_final: bool = True, _depth: int = 0) -> Path:
        if _depth > 40:
            raise JailError(f"too many symlink levels: {path}")
        parts = [p for p in PurePosixPath("/" + str(path).lstrip("/")).parts[1:]]
        cur: list[str] = []
        for i, part in enumerate(parts):
            if part in ("", "."):
                continue
            if part == "..":
                if cur:
                    cur.pop()
                continue
            cur.append(part)
            host = self.root.joinpath(*cur)
            is_last = i == len(parts) - 1
            if host.is_symlink() and (follow_final or not is_last):
                link = os.readlink(host)
                cur.pop()
                base = "/" if link.startswith("/") else "/" + "/".join(cur)
                rest = "/".join(parts[i + 1 :])
                new = str(PurePosixPath(base) / link / rest) if rest else str(PurePosixPath(base) / link)
                return self.resolve(new, follow_final, _depth + 1)
        p = self.root.joinpath(*cur) if cur else self.root
        # defence in depth
        rp = os.path.abspath(p)
        prefix = str(self.root).rstrip(os.sep) + os.sep  # root "/" must give "/", not "//"
        if rp != str(self.root) and not rp.startswith(prefix):
            raise JailError(f"path escapes rootfs: {path}")
        return p

    def rel(self, host_path: Path | str) -> str:
        r = os.path.relpath(host_path, self.root)
        return "/" if r == "." else "/" + r.replace(os.sep, "/")

    # -- walking ----------------------------------------------------------
    def walk(self, start: str = "/", skip_dirs: set[str] | None = None, max_files: int = 2_000_000):
        """Yield (rootfs_path, host_path, lstat) for files under start without following dir symlinks."""
        skip = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
        base = self.resolve(start)
        count = 0
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            if Path(dirpath) == self.root:
                dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                hp = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(hp)
                except OSError:
                    continue
                count += 1
                if count > max_files:
                    return
                yield "/" + os.path.relpath(hp, self.root).replace(os.sep, "/"), hp, st


# ---------------------------------------------------------------------------
# Tool implementations (pure functions, wrapped as LangChain tools in registry.py)
# ---------------------------------------------------------------------------


def _is_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk[:8192]


def read_file(jail: Jail, path: str, offset: int = 0, max_bytes: int = 48_000) -> str:
    p = jail.resolve(path)
    if not p.is_file():
        return f"not a regular file: {path}"
    with open(p, "rb") as f:
        f.seek(max(0, offset))
        data = f.read(max_bytes + 1)
    if _is_binary(data):
        return f"{path} is a binary file ({p.stat().st_size} bytes); use binary tools (elf_info, strings_search)."
    text = data[:max_bytes].decode("utf-8", errors="replace")
    more = len(data) > max_bytes
    return text + (f"\n...[more content; continue with offset={offset + max_bytes}]" if more else "")


def list_dir(jail: Jail, path: str = "/", max_entries: int = 400) -> list[dict]:
    p = jail.resolve(path)
    if not p.is_dir():
        return [{"error": f"not a directory: {path}"}]
    out = []
    for i, entry in enumerate(sorted(os.scandir(p), key=lambda e: e.name)):
        if i >= max_entries:
            out.append({"note": f"truncated at {max_entries} entries"})
            break
        st = entry.stat(follow_symlinks=False)
        item = {"name": entry.name, "type": "dir" if entry.is_dir(follow_symlinks=False) else
                "symlink" if entry.is_symlink() else "file", "size": st.st_size,
                "mode": stat.filemode(st.st_mode)}
        if entry.is_symlink():
            item["target"] = os.readlink(entry.path)
        out.append(item)
    return out


def glob_files(jail: Jail, pattern: str, start: str = "/", max_results: int = 500) -> list[str]:
    """fnmatch-style glob over full rootfs paths, e.g. '**/site-packages/*/METADATA' or '/usr/lib/**/libssl*'."""
    pat = pattern if pattern.startswith("/") else "/**/" + pattern
    rx = re.compile(_glob_to_regex(pat))
    out = []
    for rel, _hp, _st in jail.walk(start):
        if rx.match(rel):
            out.append(rel)
            if len(out) >= max_results:
                break
    return out


def _glob_to_regex(pat: str) -> str:
    i, n, res = 0, len(pat), ""
    while i < n:
        c = pat[i]
        if pat.startswith("**/", i):
            res += "(?:.*/)?"
            i += 3
            continue
        if pat.startswith("**", i):
            res += ".*"
            i += 2
            continue
        if c == "*":
            res += "[^/]*"
        elif c == "?":
            res += "[^/]"
        elif c == "[":
            j = pat.find("]", i)
            if j == -1:
                res += re.escape(c)
            else:
                res += "[" + pat[i + 1 : j].replace("!", "^", 1) + "]"
                i = j
        else:
            res += re.escape(c)
        i += 1
    return "^" + res + "$"


def grep(
    jail: Jail,
    pattern: str,
    path: str = "/",
    file_glob: str | None = None,
    ignore_case: bool = False,
    max_matches: int = 200,
    max_file_bytes: int = 5_000_000,
    include_binary: bool = False,
) -> list[dict]:
    """Regex search. Uses ripgrep if installed (fast, jailed by cwd + --no-follow), else pure Python."""
    base = jail.resolve(path)
    rg = shutil.which("rg")
    if rg and not include_binary:
        cmd = [rg, "-uu", "--no-follow", "--json", "-m", "20", "--max-filesize", f"{max_file_bytes}"]
        if ignore_case:
            cmd.append("-i")
        if file_glob:
            cmd += ["-g", file_glob]
        cmd += ["-e", pattern, str(base)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            import json

            out = []
            for line in proc.stdout.splitlines():
                ev = json.loads(line)
                if ev.get("type") != "match":
                    continue
                d = ev["data"]
                out.append({"path": jail.rel(d["path"]["text"]), "line": d["line_number"],
                            "text": d["lines"].get("text", "")[:400].rstrip()})
                if len(out) >= max_matches:
                    break
            return out
        except (subprocess.SubprocessError, ValueError):
            pass
    flags = re.I if ignore_case else 0
    rx = re.compile(pattern.encode(), flags)
    gl = re.compile(_glob_to_regex(file_glob if file_glob.startswith("/") else "/**/" + file_glob)) if file_glob else None
    out: list[dict] = []
    for rel, hp, st in jail.walk(jail.rel(base)):
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_file_bytes:
            continue
        if gl and not gl.match(rel):
            continue
        try:
            with open(hp, "rb") as f:
                data = f.read()
        except OSError:
            continue
        binary = _is_binary(data)
        if binary and not include_binary:
            continue
        if binary:
            if rx.search(data):
                out.append({"path": rel, "line": 0, "text": "(binary file matches)"})
        else:
            for ln, line in enumerate(data.splitlines(), 1):
                if rx.search(line):
                    out.append({"path": rel, "line": ln, "text": line[:400].decode("utf-8", "replace")})
                    if len(out) >= max_matches:
                        return out
        if len(out) >= max_matches:
            break
    return out


def file_info(jail: Jail, path: str) -> dict:
    p = jail.resolve(path, follow_final=False)
    if not p.exists() and not p.is_symlink():
        return {"path": path, "exists": False}
    st = os.lstat(p)
    info = {"path": path, "exists": True, "mode": stat.filemode(st.st_mode), "size": st.st_size}
    if p.is_symlink():
        info["symlink_to"] = os.readlink(p)
        try:
            info["resolves_to"] = jail.rel(jail.resolve(path))
        except JailError as e:
            info["resolves_to"] = f"error: {e}"
    return info
