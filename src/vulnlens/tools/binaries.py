"""Binary analysis: ELF metadata/dependencies/symbols, shared-library discovery, Go build info, strings."""

from __future__ import annotations

import mmap
import os
import re
import stat
from dataclasses import asdict, dataclass, field

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .fs import Jail

ELF_MAGIC = b"\x7fELF"
GO_MAGIC = b"\xff Go buildinf:"

# Well-known embedded version banners -> (library, regex)
VERSION_BANNERS = [
    ("openssl", rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)"),
    ("zlib", rb"(?:deflate|inflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright"),
    ("curl", rb"libcurl/(\d+\.\d+\.\d+)"),
    ("sqlite", rb"SQLite version (\d+\.\d+\.\d+)"),
    ("libxml2", rb"libxml2-(\d+\.\d+\.\d+)"),
    ("glibc", rb"GNU C Library \([^)]*\) (?:stable )?release version (\d+\.\d+)"),
    ("expat", rb"expat_(\d+\.\d+\.\d+)"),
    ("libpng", rb"libpng version (\d+\.\d+\.\d+)"),
    ("pcre2", rb"PCRE2 (\d+\.\d+)"),
    ("nginx", rb"nginx/(\d+\.\d+\.\d+)"),
    ("busybox", rb"BusyBox v(\d+\.\d+\.\d+)"),
]


def is_elf(host_path: str) -> bool:
    try:
        with open(host_path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


def elf_info(jail: Jail, path: str, max_symbols: int = 400, symbol_filter: str | None = None) -> dict:
    hp = jail.resolve(path)
    if not is_elf(str(hp)):
        return {"path": path, "elf": False}
    out: dict = {"path": path, "elf": True}
    rx = re.compile(symbol_filter) if symbol_filter else None
    try:
        with open(hp, "rb") as f:
            elf = ELFFile(f)
            out["type"] = elf.header["e_type"]
            out["machine"] = elf.header["e_machine"]
            needed, rpath = [], []
            flags_bind_now = False
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_INTERP":
                    out["interpreter"] = seg.get_interp_name()
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for t in sec.iter_tags():
                        if t.entry.d_tag == "DT_NEEDED":
                            needed.append(t.needed)
                        elif t.entry.d_tag == "DT_SONAME":
                            out["soname"] = t.soname
                        elif t.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                            rpath.append(getattr(t, "rpath", None) or getattr(t, "runpath", ""))
                        elif t.entry.d_tag == "DT_FLAGS" and t.entry.d_val & 0x8:
                            flags_bind_now = True
                        elif t.entry.d_tag == "DT_FLAGS_1" and t.entry.d_val & 0x1:
                            flags_bind_now = True
            out["needed"] = needed
            if rpath:
                out["rpath"] = rpath
            imported, exported = [], []
            static_syms = 0
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                dyn = sec.name == ".dynsym"
                for sym in sec.iter_symbols():
                    name = sym.name
                    if not name or (rx and not rx.search(name)):
                        continue
                    if not dyn:
                        static_syms += 1
                        if rx and len(exported) < max_symbols:
                            exported.append(name)
                        continue
                    if sym["st_shndx"] == "SHN_UNDEF":
                        if len(imported) < max_symbols:
                            imported.append(name)
                    elif len(exported) < max_symbols:
                        exported.append(name)
            out["imported_symbols"] = imported
            out["exported_symbols"] = exported
            out["has_static_symtab"] = static_syms > 0
            out["hardening"] = _hardening(elf, imported + exported, flags_bind_now)
            out["is_go"] = elf.get_section_by_name(".go.buildinfo") is not None
    except (ELFError, OSError, ValueError) as e:
        out["error"] = str(e)
    return out


def _hardening(elf: ELFFile, syms: list[str], bind_now: bool) -> dict:
    pie = elf.header["e_type"] == "ET_DYN" and any(s.header.p_type == "PT_INTERP" for s in elf.iter_segments())
    nx, relro = True, "none"
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            nx = not (seg.header.p_flags & 0x1)
        if seg.header.p_type == "PT_GNU_RELRO":
            relro = "partial"
    if relro == "partial" and bind_now:
        relro = "full"
    return {
        "pie": pie,
        "nx": nx,
        "relro": relro,
        "stack_canary": "__stack_chk_fail" in syms,
        "fortify": any(s.endswith("_chk") and s.startswith("__") for s in syms),
        "cfi_cet": False,  # would need .note.gnu.property parsing; reported conservatively
    }


def find_symbol_users(jail: Jail, symbol_regex: str, start: str = "/", max_results: int = 100) -> list[dict]:
    """Find ELF files that import or define symbols matching a regex (e.g. 'BIO_new_|SSL_read')."""
    rx = re.compile(symbol_regex)
    out = []
    for rel, hp, st in jail.walk(start):
        if not stat.S_ISREG(st.st_mode) or st.st_size < 64 or st.st_size > 300_000_000 or not is_elf(hp):
            continue
        try:
            with open(hp, "rb") as f:
                elf = ELFFile(f)
                sec = elf.get_section_by_name(".dynsym")
                if not sec:
                    continue
                imp, exp = [], []
                for sym in sec.iter_symbols():
                    if sym.name and rx.search(sym.name):
                        (imp if sym["st_shndx"] == "SHN_UNDEF" else exp).append(sym.name)
                if imp or exp:
                    out.append({"path": rel, "imports": imp[:30], "defines": exp[:30]})
        except (ELFError, OSError, ValueError):
            continue
        if len(out) >= max_results:
            break
    return out


def strings_search(jail: Jail, path: str, regex: str, max_matches: int = 50, min_len: int = 4) -> list[str]:
    hp = jail.resolve(path)
    rx = re.compile(regex.encode())
    out: list[str] = []
    with open(hp, "rb") as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return []
        try:
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, mm):
                s = m.group(0)
                if rx.search(s):
                    out.append(s[:300].decode("ascii", "replace"))
                    if len(out) >= max_matches:
                        break
        finally:
            mm.close()
    return out


def embedded_versions(host_path: str, max_bytes: int = 64_000_000) -> dict[str, str]:
    found: dict[str, str] = {}
    try:
        with open(host_path, "rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return found
    for lib, rx in VERSION_BANNERS:
        m = re.search(rx, data)
        if m:
            found[lib] = m.group(1).decode()
    return found


# ---------------------------------------------------------------------------
# Shared libraries
# ---------------------------------------------------------------------------

LIB_DIRS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64", "/opt")
_SO_RX = re.compile(r"^(lib[\w+\-]+?)\.so(?:\.(\d[\d.]*))?$|^(lib[\w+\-]+?)-(\d[\d.]*)\.so$")


@dataclass
class SharedLib:
    path: str
    name: str
    version: str = ""
    soname: str = ""
    embedded: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


def shared_libraries(jail: Jail, dirs: tuple[str, ...] = LIB_DIRS, name_filter: str | None = None,
                     with_banners: bool = True) -> list[SharedLib]:
    out: list[SharedLib] = []
    rx = re.compile(name_filter) if name_filter else None
    seen_real: set[str] = set()
    for d in dirs:
        try:
            base = jail.resolve(d)
        except ValueError:
            continue
        if not base.is_dir():
            continue
        for rel, hp, st in jail.walk(jail.rel(base)):
            fn = os.path.basename(rel)
            m = _SO_RX.match(fn)
            if not m or not stat.S_ISREG(st.st_mode):
                continue
            if rx and not rx.search(fn):
                continue
            real = os.path.realpath(hp)
            if real in seen_real:
                continue
            seen_real.add(real)
            name = m.group(1) or m.group(3)
            ver = m.group(2) or m.group(4) or ""
            lib = SharedLib(rel, name, ver)
            if with_banners and st.st_size < 64_000_000:
                lib.embedded = embedded_versions(hp)
            out.append(lib)
    return out


# ---------------------------------------------------------------------------
# Go binaries
# ---------------------------------------------------------------------------


def _uvarint(buf: bytes, pos: int) -> tuple[int, int]:
    x = s = 0
    while True:
        b = buf[pos]
        pos += 1
        x |= (b & 0x7F) << s
        if b < 0x80:
            return x, pos
        s += 7


def _parse_modinfo(mod: str) -> dict:
    if len(mod) >= 33 and mod[-17] == "\n":
        mod = mod[16:-16]
    info: dict = {"main": None, "deps": [], "settings": {}}
    for line in mod.splitlines():
        f = line.split("\t")
        if f[0] == "path" and len(f) > 1:
            info["path"] = f[1]
        elif f[0] == "mod" and len(f) > 2:
            info["main"] = {"path": f[1], "version": f[2]}
        elif f[0] == "dep" and len(f) > 2:
            info["deps"].append({"path": f[1], "version": f[2]})
        elif f[0] == "=>" and len(f) > 2 and info["deps"]:
            info["deps"][-1]["replaced_by"] = {"path": f[1], "version": f[2]}
        elif f[0] == "build" and len(f) > 1 and "=" in f[1]:
            k, v = f[1].split("=", 1)
            info["settings"][k] = v
    return info


def go_buildinfo(host_path: str) -> dict | None:
    """Parse Go module build info (Go >= 1.13). Returns None if not a Go binary."""
    try:
        with open(host_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    except (OSError, ValueError):
        return None
    try:
        off = mm.find(GO_MAGIC)
        if off < 0:
            return None
        hdr = mm[off : off + 32]
        ptr_size, flags = hdr[14], hdr[15]
        if flags & 0x2:  # Go 1.18+: inline varint strings
            pos = off + 32
            n, pos = _uvarint(mm, pos)
            version = mm[pos : pos + n].decode("utf-8", "replace")
            pos += n
            n, pos = _uvarint(mm, pos)
            modinfo = mm[pos : pos + n].decode("utf-8", "replace")
        else:  # pre-1.18: pointers to Go string headers; resolve via ELF segments
            big = bool(flags & 0x1)
            version, modinfo = _go_legacy_strings(host_path, hdr, ptr_size, big)
            if version is None:
                return {"go_version": "unknown", "deps": [], "note": "legacy buildinfo not resolvable"}
        info = _parse_modinfo(modinfo)
        info["go_version"] = version
        return info
    finally:
        mm.close()


def _go_legacy_strings(host_path: str, hdr: bytes, ptr_size: int, big: bool):
    order = "big" if big else "little"
    try:
        with open(host_path, "rb") as f:
            elf = ELFFile(f)
            segs = [s for s in elf.iter_segments() if s.header.p_type == "PT_LOAD"]

            def read(addr: int, n: int) -> bytes | None:
                for s in segs:
                    if s.header.p_vaddr <= addr < s.header.p_vaddr + s.header.p_filesz:
                        f.seek(s.header.p_offset + addr - s.header.p_vaddr)
                        return f.read(n)
                return None

            def read_str(ptr_addr: int) -> str | None:
                h = read(ptr_addr, ptr_size * 2)
                if not h:
                    return None
                data_ptr = int.from_bytes(h[:ptr_size], order)
                length = int.from_bytes(h[ptr_size:], order)
                b = read(data_ptr, length)
                return b.decode("utf-8", "replace") if b is not None else None

            v_ptr = int.from_bytes(hdr[16 : 16 + ptr_size], order)
            m_ptr = int.from_bytes(hdr[16 + ptr_size : 16 + 2 * ptr_size], order)
            return read_str(v_ptr), read_str(m_ptr) or ""
    except (ELFError, OSError, ValueError):
        return None, ""


def go_binaries(jail: Jail, start: str = "/", max_results: int = 500) -> list[dict]:
    out = []
    for rel, hp, st in jail.walk(start):
        if not stat.S_ISREG(st.st_mode) or st.st_size < 500_000 or not is_elf(hp):
            continue
        info = go_buildinfo(hp)
        if info:
            info["binary"] = rel
            out.append(info)
            if len(out) >= max_results:
                break
    return out
