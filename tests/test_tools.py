import io
import os
import tarfile

import pytest

from vulnlens.rootfs.resolver import safe_extract
from vulnlens.tools import Jail, JailError, build_inventory
from vulnlens.tools import fs
from vulnlens.tools.backports import changelog_mentions, osv_distro_ecosystem
from vulnlens.tools.inventory import os_package_obj
from vulnlens.tools.registry import ToolContext, analysis_tools
from vulnlens.tools.security_controls import image_config_summary, inspect_security_controls


def test_jail_symlinks(rootfs):
    j = Jail(rootfs)
    assert j.resolve("/bin/tool") == rootfs / "usr/bin/tool"  # absolute link resolved inside the jail
    assert j.resolve("/evil/passwd") == rootfs / "etc/passwd"  # escaping link clamped to the rootfs
    assert j.resolve("/../../etc/passwd") == rootfs / "etc/passwd"
    assert "echo hi" in fs.read_file(j, "/bin/tool")


def test_jail_loop(tmp_path):
    os.symlink("b", tmp_path / "a")
    os.symlink("a", tmp_path / "b")
    with pytest.raises(JailError):
        Jail(tmp_path).resolve("/a")


def test_fs_tools(rootfs):
    j = Jail(rootfs)
    assert "/app/node_modules/lodash/package.json" in fs.glob_files(j, "**/lodash/package.json")
    hits = fs.grep(j, r"_\.template", "/app", "*.js")
    assert hits and hits[0]["path"] == "/app/server.js" and hits[0]["line"] == 2
    names = {e["name"] for e in fs.list_dir(j, "/")}
    assert {"etc", "usr", "evil"} <= names


def test_inventory(rootfs):
    inv = build_inventory(Jail(rootfs))
    assert inv.distro["ID"] == "debian"
    names = {p["name"] for p in inv.os_packages}
    assert names == {"libssl3", "openssh-server", "libc6"}  # deinstalled package excluded
    assert {p["name"] for p in inv.python} == {"requests"}
    assert {p["name"] for p in inv.npm} == {"lodash", "@scope/pkg"}
    java = {(p["name"], p["version"]) for p in inv.java}
    assert ("org.apache.logging.log4j:log4j-core", "2.14.1") in java  # nested fat-jar lib
    hits = inv.find("openssl")
    kinds = {h["kind"] for h in hits}
    assert "os" in kinds and "shared_lib" in kinds
    assert inv.find("openssl", "deb")[0]["source_version"] == "3.0.11-1~deb12u2"
    assert inv.find("log4j-core", "maven")[0]["version"] == "2.14.1"
    assert inv.find("nope") == []


def test_backport_changelog(rootfs):
    j = Jail(rootfs)
    inv = build_inventory(j)
    pkg = os_package_obj(next(p for p in inv.os_packages if p["name"] == "libssl3"))
    assert changelog_mentions(j, pkg, ["CVE-2023-5678"])["id"] == "CVE-2023-5678"
    assert changelog_mentions(j, pkg, ["CVE-2099-0001"])["id"] is None
    assert osv_distro_ecosystem({"ID": "debian", "VERSION_ID": "12"}) == "Debian:12"
    assert osv_distro_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.04"}) == "Ubuntu:22.04:LTS"
    assert osv_distro_ecosystem({"ID": "alpine", "VERSION_ID": "3.19.1"}) == "Alpine:v3.19"


def test_security_controls(rootfs):
    cfg = {"config": {"User": "", "ExposedPorts": {"80/tcp": {}}, "Env": ["DB_PASSWORD=hunter2", "PATH=/usr/bin"]}}
    s = image_config_summary(cfg)
    assert s["exposed_ports"] == ["80/tcp"] and "DB_PASSWORD=<redacted>" in s["env"]
    out = inspect_security_controls(Jail(rootfs), cfg)
    assert out["runs_as_root"] is True and "root" in out["users_with_login_shell"]


def test_tool_registry_invokes(rootfs, tmp_path):
    from vulnlens.config import Settings

    j = Jail(rootfs)
    ctx = ToolContext(settings=Settings(cache_dir=str(tmp_path)), jail=j, inventory=build_inventory(j))
    tools = {t.name: t for t in analysis_tools(ctx)}
    assert '"lodash"' in tools["find_package"].invoke({"name": "lodash", "ecosystem": "npm"})
    assert "runs_as_root" not in tools["security_controls"].invoke({})  # no image config → key absent
    assert "Debian" in tools["distro_info"].invoke({})


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for m, data in members:
            tf.addfile(m, io.BytesIO(data) if data is not None else None)
    buf.seek(0)
    return buf


def test_safe_extract(tmp_path):
    def f(name, data=b"x", mode=0o644):
        ti = tarfile.TarInfo(name)
        ti.size, ti.mode = len(data), mode
        return ti, data

    def link(name, target, kind=tarfile.SYMTYPE):
        ti = tarfile.TarInfo(name)
        ti.type, ti.linkname = kind, target
        return ti, None

    outside = tmp_path / "outside"
    outside.mkdir()
    tar_path = tmp_path / "img.tar"
    tar_path.write_bytes(_tar([
        f("etc/ok", b"fine"), f("../escape", b"bad"), f("/abs", b"abs-stripped"),
        link("lnk", str(outside)), f("lnk/pwned", b"bad"),           # write through symlink to outside
        f("usr/bin/su", b"suid", 0o4755), link("bin", "usr/bin"),
        link("hard", "../../etc/shadow", tarfile.LNKTYPE),
    ]).getvalue())
    dest = tmp_path / "rootfs"
    m = safe_extract(tar_path, dest)
    assert (dest / "etc/ok").read_text() == "fine"
    assert (dest / "abs").exists()
    assert not (tmp_path / "escape").exists()
    assert not (outside / "pwned").exists()
    assert "/usr/bin/su" in m["setuid"] and not (os.stat(dest / "usr/bin/su").st_mode & 0o4000)
    assert os.path.islink(dest / "bin")
    assert not (dest / "hard").exists()


def test_file_info_overlays_stripped_setuid_bits(rootfs, tmp_path):
    import json as _json

    from vulnlens.config import Settings
    from vulnlens.tools import Jail, ToolContext, build_inventory
    from vulnlens.tools.registry import filesystem_tools

    m = tmp_path / "manifest.json"
    m.write_text(_json.dumps({"setuid": ["/usr/bin/tool"], "setgid": [], "capabilities": []}))
    jail = Jail(rootfs)
    ctx = ToolContext(settings=Settings(), jail=jail, inventory=build_inventory(jail), manifest_path=str(m))
    tools = {t.name: t for t in filesystem_tools(ctx)}
    info = _json.loads(tools["file_info"].invoke({"path": "/usr/bin/tool"}))
    assert info["mode"][3] in "sS" and "setuid" in info["special_bits"]
    listing = _json.loads(tools["list_directory"].invoke({"path": "/usr/bin"}))
    assert next(e for e in listing if e["name"] == "tool")["mode"][3] in "sS"
    plain = _json.loads(tools["file_info"].invoke({"path": "/etc/passwd"}))
    assert "special_bits" not in plain


def test_jail_at_filesystem_root():
    from vulnlens.tools.fs import Jail
    j = Jail("/")
    assert str(j.resolve("/etc/hostname")) == "/etc/hostname"
    assert str(j.resolve("../../etc")) == "/etc"
    assert j.rel("/etc/passwd") == "/etc/passwd"
