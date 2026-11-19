import pytest

from vulnlens.agents.exploitability import pretriage
from vulnlens.agents.vex_categorizer import decide
from vulnlens.llm import extract_json
from vulnlens.models import (AffectedPackage, ExploitabilityReport, Justification as J, Verdict as V, VexStatus as S,
                             VulnerabilityReport)
from vulnlens.tools import Jail, build_inventory


def vr(*pkgs):
    return VulnerabilityReport(vuln_id="CVE-2099-0001", affected_packages=list(pkgs))


def test_pretriage_absent(rootfs):
    inv = build_inventory(Jail(rootfs))
    res, early = pretriage(vr(AffectedPackage(name="linux", ecosystem="generic",
                                              ranges=[{"introduced": "0", "fixed": "6.8"}])), inv, None)
    assert early[0] == J.CODE_NOT_PRESENT and not res[0].found


def test_pretriage_fixed_version(rootfs):
    inv = build_inventory(Jail(rootfs))
    res, early = pretriage(vr(AffectedPackage(name="requests", ecosystem="pypi", ranges=[{"expr": "<2.20.0"}])), inv, None)
    assert early[0] == J.FALSE_POSITIVE and res[0].vulnerable is False


def test_pretriage_vulnerable_goes_deep(rootfs):
    inv = build_inventory(Jail(rootfs))
    res, early = pretriage(vr(AffectedPackage(name="org.apache.logging.log4j:log4j-core", ecosystem="maven",
                                              ranges=[{"introduced": "2.0", "fixed": "2.15.0"}])), inv, None)
    assert early is None and res[0].vulnerable is True


def test_pretriage_distro_data_wins(rootfs):
    inv = build_inventory(Jail(rootfs))
    v = vr(AffectedPackage(name="openssl", ecosystem="generic", ranges=[{"introduced": "3.0.0", "fixed": "3.0.12"}]),
           AffectedPackage(name="openssl", ecosystem="deb", distro="debian:12",
                           ranges=[{"introduced": "0", "fixed": "3.0.11-1~deb12u1"}]),
           AffectedPackage(name="openssl", ecosystem="deb", distro="ubuntu:22.04:lts",
                           ranges=[{"introduced": "0", "fixed": "9.9"}]))
    res, early = pretriage(v, inv, None)
    assert early and early[0] == J.FALSE_POSITIVE  # Debian 12 fixed version already installed
    assert all(r.ecosystem == "deb" for r in res)   # generic + ubuntu entries ignored



def _with_nginx_org(rootfs):
    inv = build_inventory(Jail(rootfs))
    inv.os_packages.append({"name": "nginx", "version": "1.25.5-1~bookworm", "ecosystem": "deb", "source": "nginx",
                            "source_version": "1.25.5-1~bookworm", "db": "/var/lib/dpkg/status",
                            "vendor": "NGINX Packaging <nginx-packaging@f5.com>", "third_party": True})
    return inv


def test_pretriage_third_party_uses_upstream_data(rootfs):
    # Debian marks its own nginx (1.22.x) unfixed; the nginx.org build 1.25.5 is past the upstream fix (1.25.3).
    v = vr(AffectedPackage(name="nginx", ecosystem="deb", distro="debian:12", ranges=[{"introduced": "0"}]),
           AffectedPackage(name="nginx", ecosystem="generic", ranges=[{"expr": "<1.25.3"}], fixed_versions=["1.25.3"]))
    res, early = pretriage(v, _with_nginx_org(rootfs), None)
    assert early and early[0] == J.FALSE_POSITIVE
    assert [r.ecosystem for r in res if r.found] == ["generic"] and "third-party" in res[0].reason


def test_pretriage_third_party_without_upstream_data_goes_deep(rootfs):
    v = vr(AffectedPackage(name="nginx", ecosystem="deb", distro="debian:12", ranges=[{"introduced": "0"}]))
    res, early = pretriage(v, _with_nginx_org(rootfs), None)
    assert early is None and res[0].found and res[0].vulnerable is None


@pytest.mark.parametrize("version,maint,expected", [
    ("1.25.5-1~bookworm", "NGINX Packaging <nginx-packaging@f5.com>", True),
    ("5:24.0.7-1~debian.12~bookworm", "Docker <support@docker.com>", True),
    ("16.2-1.pgdg120+1", "Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>", True),
    ("1.22.1-9+deb12u1", "Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>", False),
    ("1.47.0-2", "Theodore Y. Ts'o <tytso@mit.edu>", False),
    ("6.1.0~bpo12+1", "Someone <a@debian.org>", False),
    ("2.35-0ubuntu3.8", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", False),
])
def test_deb_third_party_detection(version, maint, expected):
    from vulnlens.tools.packages import deb_is_third_party
    assert deb_is_third_party(version, maint) is expected



def test_pretriage_third_party_annotated_name(rootfs):
    # LLM-written "nginx (ngx_http_v2_module)" must still match the installed nginx package
    v = vr(AffectedPackage(name="nginx", ecosystem="deb", distro="debian:12", ranges=[{"introduced": "0"}]),
           AffectedPackage(name="nginx (ngx_http_v2_module)", ecosystem="generic",
                           ranges=[{"introduced": "0", "fixed": "1.25.3"}]))
    assert v.affected_packages[1].name == "nginx" and v.affected_packages[1].component == "ngx_http_v2_module"
    res, early = pretriage(v, _with_nginx_org(rootfs), None)
    assert early and early[0] == J.FALSE_POSITIVE


def ex(verdict, **kw):
    return ExploitabilityReport(vuln_id="X", verdict=verdict, complete=True, confidence=kw.pop("confidence", 0.8), **kw)


@pytest.mark.parametrize("er,relaxed,status,first", [
    (ExploitabilityReport(vuln_id="X"), False, S.UNKNOWN, J.UNCERTAIN),
    (ex(V.NOT_APPLICABLE, early_exit=True, early_exit_justification=J.FALSE_POSITIVE), False, S.NOT_AFFECTED, J.FALSE_POSITIVE),
    (ex(V.ENVIRONMENT_ISOLATED), False, S.NOT_AFFECTED, J.REQUIRES_ENVIRONMENT),
    (ex(V.NOT_REACHABLE), False, S.NOT_AFFECTED, J.CODE_NOT_REACHABLE),
    (ex(V.MITIGATED), False, S.NOT_AFFECTED, J.MITIGATING_CONTROL_PROTECTED),
    (ex(V.CONDITIONALLY_EXPLOITABLE, conditions_met=False), False, S.NOT_AFFECTED, J.REQUIRES_CONFIGURATION),
    (ex(V.CONDITIONALLY_EXPLOITABLE), False, S.AFFECTED, J.VULNERABLE),
    (ex(V.CONDITIONALLY_EXPLOITABLE), True, S.NOT_AFFECTED, J.REQUIRES_CONFIGURATION),
    (ex(V.CONDITIONALLY_EXPLOITABLE, conditions_met=True), True, S.AFFECTED, J.VULNERABLE),
    (ex(V.EXPLOITABLE), False, S.AFFECTED, J.VULNERABLE),
    (ex(V.EXPLOITABLE, confidence=0.3), True, S.NOT_AFFECTED, J.CODE_NOT_REACHABLE),
    (ex(V.EXPLOITABLE, confidence=0.3, reachability_chain=["main -> f"]), True, S.AFFECTED, J.VULNERABLE),
])
def test_vex_flowchart(er, relaxed, status, first):
    st, allowed, trace = decide(er, relaxed, 0.6)
    assert st == status and allowed[0] == first
    assert trace[0].node == "completeness"


def test_extract_json():
    assert extract_json('blah ```json\n{"a": 1}\n``` tail') == {"a": 1}
    assert extract_json('<think>{"no": 1</think> answer: {"a": {"b": "}"}} trailing') == {"a": {"b": "}"}}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_affected_package_cleans_llm_prose():
    a = AffectedPackage(name="nginx (ngx_http_v2_module)", ecosystem="generic",
                        ranges=[{"expr": "< 1.25.3 (hardening; exposure when keepalive_requests is raised)"},
                                {"expr": "still listed vulnerable in bookworm"}],
                        fixed_versions=["1.25.3", "NGINX Plus R29 P1"])
    assert a.name == "nginx" and a.ranges == [{"expr": "<1.25.3"}] and a.fixed_versions == ["1.25.3"]
    assert any("NGINX Plus" in n for n in a.notes)


def _erlang_rootfs(tmp_path):
    import zipfile
    r = tmp_path / "rfs"
    (r / "etc").mkdir(parents=True)
    (r / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    (r / "var/lib/dpkg").mkdir(parents=True)
    (r / "var/lib/dpkg/status").write_text(
        "Package: libssl3t64\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.13-0ubuntu3.15\n"
        "Architecture: amd64\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n\n")
    eb = r / "opt/rabbitmq/plugins/cowlib-2.19.0/ebin"
    eb.mkdir(parents=True)
    (eb / "cowlib.app").write_text('{application, cowlib, [{description, "x"}, {vsn, "2.19.0"}]}.')
    with zipfile.ZipFile(r / "opt/rabbitmq/plugins/jose-1.11.12.ez", "w") as z:
        z.writestr("jose-1.11.12/ebin/jose.app", '{application,jose,[{vsn,"1.11.12"}]}.')
    rel = r / "opt/erlang/lib/erlang/releases/27"
    rel.mkdir(parents=True)
    (rel / "OTP_VERSION").write_text("27.3.4.17\n")
    lib = r / "opt/openssl/lib"
    lib.mkdir(parents=True)
    (lib / "libcrypto.so.3").write_bytes(b"\x7fELF....OpenSSL 3.5.8 25 Aug 2026\x00")
    (lib / "libssl.so.3").write_bytes(b"\x7fELF....")
    return r


def test_erlang_inventory(tmp_path):
    inv = build_inventory(Jail(_erlang_rootfs(tmp_path)))
    got = {(p["name"], p["version"]) for p in inv.erlang}
    assert {("cowlib", "2.19.0"), ("jose", "1.11.12"), ("erlang/otp", "27.3.4.17")} <= got
    assert inv.find("erlang-cowlib", "generic")[0]["version"] == "2.19.0"


def test_pretriage_hex_package_present(tmp_path):
    inv = build_inventory(Jail(_erlang_rootfs(tmp_path)))
    res, early = pretriage(vr(AffectedPackage(name="cowlib", ecosystem="hex", ranges=[{"expr": "<2.20.0"}])), inv, None)
    assert early is None and res[0].found and res[0].vulnerable is True


def test_pretriage_other_packaging_blocks_absence(tmp_path):
    # only Debian/Ubuntu "erlang-jose"/"jose" deb data, but Hex jose is vendored -> must not be code_not_present
    inv = build_inventory(Jail(_erlang_rootfs(tmp_path)))
    v = vr(AffectedPackage(name="erlang-jose", ecosystem="deb", distro="ubuntu:24.04:lts", ranges=[{"introduced": "0"}]))
    res, early = pretriage(v, inv, None)
    assert early is None and any(r.found and "jose" in r.installed[0]["location"] for r in res)


def test_pretriage_vendored_openssl_judged_upstream(tmp_path):
    # Ubuntu's libssl3t64 is fixed per distro data, but /opt/openssl 3.5.8 is in the upstream range
    inv = build_inventory(Jail(_erlang_rootfs(tmp_path)))
    v = vr(AffectedPackage(name="openssl", ecosystem="deb", distro="ubuntu:24.04:lts",
                           ranges=[{"introduced": "0", "fixed": "3.0.13-0ubuntu3.10"}]),
           AffectedPackage(name="openssl", ecosystem="generic", ranges=[{"expr": ">=3.5.0,<3.5.9"}]))
    res, early = pretriage(v, inv, None)
    assert early is None
    vend = [r for r in res if r.found and r.installed[0]["location"].startswith("/opt/openssl")]
    assert vend and vend[0].vulnerable is True and all(r.installed[0]["version"] != "" for r in vend)
