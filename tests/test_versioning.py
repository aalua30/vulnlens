import pytest

from vulnlens.versioning import compare, in_range, is_vulnerable, upstream_version


@pytest.mark.parametrize("a,b,exp", [
    ("1.0", "1.0", 0), ("1.0~rc1", "1.0", -1), ("1:1.0", "2.0", 1), ("2.36-9+deb12u4", "2.36-9+deb12u3", 1),
    ("1.0-1", "1.0-1ubuntu1", -1), ("3.0.11-1~deb12u2", "3.0.11-1", -1), ("9.2p1-2", "9.2p1-2+deb12u3", -1),
])
def test_dpkg(a, b, exp):
    assert compare("deb", a, b) == exp


@pytest.mark.parametrize("a,b,exp", [
    ("1.0-1.el9", "1.0-2.el9", -1), ("1.0~beta", "1.0", -1), ("2:1.0-1", "1:9.0-1", 1), ("1.0.1a", "1.0.1", 1),
    ("3.0.7-27.el9", "3.0.7-25.el9_3", 1),
])
def test_rpm(a, b, exp):
    assert compare("rpm", a, b) == exp


def test_apk_pypi_semver_maven():
    assert compare("apk", "1.2.3-r1", "1.2.3-r0") == 1
    assert compare("apk", "1.2.3_rc1", "1.2.3") == -1
    assert compare("pypi", "2.0.0rc1", "2.0.0") == -1
    assert compare("npm", "1.2.3-beta.1", "1.2.3") == -1
    assert compare("go", "v0.17.0", "v0.9.0") == 1
    assert compare("maven", "2.17.1", "2.15.0") == 1
    assert compare("maven", "2.0-rc1", "2.0") == -1


def test_ranges():
    assert in_range("generic", "3.0.11", {"introduced": "3.0.0", "fixed": "3.0.12"})
    assert not in_range("generic", "3.0.12", {"introduced": "3.0.0", "fixed": "3.0.12"})
    assert in_range("pypi", "2.31.0", {"expr": ">= 2.0, < 2.32.0"})
    assert not in_range("pypi", "1.9", {"expr": ">=2.0,<2.32.0"})
    assert in_range("generic", "8.5", {"introduced": "0", "last_affected": "8.5"})
    assert is_vulnerable("generic", "1.1.1v", [], ["1.1.1w", "3.0.12"]) is True
    assert is_vulnerable("generic", "3.0.13", [], ["1.1.1w", "3.0.12"]) is False
    assert is_vulnerable("generic", "1.0", [], []) is None


def test_upstream_version():
    assert upstream_version("deb", "1:9.2p1-2+deb12u2") == "9.2p1"
    assert upstream_version("deb", "3.0.11-1~deb12u2") == "3.0.11"
    assert upstream_version("rpm", "1:3.0.7-27.el9") == "3.0.7"
    assert upstream_version("apk", "3.1.4-r5") == "3.1.4"
