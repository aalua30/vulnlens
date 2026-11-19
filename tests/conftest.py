import io
import json
import os
import zipfile
from pathlib import Path

import pytest

DPKG_STATUS = """Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.11-1~deb12u2

Package: openssh-server
Status: install ok installed
Architecture: amd64
Source: openssh
Version: 1:9.2p1-2+deb12u2

Package: libc6
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u4

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
"""


def _jar(path: Path, group: str, artifact: str, version: str, nested: bytes | None = None) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"META-INF/maven/{group}/{artifact}/pom.properties",
                   f"groupId={group}\nartifactId={artifact}\nversion={version}\n")
        if nested:
            z.writestr("BOOT-INF/lib/log4j-core-2.14.1.jar", nested)


@pytest.fixture
def rootfs(tmp_path: Path) -> Path:
    r = tmp_path / "rootfs"
    (r / "etc").mkdir(parents=True)
    (r / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    (r / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\napp:x:1000:1000::/app:/usr/sbin/nologin\n")
    (r / "var/lib/dpkg").mkdir(parents=True)
    (r / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    sp = r / "usr/lib/python3/dist-packages/requests-2.31.0.dist-info"
    sp.mkdir(parents=True)
    (sp / "METADATA").write_text("Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nbody\n")
    nm = r / "app/node_modules/lodash"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"name": "lodash", "version": "4.17.20"}))
    sc = r / "app/node_modules/@scope/pkg"
    sc.mkdir(parents=True)
    (sc / "package.json").write_text(json.dumps({"name": "@scope/pkg", "version": "1.0.0"}))
    (r / "app/server.js").write_text("const _ = require('lodash');\n_.template(userInput);\n")
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
                   "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")
    (r / "opt/app").mkdir(parents=True)
    _jar(r / "opt/app/app.jar", "com.example", "app", "1.0.0", inner.getvalue())
    (r / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
    (r / "usr/lib/x86_64-linux-gnu/libssl.so.3").write_bytes(b"\x7fELF....OpenSSL 3.0.11 19 Sep 2023\x00")
    # symlinks: absolute (must resolve inside jail) and escaping
    (r / "bin").mkdir()
    (r / "usr/bin").mkdir(parents=True)
    (r / "usr/bin/tool").write_text("#!/bin/sh\necho hi\n")
    os.symlink("/usr/bin/tool", r / "bin/tool")
    os.symlink("/../../../../etc", r / "evil")
    (r / "usr/share/doc/openssl").mkdir(parents=True)
    import gzip

    (r / "usr/share/doc/openssl/changelog.Debian.gz").write_bytes(gzip.compress(
        b"openssl (3.0.11-1~deb12u2) bookworm-security; urgency=medium\n\n  * Fix CVE-2023-5678\n"))
    return r
