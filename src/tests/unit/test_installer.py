"""Exercise the public installer against local release archives."""

import hashlib
import os
import subprocess
import tarfile
from pathlib import Path

import pytest


@pytest.mark.parametrize("bundle", [False, True])
@pytest.mark.parametrize("valid_checksum", [False, True])
def test_install_release_archive(tmp_path, bundle, valid_checksum):
    release = tmp_path / "release"
    release.mkdir()
    payload = tmp_path / "payload"
    payload.mkdir()
    executable = payload / "socketclaw"
    if bundle:
        executable.mkdir()
        executable = executable / "socketclaw"
        runtime = payload / "socketclaw" / "_internal"
        runtime.mkdir()
        (runtime / "resource.txt").write_text("runtime")
    executable.write_text("#!/bin/sh\nprintf 'SocketClaw test\\n'\n")
    executable.chmod(0o755)
    archive = release / "socketclaw-darwin-arm64.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.add(payload / "socketclaw", arcname="socketclaw")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest() if valid_checksum else "0" * 64
    (release / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "uname").write_text(
        '#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n'
    )
    (commands / "curl").write_text(
        '#!/bin/sh\nfor arg do\ncase "$arg" in https:*) url="$arg";; esac\n'
        'destination="$arg"\ndone\ncp "$TEST_RELEASE/${url##*/}" "$destination"\n'
    )
    for command in commands.iterdir():
        command.chmod(0o755)
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    installed = install_dir / "socketclaw"
    installed.write_text("previous installation")
    environment = dict(
        os.environ,
        PATH=f"{commands}:{os.environ['PATH']}",
        TEST_RELEASE=str(release),
        SOCKETCLAW_INSTALL_DIR=str(install_dir),
        SOCKETCLAW_DATA_DIR="local data",
        SOCKETCLAW_VERSION="latest",
    )
    script = Path(__file__).resolve().parents[3] / "scripts" / "install.sh"
    result = subprocess.run(
        ["sh", str(script)], cwd=tmp_path, env=environment, capture_output=True, text=True
    )
    if not valid_checksum:
        assert result.returncode != 0
        assert "Checksum verification failed" in result.stderr
        assert installed.read_text() == "previous installation"
        return
    assert result.returncode == 0, result.stderr
    assert installed.is_symlink() is bundle
    assert subprocess.check_output([str(installed)], text=True).strip() == "SocketClaw test"
    if bundle:
        assert (installed.resolve().parent / "_internal" / "resource.txt").read_text() == "runtime"
