"""scripts/mail_stamp_sign.py, the signer the mail server runs, and the Postfix example beside it
(infra/production/mail-stamp). The MTA itself cannot run here; these hold the script and the files.

No database.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mail_stamp_support import KEY, KEYS
from noctornal_api import mail_stamp

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "mail_stamp_sign.py"
EXAMPLES = ROOT / "infra" / "production" / "mail-stamp"
B64 = base64.b64encode(KEY).decode()
AUTHSERV = "mx.corp.example"
MESSAGE = (b"Authentication-Results: mx.corp.example; dkim=pass header.d=acme.example\r\n"
           b"Received: from s.example ([203.0.113.9]) by mx.corp.example;"
           b" Mon, 20 Jul 2026 09:00:00 +0000\r\n"
           b"From: jane@acme.example\r\nSubject: Remittance\r\n\r\nbody\r\n")

_RUNS: list[subprocess.CompletedProcess] = []


def _run(*args, data=MESSAGE, key_env=True, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("NOCTORNAL_MAIL_STAMP")}
    if key_env:
        env[mail_stamp.KEY_ENV] = B64
    env.update(extra_env or {})
    done = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], input=data,
                          capture_output=True, env=env, timeout=60)
    _RUNS.append(done)
    return done


def _key_file(tmp_path, mode=0o600):
    path = tmp_path / "key"
    path.write_text(B64 + "\n", encoding="ascii")
    os.chmod(path, mode)
    return str(path)


def test_sign_then_verify_round_trips_through_the_script_and_the_module(tmp_path):
    signed = _run("sign", "--authserv-id", AUTHSERV, "--key-id", "mail:t1")
    assert signed.returncode == 0, signed.stderr
    assert signed.stdout.startswith(b"X-NocTORnal-Stamp: v=1; k=mail:t1; ")
    assert mail_stamp.verify(signed.stdout, KEYS).ok
    checked = _run("verify", "--key-file", _key_file(tmp_path), "--key-id", "mail:t1",
                   data=signed.stdout, key_env=False)
    assert checked.returncode == 0
    assert json.loads(checked.stdout) == {"valid": True, "key_id": "mail:t1", "reason": None}
    bad = _run("verify", "--key-id", "mail:t1",
               data=signed.stdout.replace(b"body", b"b0dy"))
    assert bad.returncode == 1 and json.loads(bad.stdout)["valid"] is False


def test_the_script_strips_an_inbound_stamp_before_signing():
    inbound = b"X-NocTORnal-Stamp: v=1; k=mail:t1; forged\r\n" + MESSAGE
    signed = _run("sign", "--authserv-id", AUTHSERV, "--key-id", "mail:t1", data=inbound)
    assert signed.returncode == 0
    assert signed.stdout.count(b"X-NocTORnal-Stamp:") == 1
    assert b"forged" not in signed.stdout
    assert mail_stamp.verify(signed.stdout, KEYS).ok


@pytest.mark.parametrize("data", [
    MESSAGE.split(b"\r\n", 1)[1],                                   # no Authentication-Results
    b"".join(line + b"\r\n" for line in MESSAGE.split(b"\r\n")[:-1]
             if not line.startswith(b"Received:")),                 # no Received
    MESSAGE.replace(b"Authentication-Results: mx.corp.example",
                    b"Authentication-Results: mx.other.example"),   # another server's header
])
def test_a_message_it_cannot_stamp_passes_through_unchanged_with_exit_0(data):
    done = _run("sign", "--authserv-id", AUTHSERV, data=data)
    assert done.returncode == 0
    assert done.stdout == data
    assert b"left unstamped" in done.stderr


def test_a_missing_key_exits_75_and_prints_no_key_material(tmp_path):
    done = _run("sign", "--authserv-id", AUTHSERV, key_env=False)
    assert done.returncode == 75 and done.stdout == b""
    short = _run("sign", "--authserv-id", AUTHSERV, key_env=False,
                 extra_env={mail_stamp.KEY_ENV: base64.b64encode(KEY[:8]).decode()})
    assert short.returncode == 75 and short.stdout == b""
    unreadable = _run("sign", "--authserv-id", AUTHSERV, "--key-file",
                      str(tmp_path / "absent"), key_env=False)
    assert unreadable.returncode == 75


def test_a_usage_error_is_exit_2():
    assert _run("sign").returncode == 2
    assert _run("frobnicate").returncode == 2


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")
def test_a_group_readable_key_file_is_refused(tmp_path):
    loose = _run("sign", "--authserv-id", AUTHSERV, "--key-file",
                 _key_file(tmp_path, 0o644), key_env=False)
    assert loose.returncode == 75 and loose.stdout == b""
    tight = _run("sign", "--authserv-id", AUTHSERV, "--key-file",
                 _key_file(tmp_path, 0o640), key_env=False)
    assert tight.returncode == 0


def test_the_script_never_prints_the_key():
    """Runs last in this file, over every run above."""
    assert _RUNS
    for done in _RUNS:
        assert B64.encode() not in done.stdout + done.stderr


def test_the_example_files_exist_have_lf_endings_and_the_shell_script_has_a_shebang():
    """LF for the shell script, which .gitattributes holds for every *.sh: `#!/bin/sh\\r` is no shebang."""
    assert (EXAMPLES / "README.md").is_file()
    assert b"\r\n" not in (EXAMPLES / "stamp-filter.sh").read_bytes()
    filter_sh = (EXAMPLES / "stamp-filter.sh").read_text(encoding="ascii")
    assert filter_sh.startswith("#!/bin/sh\n")
    assert "exit $EX_TEMPFAIL" in filter_sh
    assert "-t" not in filter_sh.split("SENDMAIL=", 1)[1].split("\n", 1)[0]
    master = (EXAMPLES / "postfix-master.cf.example").read_text(encoding="ascii")
    assert "flags=Rq user=noctornal-stamp null_sender=" in master
    live = [line for line in master.splitlines() if not line.startswith("#")]
    assert not any("content_filter" in line for line in live), (
        "content_filter belongs on the smtpd line, which the example leaves commented")
    staged = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--stage",
                             "infra/production/mail-stamp/stamp-filter.sh"],
                            capture_output=True, text=True)
    if staged.returncode == 0 and staged.stdout:
        assert staged.stdout.startswith("100755 "), staged.stdout


@pytest.mark.parametrize("written", [
    "mx.corp.example;", "MX.Corp.Example;", "mx.corp.example.;", "mx.corp.example. ;",
    "mx.corp.example 1;", "mx.corp.example\t;", "mx.corp.example\n ;", "\n mx.corp.example.;",
    "mx.corp.example",
])
def test_the_readme_header_checks_line_drops_every_form_the_signer_accepts(written):
    """A sender's header the README's line misses, and the signer accepts as this server's, is stamped
    and believed whenever no milter writes one above it. Postfix regexp tables ignore case by default
    and match a folded header as one text with its newlines."""
    readme = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    line = next(x for x in readme.splitlines() if x.startswith("/^Authentication-Results:"))
    pattern, action = line[1:].rsplit("/ ", 1)
    assert action == "IGNORE"
    drops = re.compile(pattern.replace("[:space:]", r"\s"), re.IGNORECASE)
    value = written.encode("ascii").replace(b"\n", b"\r\n")
    message = MESSAGE.replace(b"mx.corp.example; dkim", value + b" dkim", 1)
    assert mail_stamp.refusal(message, authserv_id=AUTHSERV) is None
    assert drops.search("Authentication-Results: " + written.replace("\r", ""))


def test_the_signer_and_the_api_share_one_module():
    """The script loads mail_stamp.py by path and holds no canonical form of its own."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "hmac" not in text and "hashlib" not in text
    assert '"noctornal_api" / "mail_stamp.py"' in text
