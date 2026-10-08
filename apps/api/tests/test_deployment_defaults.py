"""Four deployment residuals of docs/17, closed (2026-10-08).

* "bucket names have no shell default": `minio-init` expanded
  `$EVIDENCE_BUCKET`, `$INGEST_BUCKET` and `$SAMPLE_BUCKET` bare, though the
  code defaults all three, so a secrets.env that left one out failed the init
  on `mc mb "local/"` and the API never started. The script now defaults them
  to the code's names.
* "the volume name": `install.sh` and `install.ps1` decided whether to
  generate the schema owner's password by asking Docker for a volume of one
  fixed name, so a stack started under another project name looked new and
  was given a password initdb had never been given. They ask Docker for the
  volume by the label Compose puts on it.
* "a missing hop count": the readiness register reports
  `NOCTORNAL_TRUSTED_PROXY_HOPS` in production.
* The development compose file's pins are held in test_g48_image_context.

No Docker, no database: the shell and the PowerShell are run with stand-ins
for `mc` and `docker`, and the register's probe is called directly.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
from test_g48_image_context import _posix_shell, _script, _text
from test_install_wizard import POWERSHELL, _ps_function, _shell_function

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "production" / "compose.yml"
INSTALL_SH = ROOT / "release" / "install.sh"
INSTALL_PS1 = ROOT / "release" / "install.ps1"

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


# --- minio-init and the three bucket names ------------------------------------------

#: A stand-in `mc`: it records every call that names a bucket, and the policy
#: file a service account is given, in $MCLOG.
_MC = r"""
mc_setup() { :; }
mc() {
  case "$1 $2 $3 $4" in
    "admin user svcacct info") return 1 ;;
  esac
  case "$1" in
    ls) return 0 ;;
    mb|retention) echo "$*" >> "$MCLOG" ;;
    admin)
      shift 4
      while [ "$#" -gt 0 ]; do
        case "$1" in --policy) echo "POLICY $(cat "$2")" >> "$MCLOG"; shift ;; esac
        shift
      done ;;
  esac
  return 0
}
"""

_BUCKET_VARS = ("EVIDENCE_BUCKET", "INGEST_BUCKET", "SAMPLE_BUCKET", "COLLECT_RAW_BUCKET",
                "PRESERVE_BUCKET", "PRESERVE_ACCESS_KEY", "PRESERVE_SECRET_KEY")


def _minio_init(tmp_path: Path, **given: str) -> list[str]:
    shell = _posix_shell()
    if shell is None:
        pytest.skip("no POSIX shell")
    script = _script("minio-init", "entrypoint")
    body = script.replace(". /mc-alias.sh", ":", 1)
    path = tmp_path / "minio-init.sh"
    path.write_text(_MC + body + "\n", encoding="utf-8", newline="\n")
    log = tmp_path / "mc.log"
    log.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in _BUCKET_VARS}
    env.update({"MINIO_ROOT_USER": "test-root", "SAMPLE_ACCESS_KEY": "test-sample-ak",
                "SAMPLE_SECRET_KEY": "TEST-SAMPLE-SECRET-q9Zx", "MCLOG": log.as_posix(), **given})
    done = subprocess.run([shell, path.as_posix()], capture_output=True, text=True, env=env,
                          timeout=60)
    assert done.returncode == 0, done.stderr
    assert "buckets ready" in done.stdout
    return log.read_text(encoding="utf-8").splitlines()


def test_a_secrets_file_that_names_no_bucket_gets_the_buckets_the_code_looks_for(tmp_path):
    lines = _minio_init(tmp_path)
    assert "mb --ignore-existing --with-lock local/noctornal-evidence" in lines
    assert "mb --ignore-existing local/noctornal-raw" in lines
    assert "mb --ignore-existing local/noctornal-samples" in lines
    assert "retention set --default COMPLIANCE 365d local/noctornal-evidence" in lines
    policy = next(line for line in lines if line.startswith("POLICY "))
    assert "arn:aws:s3:::noctornal-samples/*" in policy and "arn:aws:s3:::noctornal-samples\"" in policy
    assert not [line for line in lines if re.search(r"local/(\s|$)", line)], (
        "a bucket of no name was asked for")


def test_the_defaults_are_the_names_the_code_falls_back_to():
    """One reader per fact: the three strings the script defaults to are the
    ones the three stores default to."""
    root = ROOT / "apps" / "api" / "src" / "noctornal_api"
    for env, default, module in (("EVIDENCE_BUCKET", "noctornal-evidence", "evidence.py"),
                                 ("INGEST_BUCKET", "noctornal-raw", "rawstore.py"),
                                 ("SAMPLE_BUCKET", "noctornal-samples", "samples.py")):
        assert f'os.environ.get("{env}", "{default}")' in _text(root / module), env
        assert f"${{{env}:-{default}}}" in _script("minio-init", "entrypoint").replace("$$", "$"), env


def test_an_empty_bucket_variable_counts_as_left_out(tmp_path):
    lines = _minio_init(tmp_path, EVIDENCE_BUCKET="", INGEST_BUCKET="", SAMPLE_BUCKET="")
    assert "mb --ignore-existing --with-lock local/noctornal-evidence" in lines
    assert "mb --ignore-existing local/noctornal-raw" in lines
    assert "mb --ignore-existing local/noctornal-samples" in lines


def test_a_name_the_deployment_chose_still_wins(tmp_path):
    lines = _minio_init(tmp_path, EVIDENCE_BUCKET="ev-chosen", INGEST_BUCKET="in-chosen",
                        SAMPLE_BUCKET="smp-chosen")
    assert "mb --ignore-existing --with-lock local/ev-chosen" in lines
    assert "mb --ignore-existing local/in-chosen" in lines
    assert "mb --ignore-existing local/smp-chosen" in lines
    assert "retention set --default COMPLIANCE 365d local/ev-chosen" in lines
    assert not [line for line in lines if "noctornal-evidence" in line or "noctornal-samples" in line]


# --- the database volume, asked of Docker -------------------------------------------

def _compose_key() -> str:
    text = _text(COMPOSE)
    postgres = re.search(r"(?ms)^  postgres:\n(.*?)^  \S", text + "\n  x").group(1)
    (key,) = re.findall(r"(?m)^      - ([\w-]+):/var/lib/postgresql/data\s*$", postgres)
    assert re.search(rf"(?m)^  {re.escape(key)}:\s*$", text[text.index("\nvolumes:\n"):]), key
    return key


def test_the_installers_ask_for_the_volume_by_the_key_postgres_mounts():
    key = _compose_key()
    project = re.search(r"(?m)^name: (\S+)$", _text(COMPOSE)).group(1)
    for path in (INSTALL_SH, INSTALL_PS1):
        text = _text(path)
        assert f"label=com.docker.compose.volume={key}" in text, path.name
        # The documented name, kept as a second question for a volume made by hand.
        assert f"{project}_{key}" in text, path.name


def _sh(tmp_path: Path, lines: list[str]) -> str:
    from test_g48_install_env_data import _bash
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    script = tmp_path / "volume.sh"
    script.write_text("set -euo pipefail\n" + _shell_function("production_database_state")
                      + "\n".join(lines) + "\nproduction_database_state\n",
                      encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix()], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


#: A `docker` that answers as the engine would: `info`, then `volume ls` and
#: `volume inspect`, each with the exit status and output a case sets.
_DOCKER = """
docker() {
  case "${1:-} ${2:-}" in
    "info ") return "${INFO_RC}" ;;
    "volume ls") echo "$*" >> "${DOCKERLOG}"; [ "${LS_RC}" = 0 ] || return "${LS_RC}"; printf '%s' "${LS_OUT}" ;;
    "volume inspect") echo "$*" >> "${DOCKERLOG}"; return "${INSPECT_RC}" ;;
  esac
}
"""


def _case(info=0, ls=0, listed="", inspect=1) -> list[str]:
    return [f"INFO_RC={info}", f"LS_RC={ls}", f"LS_OUT='{listed}'", f"INSPECT_RC={inspect}",
            "DOCKERLOG=/dev/null", _DOCKER]


def test_a_volume_found_by_its_label_exists_whatever_the_project_is_called(tmp_path):
    """The old question named `noctornal-prod_prod-pgdata`; a stack started
    under `-p other` has `other_prod-pgdata`, which that name never found."""
    assert _sh(tmp_path, _case(listed="other_prod-pgdata\n")) == "exists"


def test_a_volume_made_by_hand_under_the_documented_name_still_exists(tmp_path):
    assert _sh(tmp_path, _case(inspect=0)) == "exists"


def test_no_volume_from_an_engine_that_answered_is_new(tmp_path):
    assert _sh(tmp_path, _case()) == "new"


def test_an_engine_that_does_not_answer_or_refuses_is_unknown_never_new(tmp_path):
    """"New" is what lets the helper generate the owner's password, and an
    initdb that has run fixes it for good: when Docker cannot say, the helper
    asks the operator instead."""
    assert _sh(tmp_path, _case(info=1)) == "unknown"
    assert _sh(tmp_path, _case(ls=1)) == "unknown"
    absent = ["command() { if [ \"${1:-}\" = -v ] && [ \"${2:-}\" = docker ]; then return 1; fi; "
              "builtin command \"$@\"; }"]
    assert _sh(tmp_path, absent + _case()) == "unknown"


def test_the_question_asked_of_docker_is_the_one_the_comment_says(tmp_path):
    log = tmp_path / "docker.log"
    from test_g48_install_env_data import _bash
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    script = tmp_path / "ask.sh"
    script.write_text("set -euo pipefail\n" + _shell_function("production_database_state")
                      + "\n".join(_case(listed="x")[:-2]) + f"\nDOCKERLOG='{log.as_posix()}'\n"
                      + _DOCKER + "production_database_state >/dev/null\n",
                      encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix()], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    assert done.returncode == 0, done.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        "volume ls --quiet --filter label=com.docker.compose.volume=prod-pgdata"]


def test_install_sh_uses_the_question_and_keeps_its_old_guard():
    text = _text(INSTALL_SH)
    start = text.index('if [[ $PRODUCTION_STEP -eq 1 ]]; then')
    block = text[start:text.index("exit \"$status\"", start)]
    assert '[[ -z "$PROD_DIR" && "$(production_database_state)" == "new" ]]' in block
    assert "docker volume inspect" not in block, "the fixed name is asked in one place, the function"
    assert b"\r" not in INSTALL_SH.read_bytes()


if POWERSHELL:
    def _ps(tmp_path: Path, stub: str, *, scrub_path: bool = False) -> str:
        script = tmp_path / "volume.ps1"
        pre = "$env:PATH = ''\n" if scrub_path else ""
        script.write_text(stub + _ps_function("Get-ProductionDatabaseState") + pre
                          + "Get-ProductionDatabaseState\n", encoding="utf-8")
        done = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                               str(script)], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=120)
        assert done.returncode == 0, done.stdout + done.stderr
        return done.stdout.strip()

    def _ps_docker(info=0, ls=0, listed="", inspect=1) -> str:
        return ("function docker { }\n"
                "function Invoke-Capture {\n"
                "    param([string] $Exe, [string[]] $Arguments = @())\n"
                "    switch ($Arguments[0]) {\n"
                f"        'info' {{ [pscustomobject]@{{ Code = {info}; Text = '' }} }}\n"
                f"        'volume' {{ if ($Arguments[1] -eq 'ls') {{ [pscustomobject]@{{ Code = {ls}; "
                f"Text = '{listed}' }} }} else {{ [pscustomobject]@{{ Code = {inspect}; Text = '' }} }} }}\n"
                "    }\n}\n")

    def test_install_ps1_asks_docker_the_same_question(tmp_path):
        assert _ps(tmp_path, _ps_docker(listed="other_prod-pgdata")) == "exists"
        assert _ps(tmp_path, _ps_docker(inspect=0)) == "exists"
        assert _ps(tmp_path, _ps_docker()) == "new"
        assert _ps(tmp_path, _ps_docker(info=1)) == "unknown"
        assert _ps(tmp_path, _ps_docker(ls=1)) == "unknown"
        assert _ps(tmp_path, "function Invoke-Capture { }\n", scrub_path=True) == "unknown"
else:
    def test_install_ps1_carries_the_same_question():
        assert "function Get-ProductionDatabaseState" in _text(INSTALL_PS1)


def test_install_ps1_uses_the_question_and_does_not_ask_for_the_fixed_name_itself():
    text = _text(INSTALL_PS1)
    start = text.index("if ($ProductionSecrets) {")
    block = text[start:text.index("exit $status", start)]
    assert "(-not $ProductionDir -and (Get-ProductionDatabaseState) -eq 'new')" in block
    assert "noctornal-prod_prod-pgdata" not in block
    raw = INSTALL_PS1.read_bytes()
    assert raw.count(b"\r\n") in (0, raw.count(b"\n")), "mixed line endings"


# --- the hop count on the register --------------------------------------------------

def _probe():
    from noctornal_api import readiness
    return dict((name, probe) for name, probe, _ in readiness._CHECKS)["proxy_hops_declared"]


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv("NOCTORNAL_TRUSTED_PROXY_HOPS", raising=False)


@pytest.mark.parametrize("value", [None, "", "0", "-1", "banana"])
def test_production_without_a_hop_count_is_a_failed_row_that_says_what_it_costs(
        production, monkeypatch, value):
    if value is not None:
        monkeypatch.setenv("NOCTORNAL_TRUSTED_PROXY_HOPS", value)
    check = _probe()(None)
    assert check.ok is False, check
    assert "NOCTORNAL_TRUSTED_PROXY_HOPS" in check.evidence
    for cost in ("rate limiter", "sign-in audit", "session binding"):
        assert cost in check.evidence, cost
    # Said as it is: uvicorn, told to trust the proxy, reports the client as the
    # peer (measured), so the row names the condition and not a certain harm.
    assert "--forwarded-allow-ips" in check.evidence
    assert "number of proxies in front of the API" in check.action
    assert "restart" in check.action


@pytest.mark.parametrize("value, phrase", [("1", "1 proxy stands"), ("2", "2 proxies stand")])
def test_production_with_a_count_passes_and_says_where_the_client_is(production, monkeypatch,
                                                                    value, phrase):
    monkeypatch.setenv("NOCTORNAL_TRUSTED_PROXY_HOPS", value)
    check = _probe()(None)
    assert check.ok is True and phrase in check.evidence, check
    assert f"entry {value} from the right" in check.evidence


@pytest.mark.parametrize("value", [None, "0", "banana", "1"])
def test_outside_production_the_row_passes_and_says_what_it_read(monkeypatch, value):
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    monkeypatch.delenv("NOCTORNAL_TRUSTED_PROXY_HOPS", raising=False)
    if value is not None:
        monkeypatch.setenv("NOCTORNAL_TRUSTED_PROXY_HOPS", value)
    check = _probe()(None)
    assert check.ok is True, check
    assert "NOCTORNAL_TRUSTED_PROXY_HOPS is" in check.evidence


def test_the_row_is_in_the_register_after_the_limiter_row_and_is_not_blocking():
    from noctornal_api import readiness
    names = list(readiness.CHECK_NAMES)
    assert names.index("proxy_hops_declared") == names.index("rate_limiting_enabled") + 1
    assert "proxy_hops_declared" not in readiness.BLOCKING_CHECKS


def test_the_row_and_the_limiter_read_the_count_through_one_function(monkeypatch):
    """One reader per fact: the register reports the number `client_ip` uses."""
    import inspect

    from fastapi import Request

    from noctornal_api.http import limits
    assert "trusted_proxy_hops()" in inspect.getsource(limits.client_ip)
    from noctornal_api import readiness
    assert "trusted_proxy_hops" in inspect.getsource(readiness._proxy_hops_declared)
    monkeypatch.setenv(limits.HOPS_ENV, "1")
    scope = {"type": "http", "client": ("172.31.243.10", 1234), "method": "GET",
             "path": "/", "query_string": b"", "headers": [(b"x-forwarded-for",
                                                              b"6.6.6.6, 203.0.113.9")]}
    assert limits.client_ip(Request(scope)) == "203.0.113.9"
    monkeypatch.delenv(limits.HOPS_ENV)
    assert limits.client_ip(Request(scope)) == "172.31.243.10"


def test_the_rows_words_carry_none_of_the_house_styles_refusals(production):
    check = _probe()(None)
    for text in (check.evidence, check.action):
        assert not re.search("[" + chr(0x2013) + chr(0x2014) + "]| -- |\\(s\\)", text), text


def test_the_secrets_template_still_sets_the_count_the_register_wants():
    template = _text(ROOT / "infra" / "production" / "secrets.env.example")
    assert re.search(r"(?m)^NOCTORNAL_TRUSTED_PROXY_HOPS=1$", template)

