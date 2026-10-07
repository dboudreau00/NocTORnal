"""The persona key's split, without a database (ROADMAP-REMAINING "A
collector process", 2026-10-02).

Invariant 7, as of 2026-10-02: a persona credential opens only under
NOCTORNAL_PERSONA_KEK, never the TOTP ring; in production only the collector
holds that key and only the collector's vault opens with it; every other
process refuses to start holding it; the inline mode that runs persona acts
inside the API is refused in production; and the deployment files give the
key to the collector service alone. Each test here fails without the
behaviour it names.
"""
from __future__ import annotations

import base64
import os
import re
from pathlib import Path

import pytest

from noctornal_api import config, persona_acts
from noctornal_api.security import envelope, persona_envelope, persona_sealed, sealed

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "production" / "compose.yml"

KEY_A = base64.b64encode(b"persona-key-a-for-the-split-0001").decode()
KEY_B = base64.b64encode(b"persona-key-b-for-the-split-0002").decode()
TOTP = base64.b64encode(b"totp-key-for-the-split-tests-001").decode()


@pytest.fixture
def ring(monkeypatch):
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    monkeypatch.delenv(persona_envelope.COLLECTOR_ENV, raising=False)
    monkeypatch.delenv(persona_envelope.KEK_ID_ENV, raising=False)
    monkeypatch.delenv(persona_envelope.RETIRED_ENV, raising=False)
    monkeypatch.setenv(persona_envelope.KEK_ENV, KEY_A)
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", TOTP)
    monkeypatch.delenv("NOCTORNAL_TOTP_KEK_ID", raising=False)
    monkeypatch.delenv("NOCTORNAL_TOTP_KEK_RETIRED", raising=False)
    return monkeypatch


# --- the ring -------------------------------------------------------------------

def test_a_persona_credential_seals_under_the_persona_key_and_not_the_totp_ring(ring):
    blob, key_id = persona_envelope.encrypt("tg-session")
    assert key_id == "persona:v1"
    assert persona_envelope.decrypt(blob, key_id=key_id) == "tg-session"
    # The TOTP ring holds no persona id, and its key does not open the blob.
    with pytest.raises(envelope.UNOPENABLE):
        envelope.decrypt(blob, key_id=key_id)
    with pytest.raises(envelope.UNOPENABLE):
        envelope.open_with(blob, base64.b64decode(TOTP))


def test_a_credential_sealed_before_the_split_is_refused_by_name(ring):
    blob, key_id = envelope.encrypt("old-session")
    with pytest.raises(persona_envelope.SealedBeforeSplit) as refused:
        persona_envelope.decrypt(blob, key_id=key_id)
    assert persona_envelope.MOVE_COMMAND in str(refused.value)
    assert "old-session" not in str(refused.value)
    # A NULL id is the TOTP ring's default, so it is refused the same way.
    with pytest.raises(persona_envelope.SealedBeforeSplit):
        persona_envelope.decrypt(blob, key_id=None)


def test_the_persona_ids_are_their_own_namespace(ring):
    ring.setenv(persona_envelope.KEK_ID_ENV, "env:v2")
    with pytest.raises(persona_envelope.PersonaKeyError):
        persona_envelope.active_key_id()
    ring.setenv(persona_envelope.KEK_ID_ENV, "persona:v2")
    ring.setenv(persona_envelope.RETIRED_ENV, f"persona:v1={KEY_B}")
    assert persona_envelope.key_ids() == ("persona:v2", "persona:v1")
    ring.setenv(persona_envelope.RETIRED_ENV, f"persona:v2={KEY_B}")
    with pytest.raises(persona_envelope.PersonaKeyError, match="reuses the ACTIVE"):
        persona_envelope.ring()


def test_a_retired_persona_key_still_opens_and_a_rewrap_moves_it_home(ring):
    blob, old_id = persona_envelope.encrypt("rotating")
    ring.setenv(persona_envelope.KEK_ENV, KEY_B)
    ring.setenv(persona_envelope.KEK_ID_ENV, "persona:v2")
    ring.setenv(persona_envelope.RETIRED_ENV, f"persona:v1={KEY_A}")
    assert persona_envelope.decrypt(blob, key_id=old_id) == "rotating"
    new_blob, new_id = persona_envelope.rewrap(blob, key_id=old_id)
    assert new_id == "persona:v2"
    ring.delenv(persona_envelope.RETIRED_ENV)
    assert persona_envelope.decrypt(new_blob, key_id=new_id) == "rotating"
    assert persona_envelope.can_open(blob, key_id=old_id) is not None


def test_in_production_only_the_collector_opens_with_the_key(ring):
    blob, key_id = persona_envelope.encrypt("tg-session")
    ring.setenv("NOCTORNAL_ENV", "production")
    with pytest.raises(persona_envelope.PersonaKeyError, match="collector alone"):
        persona_envelope.decrypt(blob, key_id=key_id)
    with pytest.raises(persona_envelope.PersonaKeyError):
        persona_envelope.encrypt("x")
    ring.setenv(persona_envelope.COLLECTOR_ENV, "1")
    assert persona_envelope.decrypt(blob, key_id=key_id) == "tg-session"


def test_a_process_without_the_key_cannot_open_and_says_which_variable(ring):
    blob, key_id = persona_envelope.encrypt("tg-session")
    ring.delenv(persona_envelope.KEK_ENV)
    with pytest.raises(persona_envelope.PersonaKeyError) as refused:
        persona_envelope.decrypt(blob, key_id=key_id)
    assert persona_envelope.KEK_ENV in str(refused.value)
    assert persona_envelope.held() == []


# --- the inventories ----------------------------------------------------------------

def test_the_totp_inventory_no_longer_holds_the_persona_column():
    tables = {table for table, _c, _k in sealed.SEALED_COLUMNS}
    assert "collect.collection_account" not in tables
    assert {t for t, _c, _k in persona_sealed.PERSONA_SEALED_COLUMNS} == {
        "collect.collection_account"}


# --- the boot refusals ----------------------------------------------------------------

def _prod(**extra) -> dict:
    env = {"NOCTORNAL_ENV": "production"}
    env.update(extra)
    return env


def test_a_production_api_holding_the_persona_key_is_refused():
    problems = config.persona_key_problems(
        _prod(NOCTORNAL_PERSONA_KEK=KEY_A), collector=False)
    assert any("not the collector" in p and "NOCTORNAL_PERSONA_KEK" in p
               for p in problems), problems
    retired = config.persona_key_problems(
        _prod(NOCTORNAL_PERSONA_KEK_RETIRED=f"persona:v1={KEY_A}"), collector=False)
    assert any("NOCTORNAL_PERSONA_KEK_RETIRED" in p for p in retired), retired
    assert KEY_A not in " ".join(problems + retired)
    # And through the API's own boot check.
    assert any("not the collector" in p for p in config.verify_environment(
        _prod(NOCTORNAL_PERSONA_KEK=KEY_A)))


def test_the_collectors_mark_on_another_process_is_refused():
    problems = config.persona_key_problems(_prod(NOCTORNAL_COLLECTOR="1"),
                                           collector=False)
    assert any("marks the collector service alone" in p for p in problems), problems


def test_the_boot_makes_the_persona_refusals_and_the_owner_credentials_together():
    """Two groups' refusals in one list (merged): a production process that
    holds the persona key AND the schema owner's credential is refused for
    both, each by name and neither by value. The collector is not asked for
    the key but never holds the owner's credential either."""
    owner = "Hq7vX2-owner-password"
    env = _prod(NOCTORNAL_PERSONA_KEK=KEY_A, POSTGRES_PASSWORD=owner)
    problems = config.verify_environment(env)
    assert any("not the collector" in p and "NOCTORNAL_PERSONA_KEK" in p for p in problems)
    assert any("POSTGRES_PASSWORD is set on a runtime process" in p for p in problems)
    assert KEY_A not in " ".join(problems) and owner not in " ".join(problems)
    collector = config.verify_environment(
        {**env, "NOCTORNAL_COLLECTOR": "1"}, collector=True)
    assert not any("not the collector" in p for p in collector), collector
    assert any("POSTGRES_PASSWORD is set on a runtime process" in p for p in collector)
    assert owner not in " ".join(collector)


def test_the_inline_mode_is_refused_in_production_and_ignored_there(monkeypatch):
    problems = config.persona_key_problems(
        _prod(NOCTORNAL_COLLECTOR_INLINE="1"), collector=False)
    assert any("development only" in p for p in problems), problems
    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "1")
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    assert persona_acts.inline_mode() is False
    monkeypatch.delenv("NOCTORNAL_ENV")
    assert persona_acts.inline_mode() is True


def test_the_collector_needs_its_mark_and_a_usable_key():
    missing = config.persona_key_problems(_prod(NOCTORNAL_COLLECTOR="1"),
                                          collector=True)
    assert any("NOCTORNAL_PERSONA_KEK is not set" in p for p in missing), missing
    unmarked = config.persona_key_problems(_prod(NOCTORNAL_PERSONA_KEK=KEY_A),
                                           collector=True)
    assert any("NOCTORNAL_COLLECTOR is not set" in p for p in unmarked), unmarked
    assert config.persona_key_problems(
        _prod(NOCTORNAL_COLLECTOR="1", NOCTORNAL_PERSONA_KEK=KEY_A),
        collector=True) == []


def test_nothing_is_refused_outside_production():
    assert config.persona_key_problems(
        {"NOCTORNAL_PERSONA_KEK": KEY_A, "NOCTORNAL_COLLECTOR_INLINE": "1"},
        collector=False) == []


def test_the_cron_entries_refuse_a_persona_key():
    with pytest.raises(RuntimeError, match="not the collector"):
        config.enforce_persona_key_boundary(_prod(NOCTORNAL_PERSONA_KEK=KEY_A),
                                            collector=False)
    config.enforce_persona_key_boundary(_prod(), collector=False)
    # The cron entries refuse it through the one helper every job calls
    # (merged with the hardening work, which made that helper), as one line
    # on stderr and the one exit code every job gives a refusal.
    lines = config.refuse_unsafe_job_environment(
        "notify_drain", _prod(NOCTORNAL_PERSONA_KEK=KEY_A))
    assert any(line.startswith("notify_drain: refusing to run: ")
               and "not the collector" in line for line in lines), lines
    assert KEY_A not in " ".join(lines)
    for script in ("notify_drain.py", "lookup_drain.py", "embed_pass.py"):
        text = (ROOT / "scripts" / script).read_text(encoding="utf-8")
        assert text.count("refuse_unsafe_job_environment(") == 1, script
        assert "holds_persona_key" not in text, script
        assert "enforce_persona_key_boundary" not in text, script
    # The poll runs as the collector's child and the collector is the key's
    # holder: neither is asked for the key by the helper, and the poll makes
    # the collector's own half itself.
    poll = (ROOT / "scripts" / "collection_poll.py").read_text(encoding="utf-8")
    assert "enforce_persona_key_boundary(collector=True)" in poll
    assert 'refuse_unsafe_job_environment("collection_poll", holds_persona_key=True)' in poll
    collector = (ROOT / "scripts" / "collector.py").read_text(encoding="utf-8")
    assert 'refuse_unsafe_job_environment("collector", holds_persona_key=True)' in collector


def test_the_suites_persona_key_is_a_published_value():
    found = config.published_credentials({"NOCTORNAL_PERSONA_KEK": "AQEB" * 10 + "AQE="})
    assert [p.variable for p in found] == ["NOCTORNAL_PERSONA_KEK"]
    assert config.published_credentials({"NOCTORNAL_PERSONA_KEK": KEY_A}) == []


def test_the_egress_proxy_refuses_to_hold_the_persona_key():
    from noctornal_api import egress_proxy

    assert {"NOCTORNAL_PERSONA_KEK", "NOCTORNAL_PERSONA_KEK_RETIRED"} <= set(
        egress_proxy.FORBIDDEN_ENV)


# --- the deployment files ---------------------------------------------------------------

def _service(name: str) -> str:
    text = COMPOSE.read_text(encoding="utf-8")
    start = text.index(f"\n  {name}:\n")
    nxt = re.search(r"\n  [a-z][a-z-]*:\n", text[start + 1:])
    return text[start:start + 1 + nxt.start()] if nxt else text[start:]


def test_only_the_collector_service_reads_the_persona_key_file_and_carries_the_mark():
    from test_egress_topology import COMPOSE as TOPOLOGY_COMPOSE, Reader, _env_files

    doc = Reader(TOPOLOGY_COMPOSE.read_text(encoding="utf-8")).document()
    readers = {name for name, svc in doc["services"].items()
               if "collector.env" in dict(_env_files(svc))}
    assert readers == {"collector"}
    marked = {name for name, svc in doc["services"].items()
              if "NOCTORNAL_COLLECTOR" in (svc.get("environment") or {})}
    assert marked == {"collector"}
    collector = doc["services"]["collector"]
    assert collector["environment"]["NOCTORNAL_COLLECTOR"] == "1"
    assert collector["environment"]["NOCTORNAL_ENV"] == "production"
    assert ("collector.env", False) in _env_files(collector)
    assert "exec python scripts/collector.py" in _service("collector")


def test_the_cron_loop_no_longer_polls_and_the_collector_does():
    commands = [line for line in _service("cron").split("command:", 1)[1].splitlines()
                if not line.strip().startswith("#")]
    assert not any("collection_poll.py" in line for line in commands)
    collector = (ROOT / "scripts" / "collector.py").read_text(encoding="utf-8")
    assert "collection_poll.py" in collector


def test_the_persona_key_file_is_ignored_and_its_template_exists():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "infra/production/collector.env\n" in ignored
    template = (ROOT / "infra" / "production" / "collector.env.example").read_text(
        encoding="utf-8")
    assert re.search(r"(?m)^NOCTORNAL_PERSONA_KEK=replace-me$", template)
    secrets =(ROOT / "infra" / "production" / "secrets.env.example").read_text(
        encoding="utf-8")
    assert not re.search(r"(?m)^NOCTORNAL_PERSONA_KEK", secrets)


_GENERATOR = re.compile(
    r"os\.urandom\((\d+)\)|New-Object byte\[\] (\d+)|\[byte\[\]\]::new\((\d+)\)")
_PERSONA_KEY_WRITE = re.compile(r"NOCTORNAL_PERSONA_KEK=[%$]")


@pytest.mark.parametrize("path", ["release/install.sh", "release/install.ps1",
                                  "scripts/launch.sh", "scripts/launch.ps1"])
def test_every_installer_and_launcher_gives_a_dev_install_its_persona_key(path):
    """Each place that WRITES the key draws it from a 32 byte generator (the
    one before the write is read, not any in the file), writes the inline
    mode beside it, and the header no longer counts two secrets where
    three are written (2026-10-03)."""
    text = (ROOT / path).read_text(encoding="utf-8")
    writes = [m.start() for m in _PERSONA_KEY_WRITE.finditer(text)]
    assert writes, f"{path} never writes the persona key"
    for at in writes:
        drawn = [int(next(g for g in groups if g)) for groups in
                 _GENERATOR.findall(text[max(0, at - 4000):at])]
        assert drawn and drawn[-1] == 32, (path, drawn)
    assert re.search(r"NOCTORNAL_COLLECTOR_INLINE\s*=?\s*'?1\b", text), path
    # The TOTP header no longer claims the persona credentials.
    assert "collection persona credentials, which NOCTORNAL_PERSONA_KEK seals" in text
    assert "these two secrets" not in text


def test_the_key_a_dev_install_writes_is_one_the_persona_ring_accepts(ring):
    """The one-liner the shell installers run, run: its output is a key the
    ring reads (32 bytes of base64), not something that merely looks like
    one."""
    import subprocess
    import sys

    code = re.search(r"-c '([^']*urandom\(32\)[^']*)'",
                     (ROOT / "release" / "install.sh").read_text(encoding="utf-8"))
    if code is None:
        code = re.search(r'-c "([^"]*urandom\(32\)[^"]*)"',
                         (ROOT / "release" / "install.ps1").read_text(encoding="utf-8"))
    assert code, "no installer one-liner draws 32 bytes"
    drawn = subprocess.run([sys.executable, "-c", code.group(1)], capture_output=True,
                           text=True, check=True).stdout.strip()
    ring.setenv(persona_envelope.KEK_ENV, drawn)
    blob, key_id = persona_envelope.encrypt("tg-session")
    assert persona_envelope.decrypt(blob, key_id=key_id) == "tg-session"


# --- the scripts that must not start without it (2026-10-03) ------------------------

def test_telegram_enrolment_refuses_before_asking_anybody_when_there_is_no_key(
        ring, capsys):
    """The development guard did nothing outside production, so a machine
    upgraded without its launcher took the whole Telegram login, burnt a
    code, and failed storing the session with a traceback. Every sign-in
    prompt here raises, so a refusal that comes after one fails the test."""
    import builtins
    import getpass
    import sys
    import uuid

    sys.path.insert(0, str(ROOT / "scripts"))
    import telegram_persona

    def asked(*_a, **_k):
        raise AssertionError("somebody was asked for something")

    ring.delenv(persona_envelope.KEK_ENV)
    ring.setattr(telegram_persona, "load_env_local", lambda: None)
    ring.setattr(telegram_persona, "sign_in", asked)
    ring.setattr(builtins, "input", asked)
    ring.setattr(getpass, "getpass", asked)
    for argv in (["enrol", "--persona", str(uuid.uuid4())],
                 ["import", "--persona", str(uuid.uuid4())],
                 ["logout", "--persona", str(uuid.uuid4()), "--reason", "a test"]):
        assert telegram_persona.main(argv) == 2, argv
        err = capsys.readouterr().err
        assert persona_envelope.KEK_ENV in err and "nothing was asked of anyone" in err
        assert "Traceback" not in err


def test_the_embed_pass_worker_refuses_to_hold_the_persona_key_in_production(
        ring, capsys):
    """It was the one Lab worker that called neither enforce_environment nor
    the boundary, so only the vault guard stood between it and the key."""
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import embed_pass

    def touched(*_a, **_k):
        raise AssertionError("the pass reached the database")

    ring.setattr(embed_pass, "connect", touched)
    ring.setenv("NOCTORNAL_ENV", "production")
    assert embed_pass.main([]) == 2
    captured = capsys.readouterr()
    # Through the one helper every job calls: stderr, led by the job's name.
    assert "embed_pass: refusing to run: NOCTORNAL_PERSONA_KEK" in captured.err
    assert "not the collector" in captured.err
    assert KEY_A not in captured.out + captured.err


def test_the_test_suites_key_is_not_the_totp_one():
    assert os.environ["NOCTORNAL_PERSONA_KEK"] != os.environ["NOCTORNAL_TOTP_KEK"]


# --- claims the deployment files and docs may make (2026-10-03) ----------

def test_the_collectors_wait_needs_the_psycopg_the_project_asks_for():
    """scripts/collector.py waits with Connection.notifies(timeout=,
    stop_after=), which psycopg 3.1 does not have: the floor the project
    declares is 3.2 or later while that call is there, and the pin the image
    installs satisfies it."""
    collector = (ROOT / "scripts" / "collector.py").read_text(encoding="utf-8")
    assert re.search(r"notifies\(timeout=", collector)
    pyproject = (ROOT / "apps" / "api" / "pyproject.toml").read_text(encoding="utf-8")
    floor = re.search(r'"psycopg\[binary\]>=(\d+)\.(\d+)', pyproject)
    assert floor and (int(floor.group(1)), int(floor.group(2))) >= (3, 2)
    pinned = re.search(r"(?m)^psycopg==(\d+)\.(\d+)",
                       (ROOT / "constraints.txt").read_text(encoding="utf-8"))
    assert pinned and (int(pinned.group(1)), int(pinned.group(2))) >= (3, 2)


def test_the_docs_name_the_services_that_check_the_key_and_not_every_service():
    """Only the services that run the application's code, the egress proxy
    and the migration job refuse to start holding the persona key; the
    database, the object store and Redis read secrets.env and check nothing,
    and Caddy reads caddy.env alone (corrected on
    2026-10-07: the migration job reads migrate.env and refuses the key). A
    document that says every other service refuses is wrong about the one
    place the key must never be put."""
    for path in ("infra/production/README.md", "infra/production/collector.env.example"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert not re.search(r"(?i)every other (?:service|process)\b[^.]*\brefuse", text), path
        assert "secrets.env" in text and "Caddy" in text, path
    arch = (ROOT / "docs" / "02-architecture.md").read_text(encoding="utf-8")
    assert not re.search(r"(?i)every other production process", arch)


def test_the_poll_child_is_not_claimed_to_wind_down_while_it_has_no_handler():
    """scripts/collection_poll.py installs no SIGTERM handler, so the child
    ends at once when the collector stops it; the 30 seconds are only the
    wait before a stuck child is killed. If the poll ever gains a handler,
    this fails so the comments are rewritten to say what it now does."""
    poll = (ROOT / "scripts" / "collection_poll.py").read_text(encoding="utf-8")
    assert "SIGTERM" not in poll and "signal.signal" not in poll
    for path in ("scripts/collector.py", "infra/production/compose.yml"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert not re.search(r"(?i)wind[- ]down", text), path
