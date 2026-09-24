"""What the readiness register says about a failing row, beyond pass or
fail (2026-09-23, the ux16-admin review of the Admin pane).

- `consequence`: what the product refuses while a BLOCKING check fails.
  The banner's headline was hard-coded to "the collection poll route is
  refused" while its own items said ingest, every download and
  break-glass were refused too (blocking-headline-understates-impact).
- `ui_target`: where in the console a check is settled, so the pane can
  link there instead of printing a path template for curl
  (readiness-actions-speak-api).
- `checked_at`: when the report was taken, so a report from before a fix
  can be told from a fresh one (readiness-stale-after-fix).
- the security officer's evidence names who holds the role, and its
  `caveat` says when the only one can invoke break-glass, which is then
  refused to them, because nobody reviews their own
  (security-officer-false-green). A caveat and not evidence, because the
  console folds passing rows away and a warning in their evidence was
  never read.

The first half is pure. The database half is gated and runs inside
transactions it rolls back, because it has to change who is an officer.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from noctornal_api import readiness

STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
          / "http" / "static")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the database half is gated")


def test_a_failing_blocker_carries_its_consequence_and_a_passing_one_does_not():
    failing = readiness._register_facts(
        "prohibited_content_policy",
        readiness.Check("prohibited_content_policy", False, "e", "a"))
    assert failing.blocking is True
    assert failing.consequence == "Sample ingest is refused."
    passing = readiness._register_facts(
        "prohibited_content_policy",
        readiness.Check("prohibited_content_policy", True, "e"))
    assert passing.consequence == "" and passing.ui_target == "", (
        "a passing check says what it refuses; nothing is refused")


def test_every_consequence_belongs_to_a_blocking_check():
    """A consequence on a check nothing refuses on would put a refusal in
    the banner's headline that the product does not make."""
    assert set(readiness.CONSEQUENCES) <= set(readiness.BLOCKING_CHECKS)
    for text in readiness.CONSEQUENCES.values():
        assert text.endswith(".") and "refused" in text, text


def test_a_probe_that_crashed_still_says_what_it_refuses():
    crashed = readiness._register_facts(
        "security_officer_present",
        readiness.Check("security_officer_present", False, "boom", "x"))
    assert "Break-glass is refused" in crashed.consequence
    assert crashed.ui_target == "admin/accounts"


def test_every_ui_target_names_a_tab_and_subtab_the_console_has():
    """Named by the console's own `data-tab` and `data-subtab`, so a
    renamed subtab turns this red instead of shipping a dead link."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert set(readiness.UI_TARGETS) <= set(readiness.CHECK_NAMES)
    for name, target in readiness.UI_TARGETS.items():
        tab, sub = target.split("/")
        assert f'data-tab="{tab}"' in html, (name, target)
        start = html.index(f'<section id="pane-{tab}"')
        pane = html[start:html.index("</section>", start)]
        assert f'data-subtab="{sub}"' in pane, (
            f"{name} points at {target} and pane-{tab} has no such subtab")


def test_the_retention_action_names_the_console_first_and_keeps_the_route():
    src = (Path(readiness.__file__)).read_text(encoding="utf-8")
    body = src[src.index("def _retention_rules_confirmed("):]
    body = body[:body.index("\ndef ")]
    # "under Records, ": the rail tab's name since ux19. It said Lifecycle,
    # a name that leads nowhere (u23, 2026-09-24).
    assert body.index("under Records, ") < body.index("POST"), (
        "the retention action leads with curl again")
    assert "/retention/rules" in body


@needs_db
def test_the_report_says_when_it_was_taken():
    from noctornal_api.db import connect
    with connect() as conn:
        report = readiness.report(conn)
    at = datetime.fromisoformat(report["checked_at"])
    assert at.utcoffset() == timezone.utc.utcoffset(None)
    assert abs((datetime.now(timezone.utc) - at).total_seconds()) < 120


def _officer(conn, *roles):
    from noctornal_api.stores import PgUserStore
    email = f"rgf-{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(conn).create_user(email, "Rgf", "correct-horse-battery-9")
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return email


def _only_officers(conn):
    conn.execute(
        """UPDATE iam.app_user SET is_active = false
            WHERE id IN (SELECT user_id FROM iam.user_role
                          WHERE role_key = 'SECURITY_OFFICER')""")


@needs_db
def test_a_lone_officer_who_can_invoke_break_glass_is_named_and_warned():
    from noctornal_api.db import connect
    with connect() as conn:
        with conn.transaction(force_rollback=True):
            _only_officers(conn)
            email = _officer(conn, "SECURITY_OFFICER", "SYS_ADMIN")
            check = readiness._security_officer_present(conn)
    assert check.ok is True, (
        "a single-operator install is a documented design choice and must "
        "not refuse collection")
    assert check.evidence.startswith("1 active SECURITY_OFFICER account")
    assert email in check.evidence
    # In the caveat, which the console draws outside the fold, and not in
    # the evidence, which it folds away with every passing row.
    assert "second person" not in check.evidence
    assert check.caveat.startswith(email + " is the only Security Officer")
    assert "refused to them until a second person" in check.caveat
    assert "Grant SECURITY_OFFICER to a second person" in check.caveat
    stamped = readiness._register_facts("security_officer_present", check)
    assert stamped.caveat == check.caveat
    assert stamped.ui_target == "admin/accounts", (
        "the caveat says to grant the role and offers no way to where it is")
    assert stamped.consequence == "", "a passing check refuses nothing"


@needs_db
def test_two_officers_or_one_who_invokes_nothing_carry_no_warning():
    from noctornal_api.db import connect
    with connect() as conn:
        with conn.transaction(force_rollback=True):
            _only_officers(conn)
            _officer(conn, "SECURITY_OFFICER")
            alone = readiness._security_officer_present(conn)
            _officer(conn, "SECURITY_OFFICER", "SYS_ADMIN")
            pair = readiness._security_officer_present(conn)
    assert alone.caveat == "" and "second person" not in alone.evidence
    assert pair.evidence.startswith("2 active SECURITY_OFFICER accounts")
    assert pair.caveat == "" and "second person" not in pair.evidence
    assert readiness._register_facts(
        "security_officer_present", pair).ui_target == "", (
        "a clean pass grew a way to somewhere")


@needs_db
def test_the_way_in_is_marked_while_the_officer_check_carries_a_caveat():
    """`blocking_state` is what `GET /admin/access` answers with; the
    Readiness section is marked from its caveats, and its failures are
    exactly `blocking_failures`."""
    from noctornal_api.db import connect
    with connect() as conn:
        with conn.transaction(force_rollback=True):
            _only_officers(conn)
            _officer(conn, "SECURITY_OFFICER", "SYS_ADMIN")
            lone = readiness.blocking_state(conn)
            failures = readiness.blocking_failures(conn)
            _officer(conn, "SECURITY_OFFICER")
            pair = readiness.blocking_state(conn)
    assert lone["caveats"] == ["security_officer_present"], lone
    assert lone["failures"] == failures
    assert "security_officer_present" not in lone["failures"]
    assert pair["caveats"] == [], pair


def test_a_caveat_is_dropped_from_a_failed_row_and_kept_on_a_pass():
    """A failed row has an action; a caveat on it as well would be the row
    saying two different things about itself."""
    failed = readiness._register_facts(
        "security_officer_present",
        readiness.Check("security_officer_present", False, "e", "a", caveat="c"))
    assert failed.caveat == ""
    passed = readiness._register_facts(
        "security_officer_present",
        readiness.Check("security_officer_present", True, "e", caveat="c"))
    assert passed.caveat == "c" and passed.as_dict()["caveat"] == "c"


@needs_db
def test_no_officer_sends_the_operator_to_the_console_before_the_api():
    from noctornal_api.db import connect
    with connect() as conn:
        with conn.transaction(force_rollback=True):
            _only_officers(conn)
            check = readiness._security_officer_present(conn)
    assert check.ok is False and check.evidence.startswith("0 active")
    assert re.search(r"Admin, Accounts.*POST /admin/users", check.action), (
        check.action)
