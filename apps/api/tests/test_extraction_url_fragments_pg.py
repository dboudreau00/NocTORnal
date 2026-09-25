"""The capture extractor trims prose punctuation from a URL, and two MEGA
links in one paste are two proposals (L5, 2026-09-24).

The URL pattern kept a sentence's full stop, comma or question mark, so a
link written in prose carried it into the raw value and the normaliser; and
`url_norm` dropped every fragment, so the second legacy MEGA link in a case
was "already known" and never proposed. Each test fails on ab27a4a.

The first two tests are pure; the capture test is env-gated on
DATABASE_URL. Email prefix `euf-`, titles `euf-`.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; capture test is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


def _urls(text: str):
    from noctornal_api.extraction import find_selectors
    return [h for h in find_selectors(text) if h.selector_type == "URL"]


@pytest.mark.parametrize("tail", [".", ",", ";", ":", "!", "?", "?!", ".,"])
def test_prose_punctuation_is_trimmed_and_offsets_stay_exact(tail):
    text = f"grab it here https://example.com/a/b{tail} thanks"
    [hit] = _urls(text)
    assert hit.raw_value == "https://example.com/a/b"
    assert text[hit.char_start:hit.char_end] == hit.raw_value
    assert hit.norm_value == "https://example.com/a/b"


def test_a_url_in_parentheses_and_a_mega_key_before_a_stop():
    text = "(see https://example.com/x) and https://mega.nz/#!AbCd1234!SecretKey."
    hits = _urls(text)
    assert [h.raw_value for h in hits] == [
        "https://example.com/x", "https://mega.nz/#!AbCd1234!SecretKey"]
    for h in hits:
        assert text[h.char_start:h.char_end] == h.raw_value
    assert hits[1].norm_value == "https://mega.nz/file/AbCd1234"
    assert "SecretKey" not in hits[1].norm_value


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'euf-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    docs = "(SELECT id FROM collect.document WHERE title LIKE 'euf-%')"
    with c.transaction():
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.extraction WHERE document_id IN {docs}")
        c.execute("DELETE FROM collect.document WHERE title LIKE 'euf-%'")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'euf-%'")
    c.close()


@needs_db
def test_capture_proposes_each_mega_link(conn):
    from noctornal_api.cases import CaseService
    from noctornal_api.extraction import CaptureService
    from noctornal_api.stores import PgUserStore
    owner = PgUserStore(conn).create_user(
        f"euf-{uuid4().hex[:8]}@noctornal.test", "EUF", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (owner,))
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-EUF-{uuid4().hex[:6]}", title="URL fragments",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner)
    text = ("first drop https://mega.nz/#!AbCd1234!keyone. second drop, "
            "https://mega.nz/#!ZzYy9876!keytwo, both live " + uuid4().hex)
    made = CaptureService(conn).capture(case_id=case_id, text=text,
                                        title=f"euf-{uuid4().hex[:6]}")
    labels = sorted(r[0] for r in conn.execute(
        """SELECT payload->>'label' FROM collect.proposal
            WHERE case_id = %s AND payload->'attrs'->>'selector_type' = 'URL'""",
        (case_id,)).fetchall())
    assert labels == ["https://mega.nz/file/AbCd1234",
                      "https://mega.nz/file/ZzYy9876"], (
        "two files, two proposals, not one and 'already known'")
    assert made.skipped_existing == 0
    payloads = " ".join(r[0] for r in conn.execute(
        "SELECT payload::text FROM collect.proposal WHERE case_id = %s "
        "AND payload->'attrs'->>'selector_type' = 'URL'",
        (case_id,)).fetchall())
    assert "keyone" not in labels[0] + labels[1]
    # The raw value is the evidence of what was written, key and all; the
    # label, which the graph and search show, carries none.
    assert "keyone" in payloads
