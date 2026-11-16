"""An exhibit is marked attacker markup from what it is, not from what the uploader called it (independent review, CONSOLE-01).

`is_hostile_markup` decides two things and nothing else does: whether `GET .../content` and `POST .../export`
refuse (docs/19 section 1.1: the API origin never serves those bytes) and whether the console offers "Produce
through the sample origin" in place of "Export for disclosure", which saves under the title's extension. It
was derived from the part `Content-Type`, which the uploader writes: an HTML page sent as
`application/octet-stream`, or with no type, was exported from the application origin and saved as `.html`.

It is derived now from the declared type, the leading bytes and a markup extension on the title or the
uploaded file's name, each enough alone. Nothing re-derives it on read, so the flag stays the only thing the
route and the console look at.

Accounts `g44t-*`. The evidence store is a dictionary (`evidence_retention_support.VersionedStore`).
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import evidence_retention_support as g

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"


@pytest.fixture
def store(monkeypatch):
    st = g.VersionedStore()
    import noctornal_api.evidence as ev
    import noctornal_api.http.routers.evidence as evr
    monkeypatch.setattr(ev, "EvidenceStorage", lambda: st)
    monkeypatch.setattr(evr, "EvidenceStorage", lambda: st)
    return st


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


def _world(conn):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    return boss, case_id, g.token(conn, boss)


def _page() -> bytes:
    return b"<!DOCTYPE html><title>" + uuid4().hex.encode() + b"</title><script>1</script>"


def _plain() -> bytes:
    return b"hk-notes-" + uuid4().hex.encode()


def _upload(client, headers, case_id, data, *, filename="f.bin",
            declared="application/octet-stream", title="capture"):
    return client.post(f"{API}/cases/{case_id}/evidence", headers=headers,
                       files={"file": (filename, data, declared)},
                       data={"title": title, "classification": "AMBER"})


def _flag(conn, evidence_id) -> bool:
    return conn.execute("SELECT is_hostile_markup FROM core.evidence WHERE id = %s",
                        (evidence_id,)).fetchone()[0]


# declared type, uploaded file name, title, bytes, marked
_CASES = [
    ("octet-stream and a page", "application/octet-stream", "f.bin", "capture", _page, True),
    ("plain text and a page", "text/plain", "f.txt", "capture", _page, True),
    ("a page with a title that says nothing", "application/octet-stream", "f.bin", "x", _page, True),
    ("octet-stream and an .html title", "application/octet-stream", "f.bin", "capture.html",
     _plain, True),
    ("octet-stream and an .svg file name", "application/octet-stream", "lure.svg", "capture",
     _plain, True),
    ("an .eml title", "application/octet-stream", "f.bin", "remittance.EML", _plain, True),
    ("an .html title with the dots the file system drops", "application/octet-stream", "f.bin",
     "capture.html. ", _plain, True),
    ("text that is only text", "text/plain", "notes.txt", "notes.txt", _plain, False),
    ("octet-stream and a photo's name", "application/octet-stream", "f.bin", "photo.png",
     _plain, False),
]


@pytest.mark.parametrize("label,declared,filename,title,make,marked", _CASES,
                         ids=[c[0] for c in _CASES])
def test_an_upload_is_marked_from_what_it_is_and_the_routes_follow_the_mark(
        conn, store, client, label, declared, filename, title, make, marked):
    """The flag, then the two routes that read it. A marked exhibit is refused on the application origin
    on both routes, and the refusal is audited; one that is not marked is exported as before."""
    _boss, case_id, headers = _world(conn)
    data = make()
    up = _upload(client, headers, case_id, data, filename=filename, declared=declared,
                 title=title)
    assert up.status_code == 201, up.text
    evidence_id = up.json()["evidence_id"]
    assert _flag(conn, evidence_id) is marked, label

    content = client.get(f"{API}/cases/{case_id}/evidence/{evidence_id}/content",
                         headers=headers)
    export = client.post(f"{API}/cases/{case_id}/evidence/{evidence_id}/export",
                         headers=headers)
    if marked:
        assert content.status_code == 409 and export.status_code == 409, (
            content.text, export.text)
        assert data not in content.content and data not in export.content
        purposes = [r[0]["purpose"] for r in g.audit_rows(
            conn, "EVIDENCE_EGRESS_REFUSED", object_id=evidence_id)]
        assert purposes == ["content", "export"]
    else:
        assert content.status_code == 200 and export.status_code == 200
        assert export.content == data


def test_the_flag_is_what_the_register_hands_the_console(conn, store, client):
    """The console's "Produce through the sample origin" and its save name read `is_hostile_markup` from
    the register, so a row the upload marked is a row the console treats as markup."""
    _boss, case_id, headers = _world(conn)
    page = _upload(client, headers, case_id, _page(), title="capture").json()["evidence_id"]
    plain = _upload(client, headers, case_id, _plain(), title="photo.png").json()["evidence_id"]
    listing = client.get(f"{API}/cases/{case_id}/evidence", headers=headers)
    assert listing.status_code == 200, listing.text
    rows = {r["id"]: r for r in listing.json()["items"]}
    assert rows[page]["is_hostile_markup"] is True
    assert rows[plain]["is_hostile_markup"] is False


def test_a_service_caller_gets_the_same_derivation_and_can_still_say_otherwise(conn, store):
    """`ingest` derives the flag for every caller (a vendor answer filed as an exhibit, a seeder), from the
    title and the file name it is given as well as the bytes; True marks what nothing reveals, and False
    is the one way to un-mark, as before."""
    boss, case_id, _headers = _world(conn)

    def lodge(**kw):
        got = g.service(conn, store).ingest(
            case_id=case_id, title=kw.pop("title", "capture"),
            media_type=kw.pop("media_type", "application/octet-stream"),
            data=kw.pop("data", None) or _plain(), acquired_by=boss,
            acquisition_method="MANUAL_UPLOAD", classification="AMBER", **kw)
        return _flag(conn, got.evidence_id)

    assert lodge(data=_page()) is True
    assert lodge(title="capture.xml") is True
    assert lodge(filename="lure.mht") is True
    assert lodge() is False
    assert lodge(is_hostile_markup=True) is True
    assert lodge(data=_page(), is_hostile_markup=False) is False
    assert lodge(media_type="text/html", title="x") is True
