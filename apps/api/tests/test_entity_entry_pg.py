"""Add entity asks before it creates: is this already here, and is this a
selector the index can hold?

ux06-entry:no-duplicate-check-on-create and ux06-entry:selector-entities-
bypass-normalisation (2026-09-23). `POST /nodes` inserted whatever it was
given: "Harrow_Skua2" beside an existing "harrow_skua2" made a second
persona that split the actor's ties, and a Selector, Comms account or
Crypto wallet entity kept its raw label, so a bare Telegram id the Comms
pane refuses went in, the selector index never heard of it, and the same
selector seen elsewhere never correlated.

Held here, over HTTP against a real database:

- `POST .../graph/nodes/check` finds same-type entities whose label
  matches once case and whitespace are folded, and never one the caller
  cannot see, a merged-away one or another type;
- for a selector type it returns the canonical form, or the ontology's own
  refusal, and the entity the index already holds it against;
- `POST .../nodes` with `selector_type` records the selector against the
  new entity in the same transaction, refuses a label that reduces to
  nothing (and creates nothing), and reports a selector already held by
  another entity as a merge lead.

Every test fails on 245cb57, where neither the route nor the field exists.
Email prefix `eent-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; entity entry test is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "eent-"
GRADED = {"basis": "DIRECT_OBSERVATION", "reliability": "B",
          "credibility": "2", "confidence": "MODERATE"}


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, clearance):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", "Eent", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def world(conn):
    """A RED owner's AMBER case, an AMBER ANALYST on it, and some entities."""
    from noctornal_api.cases import CaseService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = _user(conn, "RED")
    analyst = _user(conn, "AMBER")
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-EENT-{uuid4().hex[:6]}", title="Entity entry",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification="AMBER")
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, analyst, owner))
    g = GraphWriteService(conn)
    a = AssertionInput(created_by=owner, **GRADED)

    def node(label, node_type="IDENTITY", classification="AMBER"):
        return g.create_node(case_id=case_id, node_type=node_type, label=label,
                             created_by=owner, assertion=a,
                             classification=classification)

    return {"case": case_id, "owner": owner, "analyst": analyst, "node": node,
            "g": g, "a": a}


def _check(client, conn, w, body, who="analyst"):
    r = client.post(f"/api/v1/cases/{w['case']}/graph/nodes/check",
                    headers=_auth(conn, w[who]), json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _create(client, conn, w, body, who="analyst"):
    body = {"classification": "AMBER", "assertion": GRADED, **body}
    return client.post(f"/api/v1/cases/{w['case']}/nodes",
                       headers=_auth(conn, w[who]), json=body)


# ---------------------------------------------------------------------------
# Is it already here?
# ---------------------------------------------------------------------------

def test_a_folded_label_of_the_same_type_is_found(conn, client, world):
    """The review's own reproduction: 'Harrow_Skua2' for 'harrow_skua2'."""
    w = world
    existing = w["node"]("harrow_skua2")
    w["node"]("harrow_skua2", node_type="PERSON")      # another type
    got = _check(client, conn, w, {"node_type": "IDENTITY",
                                   "label": "  Harrow_Skua2 "})
    assert [m["id"] for m in got["same_label"]] == [str(existing)]
    assert got["same_label"][0]["label"] == "harrow_skua2"
    # Runs of whitespace fold too; a different handle is not a match.
    w["node"]("tandem  logistics", node_type="ORGANISATION")
    assert len(_check(client, conn, w, {"node_type": "ORGANISATION",
                                        "label": "Tandem Logistics"})["same_label"]) == 1
    assert _check(client, conn, w, {"node_type": "IDENTITY",
                                    "label": "harrow_skua3"})["same_label"] == []


def test_a_look_alike_the_caller_cannot_see_is_not_a_match(conn, client, world):
    """A RED persona stays invisible to an AMBER analyst here exactly as
    it is in the entity list: the check is not a way to probe for it."""
    w = world
    w["node"]("quill_shrike66", classification="RED")
    assert _check(client, conn, w, {"node_type": "IDENTITY",
                                    "label": "Quill_Shrike66"})["same_label"] == []
    assert len(_check(client, conn, w, {"node_type": "IDENTITY",
                                        "label": "Quill_Shrike66"},
                      who="owner")["same_label"]) == 1


def test_a_merged_away_entity_is_not_offered(conn, client, world):
    w = world
    loser = w["node"]("ferric_auk98")
    winner = w["node"]("ferric auk 98")
    conn.execute("UPDATE core.node SET merged_into_id = %s WHERE id = %s",
                 (winner, loser))
    assert _check(client, conn, w, {"node_type": "IDENTITY",
                                    "label": "FERRIC_AUK98"})["same_label"] == []


# ---------------------------------------------------------------------------
# Selectors
# ---------------------------------------------------------------------------

def test_a_bare_telegram_id_is_refused_with_the_ontologys_reason(conn, client, world):
    """The same refusal the Comms pane and the selector index give."""
    got = _check(client, conn, world, {"node_type": "COMMS_ACCOUNT",
                                       "label": "123456789",
                                       "selector_type": "TELEGRAM_ID"})
    assert got["selector_norm"] is None
    assert "u:<id>" in got["selector_refusal"]


def test_a_selector_is_normalised_and_its_owner_named(conn, client, world):
    from noctornal_api.selectors import SelectorStore
    w = world
    holder = w["node"]("spectre.lynx@nightmarket.example", node_type="COMMS_ACCOUNT")
    got = _check(client, conn, w, {"node_type": "COMMS_ACCOUNT",
                                   "label": " Spectre.Lynx@NightMarket.example/desktop-01",
                                   "selector_type": "JABBER"})
    assert got["selector_norm"] == "spectre.lynx@nightmarket.example"
    assert got["selector_refusal"] is None
    assert got["selector_is_strong"] is True
    assert got["selector_owner"] is None, "not in the index yet"

    SelectorStore(conn).record(case_id=w["case"], selector_type="JABBER",
                               raw_value="spectre.lynx@nightmarket.example",
                               node_id=holder)
    got = _check(client, conn, w, {"node_type": "COMMS_ACCOUNT",
                                   "label": "SPECTRE.LYNX@nightmarket.example",
                                   "selector_type": "JABBER"})
    assert got["selector_owner"]["id"] == str(holder)


def test_creating_a_selector_entity_records_the_selector(conn, client, world):
    w = world
    r = _create(client, conn, w, {"node_type": "WALLET",
                                  "label": " bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq ",
                                  "selector_type": "BTC_ADDR"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["selector_norm"] == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    assert body["selector_owner_id"] is None
    row = conn.execute(
        "SELECT node_id, norm_value FROM core.selector WHERE case_id = %s "
        "AND selector_type = 'BTC_ADDR'", (w["case"],)).fetchone()
    assert str(row[0]) == body["id"]


def test_a_refused_selector_creates_nothing(conn, client, world):
    w = world
    before = conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                          (w["case"],)).fetchone()[0]
    r = _create(client, conn, w, {"node_type": "COMMS_ACCOUNT",
                                  "label": "123456789",
                                  "selector_type": "TELEGRAM_ID"})
    assert r.status_code == 400, r.text
    assert "u:<id>" in r.json()["detail"]
    after = conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                         (w["case"],)).fetchone()[0]
    assert after == before


def test_a_selector_type_on_a_persona_is_refused(conn, client, world):
    r = _create(client, conn, world, {"node_type": "IDENTITY",
                                      "label": "harrow_skua2",
                                      "selector_type": "HANDLE"})
    assert r.status_code == 400, r.text


def test_a_selector_already_held_is_a_merge_lead(conn, client, world):
    """The index keeps the first owner, so the second entity does not get
    the selector, and the response says who has it."""
    w = world
    first = _create(client, conn, w, {"node_type": "COMMS_ACCOUNT",
                                      "label": "vendor@exploit.im",
                                      "selector_type": "JABBER"}).json()
    second = _create(client, conn, w, {"node_type": "COMMS_ACCOUNT",
                                       "label": "Vendor@Exploit.im/phone",
                                       "selector_type": "JABBER"})
    assert second.status_code == 201, second.text
    assert second.json()["selector_owner_id"] == first["id"]
    assert second.json()["selector_is_strong"] is True
    owners = conn.execute(
        "SELECT node_id FROM core.selector WHERE case_id = %s", (w["case"],)
    ).fetchall()
    assert [str(o[0]) for o in owners] == [first["id"]]


# ---------------------------------------------------------------------------
# What the inspector and the forms read
# ---------------------------------------------------------------------------

def test_the_entity_count_is_what_the_caller_can_see(conn, client, world):
    """ux06-entry:entity-list-no-find: the list said "1000 of 1000" on a
    larger case. The count is the list's rows without the page, and never
    counts what the caller cannot see."""
    w = world
    w["node"]("eent_one")
    w["node"]("eent_two")
    w["node"]("eent_red", classification="RED")
    gone = w["node"]("eent_gone")
    conn.execute("UPDATE core.node SET deleted_at = now() WHERE id = %s", (gone,))

    def total(who):
        r = client.get(f"/api/v1/cases/{w['case']}/graph/nodes/count",
                       headers=_auth(conn, w[who]))
        assert r.status_code == 200, r.text
        return r.json()["total"]

    assert total("analyst") == 2
    assert total("owner") == 3


def test_the_relationship_count_is_the_tie_list_without_its_page(
        conn, client, world):
    """The count line's "N relationships in the case" was the length of the
    1000-row `/edges` page (the 2026-09-23 verifier), so a larger case read
    "1000 relationships". The count is what `GET /edges` would list for the
    caller with no page: a tie above them, or at an entity above them, is
    not counted, and neither is a retired one."""
    from datetime import datetime, timezone
    w = world
    one, two = w["node"]("eent_one"), w["node"]("eent_two")
    red = w["node"]("eent_red", classification="RED")

    def tie(src, dst, classification="AMBER", edge_type="COMMUNICATES_WITH"):
        return w["g"].create_edge(
            case_id=w["case"], edge_type=edge_type, src_node_id=src,
            dst_node_id=dst, created_by=w["owner"], assertion=w["a"],
            classification=classification)

    tie(one, two)
    tie(one, two, classification="RED", edge_type="VOUCHED_FOR")
    tie(one, red)
    gone = tie(two, one)
    w["g"].soft_delete_edge(gone, case_id=w["case"], deleted_by=w["owner"],
                            at=datetime.now(timezone.utc))

    for who, expected in (("analyst", 1), ("owner", 3)):
        headers = _auth(conn, w[who])
        r = client.get(f"/api/v1/cases/{w['case']}/graph/nodes/count",
                       headers=headers)
        assert r.status_code == 200, r.text
        listed = client.get(f"/api/v1/cases/{w['case']}/edges?limit=2000",
                            headers=headers).json()
        assert r.json()["edges"] == len(listed) == expected, who


def test_the_ontology_gives_inverse_names_and_selector_types(conn, client, world):
    """ux06-entry:edge-type-note-stale reads a type both ways; the entity
    form's selector picker is built from the ontology's own list."""
    w = world
    body = client.get(f"/api/v1/cases/{w['case']}/ontology",
                      headers=_auth(conn, w["analyst"])).json()
    by_key = {t["key"]: t for t in body["edge_types"]}
    assert by_key["VOUCHED_FOR"]["inverse_name"] == "was vouched by"
    selectors = {s["key"]: s for s in body["selector_types"]}
    assert selectors["JABBER"]["is_strong"] is True
    assert selectors["HANDLE"]["is_strong"] is False


def test_a_selectors_dates_travel_with_its_count(conn, client, world):
    """ux05-inspector:first-last-seen-always-dash: "observed 3 times" came
    with no date although the selector row keeps both."""
    from datetime import datetime, timezone

    from noctornal_api.selectors import SelectorStore
    w = world
    holder = w["node"]("spectre.lynx@nightmarket.example", node_type="COMMS_ACCOUNT")
    store = SelectorStore(conn)
    for day in (27, 3):
        month = 8 if day == 27 else 9
        store.record(case_id=w["case"], selector_type="JABBER",
                     raw_value="spectre.lynx@nightmarket.example", node_id=holder,
                     observed_at=datetime(2025, month, day, tzinfo=timezone.utc))
    rows = client.get(f"/api/v1/cases/{w['case']}/nodes/{holder}/selectors",
                      headers=_auth(conn, w["analyst"])).json()
    assert rows[0]["observation_cnt"] == 2
    assert rows[0]["first_seen"].startswith("2025-08-27")
    assert rows[0]["last_seen"].startswith("2025-09-03")


def test_the_check_needs_authentication(client):
    r = client.post(f"/api/v1/cases/{uuid4()}/graph/nodes/check",
                    json={"node_type": "IDENTITY", "label": "x"})
    assert r.status_code == 401
