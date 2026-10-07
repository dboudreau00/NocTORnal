"""The live socket and the labels of what changed (http_ui-012, http_ui-013; g45, 2026-10-03).

http_ui-012: the statement triggers announced every node and edge write in
a case to every subscriber who may read the case, so a RED or compartmented
node written in an AMBER case woke the AMBER analyst's console. The hint has
no content, but its existence and its time are a channel. 0146 puts the
labels a reader would need into the NOTIFY payload; the socket asks the
access gate per delivery and drops what the subscriber may not read. The
labels never reach the client.

http_ui-013: the first frame is untrusted input that arrives before any
credential is checked; a list, a number or an object where a case id
belongs raised AttributeError out of the handshake, a traceback per
connection for a peer with no session.

Accounts carry the prefix `g45live-`, unique to this file.
"""
from __future__ import annotations

import json
import os
import time
from uuid import uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "g45live-"
CHANNEL = "noctornal_change"
PEER = "203.0.113.77"      # TEST-NET, never a real peer
COMPARTMENTS = tuple(f"G45-LIVE-{i:02d}" for i in range(11))


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    cases = ("(SELECT id FROM core.\"case\" WHERE owner_user_id IN "
             f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'))")
    c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {cases}")
    c.execute(f"DELETE FROM collect.document WHERE title LIKE '{PREFIX}%'")
    c.execute(f"DELETE FROM collect.source WHERE name LIKE '{PREFIX}%'")
    s.cleanup(c, prefix=PREFIX)
    c.close()


@pytest.fixture
def world(owner):
    """A RED lead who owns an AMBER case, an AMBER analyst and a RED analyst
    holding one compartment, both assigned."""
    lead = s.user(owner, "RED", compartments=(COMPARTMENTS[0],), prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    cleared = s.user(owner, "RED", compartments=(COMPARTMENTS[0],), prefix=PREFIX)
    case_id = s.case(owner, lead)
    s.assign(owner, case_id, analyst)
    s.assign(owner, case_id, cleared)
    return {"lead": lead, "analyst": analyst, "cleared": cleared, "case": case_id}


def _listener():
    c = s.owner_conn()
    c.execute(f"LISTEN {CHANNEL}")
    return c


def _heard(listener, case_id, seconds=1.5):
    out = []
    for note in listener.notifies(timeout=seconds):
        payload = json.loads(note.payload)
        if payload.get("case_id") == str(case_id):
            out.append(payload)
    return out


def _labels(payload):
    return {(cls, tuple(comps)) for cls, comps in payload["labels"]}


# ---------------------------------------------------------------------------
# What the payload says
# ---------------------------------------------------------------------------

def test_the_notify_payload_names_the_labels_of_what_was_written(owner, world):
    case_id, lead = world["case"], world["lead"]
    listener = _listener()
    try:
        s.node(owner, case_id, lead, "red entity", "RED")
        s.node(owner, case_id, lead, "amber entity", "AMBER")
        s.node(owner, case_id, lead, "compartmented entity", "AMBER",
               compartments=(COMPARTMENTS[0],))
        events = [e for e in _heard(listener, case_id) if e["kind"] == "node"
                  and e["op"] == "INSERT"]
    finally:
        listener.close()
    assert [_labels(e) for e in events] == [
        {("RED", ())}, {("AMBER", ())}, {("AMBER", (COMPARTMENTS[0],))}]


def test_a_tie_is_announced_under_the_join_of_its_own_and_its_endpoints_labels(owner, world):
    """A tie is read only where both ends are, so an AMBER tie attached to a
    RED entity is a RED event."""
    case_id, lead = world["case"], world["lead"]
    a = s.node(owner, case_id, lead, "amber one", "AMBER")
    b = s.node(owner, case_id, lead, "amber two", "AMBER")
    red = s.node(owner, case_id, lead, "red one", "RED")
    listener = _listener()
    try:
        s.edge(owner, case_id, lead, a, b, "AMBER")
        s.edge(owner, case_id, lead, a, red, "AMBER")
        events = [e for e in _heard(listener, case_id)
                  if e["kind"] == "edge" and e["op"] == "INSERT"]
    finally:
        listener.close()
    assert [_labels(e) for e in events] == [{("AMBER", ())}, {("RED", ())}]


def test_an_update_is_announced_under_the_old_and_the_new_labels(owner, world):
    """A reclassification must reach the people who could see the element
    (their view has to change) and the people who can now."""
    case_id, lead = world["case"], world["lead"]
    node = s.node(owner, case_id, lead, "to be raised", "AMBER")
    listener = _listener()
    try:
        owner.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s", (node,))
        events = [e for e in _heard(listener, case_id) if e["kind"] == "node"
                  and e["op"] == "UPDATE"]
    finally:
        listener.close()
    assert len(events) == 1
    assert _labels(events[0]) == {("AMBER", ()), ("RED", ())}


def test_one_statement_is_one_event_and_a_delete_is_announced_under_its_old_labels(owner, world):
    case_id, lead = world["case"], world["lead"]
    nodes = [s.node(owner, case_id, lead, f"n{i}", "AMBER") for i in range(3)]
    listener = _listener()
    try:
        owner.execute("UPDATE core.node SET updated_at = now() WHERE case_id = %s", (case_id,))
        updates = [e for e in _heard(listener, case_id) if e["kind"] == "node"]
        assert len(updates) == 1, "the trigger is no longer statement-level"
        assert _labels(updates[0]) == {("AMBER", ())}
        owner.execute("ALTER TABLE core.assertion DISABLE TRIGGER USER")
        try:
            owner.execute("DELETE FROM core.assertion WHERE case_id = %s", (case_id,))
        finally:
            owner.execute("ALTER TABLE core.assertion ENABLE TRIGGER USER")
        _heard(listener, case_id)
        owner.execute("DELETE FROM core.node WHERE id = %s", (nodes[0],))
        deletes = [e for e in _heard(listener, case_id) if e["op"] == "DELETE"]
    finally:
        listener.close()
    assert len(deletes) == 1 and _labels(deletes[0]) == {("AMBER", ())}


def test_a_statement_writing_more_than_32_distinct_pairs_announces_none(owner, world):
    case_id, lead = world["case"], world["lead"]
    s.register(owner, *COMPARTMENTS)
    for cls in ("AMBER", "AMBER_STRICT", "RED"):
        for key in COMPARTMENTS:
            s.node(owner, case_id, lead, f"{cls} {key}", cls, compartments=(key,))
    listener = _listener()
    try:
        owner.execute("UPDATE core.node SET updated_at = now() WHERE case_id = %s", (case_id,))
        events = [e for e in _heard(listener, case_id, seconds=3.0) if e["kind"] == "node"]
    finally:
        listener.close()
    assert len(events) == 1 and events[0]["labels"] is None


def test_a_tie_is_announced_under_the_join_even_when_the_writer_cannot_see_an_endpoint(
        owner, world):
    """The function reads the endpoints as the definer (0113's rule for any
    trigger function that reads a policied table, which `test_rls_registry_pg`
    holds). Read as the writer, an AMBER analyst touching an AMBER tie that
    is attached to a RED entity would show no RED endpoint and announce the
    wrong pair, exactly when it matters."""
    case_id, lead, analyst = world["case"], world["lead"], world["analyst"]
    a = s.node(owner, case_id, lead, "visible", "AMBER")
    red = s.node(owner, case_id, lead, "hidden", "RED")
    edge = s.edge(owner, case_id, lead, a, red, "AMBER")
    _sid, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    listener = _listener()
    try:
        n = app.execute("UPDATE core.edge SET updated_at = now() WHERE id = %s", (edge,)).rowcount
        events = [e for e in _heard(listener, case_id) if e["kind"] == "edge"]
    finally:
        listener.close()
        app.close()
    assert n == 1, "the AMBER analyst could not touch an AMBER tie"
    assert len(events) == 1 and _labels(events[0]) == {("RED", ())}


# ---------------------------------------------------------------------------
# The per-delivery decision
# ---------------------------------------------------------------------------

def test_change_visible_asks_the_gate_per_pair(owner, world):
    from noctornal_api.http.routers.live import _change_visible
    case_id, analyst, cleared = world["case"], world["analyst"], world["cleared"]

    def seen(user, labels):
        return _change_visible(user, case_id, None, labels)

    # The AMBER analyst, in an AMBER case.
    assert seen(analyst, [["AMBER", []]]) is True
    assert seen(analyst, [["GREEN", []]]) is True, "a lower label is read at the case's own"
    assert seen(analyst, [["RED", []]]) is False
    assert seen(analyst, [["AMBER_STRICT", []]]) is False
    assert seen(analyst, [["AMBER", [COMPARTMENTS[0]]]]) is False
    assert seen(analyst, [["RED", []], ["AMBER", []]]) is True, "one readable pair delivers"
    # The RED analyst holding the compartment.
    assert seen(cleared, [["RED", [COMPARTMENTS[0]]]]) is True
    assert seen(cleared, [["RED", [COMPARTMENTS[1]]]]) is False
    # What it cannot place is dropped, never delivered.
    for unplaceable in (None, [], "RED", [["RED"]], [["RED", []], 7], [[1, []]],
                        [["NOT_A_LABEL", []]], [["AMBER", "x"]], {"RED": []}):
        assert seen(analyst, unplaceable) is False, unplaceable
    # And not a member of the case at all.
    stranger = s.user(owner, "RED", prefix=PREFIX)
    assert seen(stranger, [["AMBER", []]]) is False


# ---------------------------------------------------------------------------
# The socket, end to end
# ---------------------------------------------------------------------------

@pytest.fixture
def live(monkeypatch):
    from noctornal_api.http.routers import live as module
    monkeypatch.delenv("NOCTORNAL_SESSION_STRICT_BINDING", raising=False)
    monkeypatch.setattr(module, "_PING_SECONDS", 0.2)
    # A hub per test: its lock and stop flag belong to the event loop of the
    # first client that used them, and each TestClient runs its own.
    monkeypatch.setattr(module, "_hub", module._Hub())
    return module


def _app():
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return app


def _until_change(ws, seconds=20.0):
    """The next change message, or None after `seconds` of wall time. A
    wall-clock window and not a count of pings (2026-10-03): the pings come every 0.2 s
    here, so a count of forty was an
    eight second window that a loaded machine could spend on slow session
    checks, and the socket test failed intermittently."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        message = ws.receive_json()
        if message["type"] == "change":
            return message
    return None


def test_the_socket_pushes_nothing_about_an_element_above_the_subscriber(owner, world, live):
    from fastapi.testclient import TestClient
    case_id, lead, analyst = world["case"], world["lead"], world["analyst"]
    _sid, token = s.session(owner, analyst)
    with TestClient(_app(), client=(PEER, 41000)) as client:
        with client.websocket_connect("/api/v1/live") as ws:
            ws.send_json({"token": token, "case_id": str(case_id)})
            assert ws.receive_json()["type"] == "ready"
            time.sleep(1.0)      # the hub's LISTEN registers after `ready`
            # Restricted activity: a RED entity, a compartmented one, and a
            # tie between an AMBER entity and a RED one.
            a = s.node(owner, case_id, lead, "amber anchor", "AMBER")
            s.node(owner, case_id, lead, "red", "RED")
            s.node(owner, case_id, lead, "compartmented", "AMBER",
                   compartments=(COMPARTMENTS[0],))
            hidden = s.node(owner, case_id, lead, "red end", "RED")
            s.edge(owner, case_id, lead, a, hidden, "AMBER")
            # The first AMBER node above is the only readable write so far:
            # its hint is the one change the analyst may be told. Take it,
            # then watch a long stretch of pings for any other.
            first = _until_change(ws)
            assert first == {"type": "change", "kind": "node", "op": "INSERT"}
            late = [ws.receive_json() for _ in range(15)]
            assert [m["type"] for m in late] == ["ping"] * 15, (
                "a hint about an element above the subscriber was delivered")
            # A readable write is delivered, as before, and carries no label.
            s.node(owner, case_id, lead, "amber again", "AMBER")
            change = _until_change(ws)
            assert change == {"type": "change", "kind": "node", "op": "INSERT"}
            assert "labels" not in change


def test_a_subscriber_cleared_for_the_restricted_element_is_told(owner, world, live):
    from fastapi.testclient import TestClient
    case_id, lead, cleared = world["case"], world["lead"], world["cleared"]
    _sid, token = s.session(owner, cleared)
    with TestClient(_app(), client=(PEER, 41001)) as client:
        with client.websocket_connect("/api/v1/live") as ws:
            ws.send_json({"token": token, "case_id": str(case_id)})
            assert ws.receive_json()["type"] == "ready"
            time.sleep(1.0)      # the hub's LISTEN registers after `ready`
            s.node(owner, case_id, lead, "red for the cleared", "RED")
            assert _until_change(ws) == {"type": "change", "kind": "node", "op": "INSERT"}


# ---------------------------------------------------------------------------
# http_ui-013: the hello
# ---------------------------------------------------------------------------

def _close_of(client, frame, *, raw=False, binary=False):
    """What the socket does with `frame` as the first message: ('close',
    code, reason), ('message', body) or ('exception', name). A server-side
    exception is re-raised by the test client, which is exactly what this
    must not see. `raw` sends the string as a text frame as it is, `binary`
    sends the bytes as a binary frame."""
    from starlette.websockets import WebSocketDisconnect
    try:
        with client.websocket_connect("/api/v1/live") as ws:
            if binary:
                ws.send_bytes(frame)
            elif raw:
                ws.send_text(frame)
            else:
                ws.send_json(frame)
            try:
                return ("message", ws.receive_json())
            except WebSocketDisconnect as closed:
                return ("close", closed.code, closed.reason)
    except Exception as exc:  # noqa: BLE001
        return ("exception", type(exc).__name__)


@pytest.mark.parametrize("frame", [
    [1, 2], 7, "text", True, {"token": "x", "case_id": 5}, {"token": "x", "case_id": [1]},
    {"token": "x", "case_id": {"a": 1}}, {"token": 5, "case_id": None},
    {"token": ["x"], "case_id": None}, {"case_id": 5.5},
], ids=["list", "number", "string", "bool", "int_case", "list_case", "object_case",
        "int_token", "list_token", "float_case"])
def test_a_malformed_hello_is_a_clean_close_not_an_exception(live, frame):
    from fastapi.testclient import TestClient
    with TestClient(_app(), client=(PEER, 41002)) as client:
        outcome = _close_of(client, frame)
        assert outcome[0] == "close", outcome
        assert outcome[1] == 1008, outcome
        # The pending slot was released on the way out.
        assert live._pending.count == 0


def test_a_json_null_hello_and_an_empty_one_still_close_for_want_of_credentials(live):
    from fastapi.testclient import TestClient
    with TestClient(_app(), client=(PEER, 41003)) as client:
        assert _close_of(client, None) == ("close", 1008, "no credentials")
        assert _close_of(client, {}) == ("close", 1008, "no credentials")
        assert _close_of(client, "{not json", raw=True) == ("close", 1008, "no credentials")


# Why these are separate from the list above (2026-10-03): they are not shapes of JSON. The
# first fix closed every hello
# that DECODES to the wrong thing, and left a binary frame (KeyError out of
# Starlette's receive_json) and JSON nested past the interpreter's limit
# (RecursionError) raising out of the handshake, a logged traceback per
# connection from a peer with no session. The deep frames below are built
# to fit under the hello's own length bound, because a longer frame never
# reaches the parser; where exactly a parser gives up depends on the
# interpreter build, so the RecursionError itself is also forced.
_DEEP_ARRAY = "[" * 4000
_DEEP_OBJECT = '{"a":' * 800


@pytest.mark.parametrize("frame,reason", [
    (b"\x00\x01", "bad hello"),
    (b'{"token":"x","case_id":null}', "bad hello"),
    (b"", "bad hello"),
], ids=["binary", "binary_json_bytes", "empty_binary"])
def test_a_binary_first_frame_is_a_clean_close(live, frame, reason):
    from fastapi.testclient import TestClient
    with TestClient(_app(), client=(PEER, 41005)) as client:
        assert _close_of(client, frame, binary=True) == ("close", 1008, reason)
        assert live._pending.count == 0


@pytest.mark.parametrize("frame", [_DEEP_ARRAY, _DEEP_OBJECT],
                         ids=["deep_array", "deep_object"])
def test_json_nested_deeply_is_a_clean_close(live, frame):
    """Whether this build's parser gives up on the nesting (it raised
    RecursionError here before the fix) or reads it as the wrong kind of
    hello, the answer is a policy close and not an exception."""
    from fastapi.testclient import TestClient
    assert len(frame) <= live._HELLO_MAX_CHARS, "the case must reach the parser"
    with TestClient(_app(), client=(PEER, 41006)) as client:
        outcome = _close_of(client, frame, raw=True)
        assert outcome[:2] == ("close", 1008), outcome
        assert outcome[2] in ("no credentials", "bad hello"), outcome
        assert live._pending.count == 0


def test_a_parser_that_gives_up_with_recursion_error_is_a_clean_close(live, monkeypatch):
    """The failure the review reproduced, forced: `json.loads` raising
    RecursionError on the hello. Not a ValueError, so the first handler
    missed it. Only the hello's text is intercepted; the test client reads
    its own replies through the same function."""
    import json

    from fastapi.testclient import TestClient
    real = json.loads

    def giving_up(text, *args, **kwargs):
        if isinstance(text, str) and "recursion-probe" in text:
            raise RecursionError("maximum recursion depth exceeded while decoding")
        return real(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", giving_up)
    with TestClient(_app(), client=(PEER, 41009)) as client:
        assert _close_of(client, '{"recursion-probe": 1}', raw=True) == (
            "close", 1008, "no credentials")
        assert live._pending.count == 0


def test_a_hello_longer_than_any_hello_is_refused_unparsed(live, monkeypatch):
    """A 5 MiB token was read, decoded and parsed before the socket said
    'no such case'; the bound is on the frame, ahead of the parse."""
    import json

    from fastapi.testclient import TestClient

    def refuse(*_a, **_k):
        raise AssertionError("an over-long hello reached the JSON parser")

    monkeypatch.setattr(json, "loads", refuse)
    huge = '{"token": "' + "t" * live._HELLO_MAX_CHARS + '", "case_id": null}'
    with TestClient(_app(), client=(PEER, 41007)) as client:
        assert _close_of(client, huge, raw=True) == ("close", 1008, "bad hello")
        assert live._pending.count == 0


def test_a_hello_at_the_bound_is_still_read(live):
    """The bound is a ceiling on junk, not a change to what a real hello
    is: a session token is 43 characters and a case id 36."""
    import json
    hello = json.dumps({"token": "t" * 43, "case_id": "0" * 36})
    assert len(hello) < live._HELLO_MAX_CHARS // 10
    from fastapi.testclient import TestClient
    with TestClient(_app(), client=(PEER, 41008)) as client:
        assert _close_of(client, hello, raw=True)[2] in ("bad case id", "no such case")


def test_a_peer_that_leaves_before_the_hello_is_still_not_a_traceback(live):
    """The disconnect message is turned into WebSocketDisconnect by
    `_read_hello`, as `receive_json` did, so the handshake's one handler
    for a vanished peer still catches it."""
    import asyncio

    from starlette.websockets import WebSocketDisconnect

    class Gone:
        async def receive(self):
            return {"type": "websocket.disconnect", "code": 1001, "reason": "away"}

    with pytest.raises(WebSocketDisconnect) as raised:
        asyncio.run(live._read_hello(Gone()))
    assert raised.value.code == 1001


def test_a_good_hello_is_unchanged(owner, world, live):
    from fastapi.testclient import TestClient
    _sid, token = s.session(owner, world["analyst"])
    with TestClient(_app(), client=(PEER, 41004)) as client:
        with client.websocket_connect("/api/v1/live") as ws:
            ws.send_json({"token": token, "case_id": str(world["case"])})
            assert ws.receive_json() == {"type": "ready", "case_id": str(world["case"])}
        with client.websocket_connect("/api/v1/live") as ws:
            ws.send_json({"token": token, "case_id": None})
            assert ws.receive_json() == {"type": "ready", "case_id": None}


# ---------------------------------------------------------------------------
# 2026-10-07: a token that cannot be one (G1)
# ---------------------------------------------------------------------------

BS = "\\"


@pytest.mark.parametrize("frame", [
    '{"token":"' + BS + 'ud800","case_id":null}',
    '{"token":"' + BS + 'udc00x","case_id":null}',
    '{"token":"t' + BS + 'u00f6k' + BS + 'u00e9n","case_id":null}',
    '{"token":"' + "a" * 513 + '","case_id":null}',
], ids=["lone_high_surrogate", "lone_low_surrogate", "non_ascii", "over_512"])
def test_a_token_that_cannot_be_a_session_token_is_a_policy_close_not_a_traceback(
        live, frame, caplog):
    """`{"token":"\\ud800","case_id":null}` from a peer
    with no session reached `hash_token`, whose UTF-8 encode raised, so the
    handshake logged a traceback and closed 1011."""
    import logging

    from fastapi.testclient import TestClient
    with TestClient(_app(), client=(PEER, 41010)) as client:
        with caplog.at_level(logging.ERROR):
            outcome = _close_of(client, frame, raw=True)
        assert outcome == ("close", 1008, "no credentials"), outcome
        assert live._pending.count == 0
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], (
        "the handshake logged an error for a peer that proved nothing")


def test_a_token_of_the_longest_allowed_shape_still_reaches_the_session_check(live):
    from fastapi.testclient import TestClient
    assert live._TOKEN_MAX_CHARS == 512
    with TestClient(_app(), client=(PEER, 41011)) as client:
        assert _close_of(client, '{"token":"' + "a" * 512 + '","case_id":null}',
                         raw=True) == ("close", 1008, "no such case")
        assert _close_of(client, '{"token":"' + "a" * 513 + '","case_id":null}',
                         raw=True) == ("close", 1008, "no credentials")


# ---------------------------------------------------------------------------
# 2026-10-07: a proposal hint carries its labels (G3)
# ---------------------------------------------------------------------------

def _document(owner, *, classification="AMBER", keys=()):
    source = owner.execute(
        "INSERT INTO collect.source (kind, name, default_reliability, classification) "
        "VALUES ('PASTE'::collect.source_kind, %s, 'F', %s) RETURNING id",
        (f"{PREFIX}{uuid4().hex[:8]}", classification)).fetchone()[0]
    return owner.execute(
        "INSERT INTO collect.document (source_id, title, body_text, content_sha256, "
        "classification, compartments) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (source, f"{PREFIX}{uuid4().hex[:6]}", "a thread", os.urandom(32),
         classification, list(keys))).fetchone()[0]


def _propose(owner, case_id, classification="AMBER", document_id=None):
    from noctornal_api.proposals import ProposalStore
    return ProposalStore(owner).propose(
        case_id=case_id, kind="NODE", origin="g45live/1",
        rationale="a signal worth a look", document_id=document_id,
        payload={"node_type": "IDENTITY", "label": f"{PREFIX}{uuid4().hex[:6]}",
                 "classification": classification})


def test_a_proposal_hint_names_the_labels_of_the_proposal(owner, world):
    case_id = world["case"]
    doc = _document(owner, keys=(COMPARTMENTS[0],))
    listener = _listener()
    try:
        _propose(owner, case_id, "RED")
        _propose(owner, case_id, "AMBER")
        _propose(owner, case_id, "AMBER", document_id=doc)
        events = [e for e in _heard(listener, case_id) if e["kind"] == "proposal"]
    finally:
        listener.close()
    assert [_labels(e) for e in events] == [
        {("RED", ())}, {("AMBER", ())}, {("AMBER", (COMPARTMENTS[0],))}]
    assert all(e["op"] == "CHANGE" for e in events)


def test_accepting_and_rejecting_a_proposal_announce_its_labels_too(owner, world):
    from noctornal_api.proposals import ProposalReview
    case_id, lead = world["case"], world["lead"]
    refused = _propose(owner, case_id, "RED")
    taken = _propose(owner, case_id, "AMBER")
    listener = _listener()
    try:
        ProposalReview(owner).reject(refused, reviewed_by=lead, note="not this one")
        ProposalReview(owner).accept(taken, reviewed_by=lead)
        events = [e for e in _heard(listener, case_id) if e["kind"] == "proposal"]
    finally:
        listener.close()
    assert [_labels(e) for e in events] == [{("RED", ())}, {("AMBER", ())}]


def test_the_delivery_verdict_drops_a_proposal_hint_above_the_subscriber(owner, world):
    from noctornal_api.http.routers.live import _delivery_verdict
    case_id, analyst, cleared = world["case"], world["analyst"], world["cleared"]

    def verdict(user, labels, *, present=True):
        payload = {"case_id": str(case_id), "kind": "proposal", "op": "CHANGE"}
        if present:
            payload["labels"] = labels
        return _delivery_verdict(user, case_id, None, payload)

    assert verdict(analyst, [["AMBER", []]]) == "send"
    assert verdict(analyst, [["RED", []]]) == "drop"
    assert verdict(analyst, [["AMBER", [COMPARTMENTS[0]]]]) == "drop"
    assert verdict(cleared, [["RED", [COMPARTMENTS[0]]]]) == "send"
    # A hint that names no labels cannot be placed, so it is not announced.
    assert verdict(analyst, None, present=False) == "drop"
    assert verdict(analyst, []) == "drop"
    # The kinds that carry no labels are still delivered on the case alone.
    assert _delivery_verdict(analyst, case_id, None,
                             {"case_id": str(case_id), "kind": "notification"}) == "send"


def test_the_socket_wakes_a_reader_for_a_proposal_they_may_read_and_not_above(owner, world, live):
    from fastapi.testclient import TestClient
    case_id, analyst = world["case"], world["analyst"]
    _sid, token = s.session(owner, analyst)
    with TestClient(_app(), client=(PEER, 41012)) as client:
        with client.websocket_connect("/api/v1/live") as ws:
            ws.send_json({"token": token, "case_id": str(case_id)})
            assert ws.receive_json()["type"] == "ready"
            time.sleep(1.0)      # the hub's LISTEN registers after `ready`
            _propose(owner, case_id, "RED")
            _propose(owner, case_id, "AMBER", document_id=_document(
                owner, keys=(COMPARTMENTS[0],)))
            late = [ws.receive_json() for _ in range(15)]
            assert [m["type"] for m in late] == ["ping"] * 15, (
                "a proposal above the subscriber woke their console")
            _propose(owner, case_id, "AMBER")
            change = _until_change(ws)
            assert change == {"type": "change", "kind": "proposal", "op": "CHANGE"}
            assert "labels" not in change
