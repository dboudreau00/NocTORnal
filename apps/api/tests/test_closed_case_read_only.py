"""A read-only case, statically: the route inventory and the console half.

gap-closed-case-writes (2026-09-23). The server refuses content writes on
a CLOSED, ARCHIVED or PURGED case at ONE place, `authorize_object`, keyed
on the verb (`deps.CONTENT_WRITE_PERMISSIONS`) or on `content_write=True`
from a route whose verb also gates reads. That is only as good as the
route table's agreement with it, so this file holds the table:

- every unsafe case route is named here as a content write, as
  governance, or as decided by the operation it asks for, and a new one
  fails until somebody says which;
- every content write really passes the guard, and no governance route
  and no read does (a read gated on a content verb would 409 on a closed
  case, which is worse than the gap this closed);
- the console recognises the refusal by the server's own title, agrees on
  the states, and has its one read-only mechanism wired where it must be.

Pure: it reads the router objects and the shipped static assets. The
behaviour over HTTP is `test_closed_case_read_only_pg.py`.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
import re
import textwrap
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
APP_CSS = STATIC / "app.css"

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

#: An en or em dash, a spaced double hyphen, or a bracketed plural: house
#: style refuses all four in anything a reader sees. Built with chr() so
#: this file stays ASCII.
OFF_STYLE = "[" + chr(0x2013) + chr(0x2014) + r"]| -- |\(s\)"

#: Every unsafe route that writes case CONTENT. Those without `{case_id}`
#: in the path take the case in the body, or from the sample.
CONTENT = {
    ("POST", "/cases/{case_id}/nodes"),
    ("POST", "/cases/{case_id}/edges"),
    ("POST", "/cases/{case_id}/nodes/{node_id}/assertions"),
    ("POST", "/cases/{case_id}/edges/{edge_id}/assertions"),
    ("POST", "/cases/{case_id}/assertions/{assertion_id}/retract"),
    ("PATCH", "/cases/{case_id}/graph/nodes/{node_id}"),
    ("PATCH", "/cases/{case_id}/graph/edges/{edge_id}"),
    ("DELETE", "/cases/{case_id}/graph/nodes/{node_id}"),
    ("DELETE", "/cases/{case_id}/graph/edges/{edge_id}"),
    ("POST", "/cases/{case_id}/graph/edges/{edge_id}/review"),
    ("PUT", "/cases/{case_id}/graph/layout"),
    ("POST", "/cases/{case_id}/selectors"),
    ("POST", "/cases/{case_id}/merges"),
    ("POST", "/cases/{case_id}/merges/{merge_id}/reverse"),
    ("POST", "/cases/{case_id}/evidence"),
    ("POST", "/cases/{case_id}/evidence/{evidence_id}/links"),
    ("POST", "/cases/{case_id}/proposals/capture"),
    ("POST", "/cases/{case_id}/proposals/{proposal_id}/accept"),
    ("POST", "/cases/{case_id}/proposals/{proposal_id}/reject"),
    ("POST", "/cases/{case_id}/proposals/{proposal_id}/defer"),
    ("POST", "/cases/{case_id}/deception/captures"),
    ("POST", "/cases/{case_id}/deception/emails"),
    ("POST", "/cases/{case_id}/deception/calls"),
    ("POST", "/cases/{case_id}/deception/{kind}/{record_id}/propose"),
    ("POST", "/cases/{case_id}/comms/bindings"),
    ("POST", "/cases/{case_id}/comms/contact-blocks"),
    ("POST", "/cases/{case_id}/comms/stoplist"),
    ("POST", "/cases/{case_id}/comms/pgp/verify"),
    ("POST", "/cases/{case_id}/comms/conversations"),
    ("POST", "/cases/{case_id}/comms/conversations/{conversation_id}/incidental"),
    ("POST", "/cases/{case_id}/ach/hypotheses"),
    ("POST", "/cases/{case_id}/ach/hypotheses/{hypothesis_id}/status"),
    ("PATCH", "/cases/{case_id}/ach/hypotheses/{hypothesis_id}"),
    ("PUT", "/cases/{case_id}/ach/hypotheses/{hypothesis_id}/stance"),
    ("DELETE", "/cases/{case_id}/ach/hypotheses/{hypothesis_id}/stance/{assertion_id}"),
    ("POST", "/cases/{case_id}/assumptions"),
    ("PATCH", "/cases/{case_id}/assumptions/{assumption_id}"),
    ("POST", "/cases/{case_id}/curation/tags"),
    ("POST", "/cases/{case_id}/curation/tags/{tag_id}/nodes"),
    ("DELETE", "/cases/{case_id}/curation/tags/{tag_id}/nodes/{node_id}"),
    ("POST", "/cases/{case_id}/curation/sets"),
    ("POST", "/cases/{case_id}/curation/sets/{set_id}/members"),
    ("DELETE", "/cases/{case_id}/curation/sets/{set_id}/members/{node_id}"),
    ("POST", "/samples"),
    ("POST", "/ingest/batches/{batch_id}/parse"),
    ("POST", "/ingest/dead-letters/{dead_letter_id}/replay"),
    # Lab work on a sample already attached to a case: its case is in no
    # path and the verbs are global, so each calls the gate by hand (c7/c21,
    # 2026-09-24: all five used to work on a CLOSED case's sample).
    ("POST", "/samples/{sample_id}/assign"),
    ("POST", "/samples/{sample_id}/analysis"),
    ("POST", "/samples/{sample_id}/analyses/{analysis_id}/propose"),
    ("POST", "/samples/{sample_id}/detonation"),
    ("POST", "/samples/{sample_id}/reject"),
}

#: Unsafe case routes that stay open on a read-only case, and why.
NOT_CONTENT = {
    ("PATCH", "/cases/{case_id}"):
        "the governance record: title, authority, dates, classification",
    ("POST", "/cases/{case_id}/status"): "the lifecycle itself, reopen included",
    ("POST", "/cases/{case_id}/graph/nodes/check"):
        "a read (case.read), sent as POST so the label stays out of the URL",
    ("POST", "/cases/{case_id}/users"): "sharing",
    ("DELETE", "/cases/{case_id}/users/{user_id}"): "unsharing",
    ("PUT", "/cases/{case_id}/policy"): "the approval policy",
    ("POST", "/cases/{case_id}/approvals/{request_id}/withdraw"):
        "withdrawing a request asks for nothing",
    ("POST", "/cases/{case_id}/evidence/{evidence_id}/export"):
        "a read with a custody record; disclosure happens after closure",
    ("POST", "/cases/{case_id}/evidence/{evidence_id}/verify"):
        "an integrity check that adds nothing",
    # x-hostile-export (2026-09-24): the export of attacker markup, in two
    # legs, and a read with a custody record as the export is.
    ("POST", "/cases/{case_id}/evidence/{evidence_id}/production-ticket"):
        "a read with a custody record; disclosure happens after closure",
    ("POST", "/cases/{case_id}/evidence/{evidence_id}/download"):
        "the production ticket spent on the sample origin; a read",
    # x-lock-extension (2026-09-24): what extending the retention date
    # does, for locks set before they followed it. Governance, as the date.
    ("POST", "/cases/{case_id}/evidence/locks"):
        "lengthens the storage locks to the retention date, as the PATCH does",
    ("POST", "/cases/{case_id}/report"): "builds a document, audits, writes no content",
    ("POST", "/cases/{case_id}/report/release"): "the egress decision, audited",
    ("POST", "/cases/{case_id}/comms/conversations/{conversation_id}/minimise"):
        "minimisation is performed at closure (docs/16 L4)",
    ("POST", "/cases/{case_id}/collection/watch-hits/{hit_id}/acknowledge"):
        "queue housekeeping: the collector keeps raising hits on a closed "
        "case's watches, and a queue nobody may clear nags forever",
    ("POST", "/cases/{case_id}/collection/watch-hits/{hit_id}/suppress"):
        "queue housekeeping, as acknowledge",
    ("POST", "/cases/{case_id}/collection/watch-hits/{hit_id}/unsuppress"):
        "queue housekeeping, as acknowledge",
    ("POST", "/samples/{sample_id}/download-ticket"):
        "a read with a custody record, as exhibit export",
    ("POST", "/samples/{sample_id}/download"): "serves the bytes: a read",
    ("POST", "/samples/{sample_id}/preserved/authorisations"):
        "the two-person control over a preserved sample: governance",
    ("POST", "/samples/{sample_id}/preserved/authorisations/{authorisation_id}/revoke"):
        "withdrawing that authorisation",
    ("POST", "/samples/{sample_id}/preserved/retrieval-ticket"):
        "a read under that authorisation",
}

#: Gated on the REQUESTED operation's own verb (`approvals.OPERATIONS`): a
#: merge request is a content write under `graph.merge`, a `case.delete`
#: request is governance. The DB test holds the merge half.
BY_OPERATION = {
    ("POST", "/cases/{case_id}/approvals"),
    ("POST", "/cases/{case_id}/approvals/{request_id}/decide"),
}


def _routes():
    """(method, path, route) for every route on every router module.

    From the routers rather than the app: the app mounts them as
    `_IncludedRouter` objects that expose no walkable `.routes`
    (test_doc_invariants.py says the same), while an `APIRouter`'s routes
    are public and carry the router's own prefix."""
    from fastapi import APIRouter
    from fastapi.routing import APIRoute

    import noctornal_api.http.routers as pkg
    routers: list[APIRouter] = []
    for info in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
        for value in vars(mod).values():
            if isinstance(value, APIRouter) and not any(value is r for r in routers):
                routers.append(value)
    out = []
    for router in routers:
        for route in router.routes:
            if isinstance(route, APIRoute):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    out.append((method, route.path, route))
    assert len(out) > 150, f"only {len(out)} routes found: the walk broke"
    return out


def _case_gates(route) -> list[tuple[str, bool]]:
    """(permission, content_write) for every `require(...)` the route's
    dependency tree runs. `require_global` is left out on purpose: it
    decides no case, so it never reaches the read-only guard."""
    found: list[tuple[str, bool]] = []

    def walk(dep) -> None:
        call = dep.call
        if call is not None and getattr(call, "__qualname__", "").startswith(
                "require.<locals>"):
            cells = dict(zip(call.__code__.co_freevars,
                             (c.cell_contents for c in call.__closure__),
                             strict=True))
            found.append((cells["permission_key"], cells.get("content_write", False)))
        for sub in dep.dependencies:
            walk(sub)

    walk(route.dependant)
    return found


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")


def _call_literals(route) -> set[str]:
    """String constants passed as arguments anywhere in the endpoint,
    which is where a body-gated route names its verb to `authorize_object`
    or a helper around it. Arguments only, so a docstring that mentions a
    verb does not count; and not to a GLOBAL check (`require_global`,
    `_holds_global`) or a meter, which decide no case and never reach the
    read-only guard."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(route.endpoint)))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _callee(node)
            if "global" in name or name == "rate_limit":
                continue
            for arg in list(node.args) + [k.value for k in node.keywords]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    out.add(arg.value)
    return out


def _calls_the_gate(route) -> bool:
    """True when the endpoint calls the read-only gate by hand
    (`refuse_if_case_read_only`, or the samples router's wrapper round
    it), which is how a route whose case is in no path and whose verb is
    global reaches it."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(route.endpoint)))
    return any(isinstance(n, ast.Call) and "refuse_if" in _callee(n)
               and "read_only" in _callee(n) for n in ast.walk(tree))


def _guarded(route) -> bool:
    from noctornal_api.http.deps import CONTENT_WRITE_PERMISSIONS
    if any(p in CONTENT_WRITE_PERMISSIONS or cw for p, cw in _case_gates(route)):
        return True
    if _calls_the_gate(route):
        return True
    return bool(_call_literals(route) & CONTENT_WRITE_PERMISSIONS)


def _is_case_route(path: str) -> bool:
    """A case's own route, or one on a sample, which a case owns once it
    is attached (c7/c21, 2026-09-24: the scan read `{case_id}` alone, so
    the Lab's writes on an attached sample were never classified)."""
    return "{case_id}" in path or path.startswith("/samples/{sample_id}")


def test_every_unsafe_case_route_is_classified():
    """A new write on a case must be put in one of the three tables, which
    is the moment somebody decides whether a closed case refuses it."""
    unsafe_case = {(m, p) for m, p, _ in _routes()
                   if m in UNSAFE and _is_case_route(p)}
    tables = [CONTENT, set(NOT_CONTENT), BY_OPERATION]
    for a in range(3):
        for b in range(a + 1, 3):
            assert not tables[a] & tables[b], tables[a] & tables[b]
    known = CONTENT | set(NOT_CONTENT) | BY_OPERATION
    unclassified = sorted(unsafe_case - known)
    assert not unclassified, (
        "unsafe case routes nobody has classified for a CLOSED case: "
        f"{unclassified}. Put each in CONTENT (and gate it on a content "
        "verb or content_write=True) or in NOT_CONTENT with the reason.")
    routed = {(m, p) for m, p, _ in _routes()}
    stale = sorted(known - routed)
    assert not stale, f"classified routes that no longer exist: {stale}"


@pytest.mark.parametrize("method,path", sorted(CONTENT))
def test_every_content_write_passes_the_read_only_guard(method, path):
    route = next(r for m, p, r in _routes() if (m, p) == (method, path))
    assert _guarded(route), (
        f"{method} {path} writes case content but gates on no verb in "
        f"CONTENT_WRITE_PERMISSIONS and says no content_write=True, so a "
        f"CLOSED case would accept it")


@pytest.mark.parametrize("method,path", sorted(NOT_CONTENT))
def test_no_governance_route_is_refused_on_a_closed_case(method, path):
    route = next(r for m, p, r in _routes() if (m, p) == (method, path))
    assert not _guarded(route), (
        f"{method} {path} is governance ({NOT_CONTENT[(method, path)]}) but "
        f"now gates on a content verb, so a CLOSED case would refuse it")


def test_no_read_gates_on_a_content_write():
    """A read gated on a content verb would 409 on every closed case: the
    matrix read under `report.generate` is why that verb is not in the set."""
    from noctornal_api.http.deps import CONTENT_WRITE_PERMISSIONS
    offenders = []
    for method, path, route in _routes():
        if method in UNSAFE:
            continue
        for perm, cw in _case_gates(route):
            if cw or perm in CONTENT_WRITE_PERMISSIONS:
                offenders.append(f"{method} {path} ({perm})")
        if _call_literals(route) & CONTENT_WRITE_PERMISSIONS:
            offenders.append(f"{method} {path} (in its body)")
    assert not offenders, offenders


def test_the_refusal_names_every_read_only_state_in_house_style():
    from noctornal_api.cases import _TRANSITIONS, CONTENT_READ_ONLY_STATES
    from noctornal_api.http import deps
    assert CONTENT_READ_ONLY_STATES <= set(_TRANSITIONS)
    assert {"CLOSED", "ARCHIVED"} <= CONTENT_READ_ONLY_STATES
    assert "ACTIVE" not in CONTENT_READ_ONLY_STATES
    assert set(deps._READ_ONLY_DETAIL) == CONTENT_READ_ONLY_STATES
    for state, text in deps._READ_ONLY_DETAIL.items():
        assert state in text
        assert not re.search(OFF_STYLE, text), text
    # Only a CLOSED case can be reopened, and only its refusal says so.
    assert "Reopen" in deps._READ_ONLY_DETAIL["CLOSED"]
    assert "Reopen" not in deps._READ_ONLY_DETAIL["ARCHIVED"]
    assert "cannot be reopened" in deps._READ_ONLY_DETAIL["ARCHIVED"]


def test_the_case_record_says_read_only():
    from types import SimpleNamespace

    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    from noctornal_api.http.routers.cases import _out
    for status in ("DRAFT", "ACTIVE", "DORMANT", "CLOSED", "ARCHIVED", "PURGED"):
        row = SimpleNamespace(
            id="c", code="OP-X", title="t", status=status, classification="AMBER",
            owner_user_id="u", legal_basis="b", retention_until="2028-01-01",
            review_due="2027-01-01", created_at="2026-01-01T00:00:00Z",
            closed_at=None, summary=None, authority_ref=None)
        assert _out(row).read_only is (status in CONTENT_READ_ONLY_STATES)


def test_no_router_keeps_its_own_copy_of_the_refusal():
    """A second copy of the check drifts from the gate. The ingest router
    had one (g08) that refused only CLOSED and ARCHIVED, titled its 409
    "Conflict" and wrote no audit row: a PURGED case's record could be
    triaged, and the console, which knows the refusal by its title, never
    turned read-only (merged 2026-09-24). Ingest record triage gates on a
    reader's verb, `ingest.read`, so it calls the one gate by hand."""
    import noctornal_api.http.routers as pkg
    for info in pkgutil.iter_modules(pkg.__path__):
        src = inspect.getsource(
            importlib.import_module(f"{pkg.__name__}.{info.name}"))
        assert "_refuse_closed_case" not in src, info.name
        assert 'in ("CLOSED", "ARCHIVED")' not in src, info.name
    from noctornal_api.http.routers import ingest
    body = inspect.getsource(ingest.triage_record)
    assert 'refuse_if_case_read_only(conn, user, case_id, "ingest.read")' in body
    # After the record gate, which answers 404 to a caller it refuses.
    assert body.index("_authorise_record(") < body.index(
        "refuse_if_case_read_only(")
    from noctornal_api.http.deps import CONTENT_WRITE_PERMISSIONS
    assert "ingest.replay" in CONTENT_WRITE_PERMISSIONS, (
        "replay, attach and category correction rely on their verb")


def test_the_lab_asks_the_gate_after_the_label_check():
    """The Lab's writes on an attached sample call the one gate by hand, as
    ingest record triage does, and only once the sample's labels have
    answered: a caller who cannot see the sample gets the 404 and never
    the case's state (c7/c21, 2026-09-24). The service's own refusal is
    answered as the gate's, so the console turns read-only on it."""
    from noctornal_api.http.routers import samples as router
    helper = inspect.getsource(router._refuse_if_read_only)
    assert "refuse_if_case_read_only(conn, user, sample.case_id, permission_key)" in helper
    assert "CASE_READ_ONLY_TITLE" in inspect.getsource(router._read_only_problem)
    for name, verb in (("assign", "sample.analyse"),
                       ("record_analysis", "sample.analyse"),
                       ("propose_selector", "sample.analyse"),
                       ("request_detonation", "sample.detonate"),
                       ("reject", "sample.analyse")):
        body = inspect.getsource(getattr(router, name))
        call = f'_refuse_if_read_only(conn, user, sample, "{verb}")'
        assert call in body, name
        seen = body.index("_visible_or_404(" if name != "reject" else ".visible(")
        assert seen < body.index(call), f"{name} asks the gate before the labels"
        assert "except SampleCaseReadOnly as exc:" in body, name
        assert body.index("except SampleCaseReadOnly") < body.index(
            "except SampleError"), f"{name} answers the service's refusal as a 400"


# ---------------------------------------------------------------------------
# The console: one class on the workspace and one helper
# ---------------------------------------------------------------------------

def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def test_the_console_recognises_the_servers_refusal():
    from noctornal_api.http.deps import CASE_READ_ONLY_TITLE
    m = re.search(r"^const CASE_READ_ONLY_TITLE = '([^']+)';", _js(), flags=re.M)
    assert m and m.group(1) == CASE_READ_ONLY_TITLE
    fetch = _fn("_fetch")
    assert "p.title === CASE_READ_ONLY_TITLE" in fetch
    assert "caseTurnedReadOnly()" in fetch
    # And re-reads the case rather than guessing its new state.
    assert "api('/cases/' + id)" in _fn("caseTurnedReadOnly")
    assert "renderCaseState(rec)" in _fn("caseTurnedReadOnly")


def test_the_console_and_the_server_agree_on_the_states():
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    m = re.search(r"const CASE_STATES_SHUT = new Set\(\[([^\]]*)\]\)", _js())
    assert m
    assert set(re.findall(r"'([A-Z]+)'", m.group(1))) == CONTENT_READ_ONLY_STATES
    # The server's own flag wins when the record carries it.
    assert "r.read_only" in _fn("caseReadOnly")


def test_one_mechanism_turns_the_content_controls_off():
    js = _js()
    helper = _fn("applyCaseReadOnly")
    assert "const ws = $('view-workspace');" in helper
    assert "ws.classList.toggle('case-read-only', on)" in helper
    assert "node.inert = on" in helper
    assert "classList.toggle('case-ro-off', on)" in helper
    # Every state change passes through it, the case list's "no case" too.
    assert "applyCaseReadOnly(rec);" in _fn("renderCaseState")
    ids = re.findall(r"'([a-z0-9-]+)'",
                     js[js.index("const CASE_CONTENT_CONTROLS = ["):
                        js.index("];", js.index("const CASE_CONTENT_CONTROLS = ["))])
    assert len(ids) >= 15
    html = INDEX.read_text(encoding="utf-8")
    missing = [i for i in ids if f'id="{i}"' not in html]
    assert not missing, f"CASE_CONTENT_CONTROLS names ids index.html lacks: {missing}"
    # Reads must never be on the list: they stay live on a closed case.
    for read in ("search-form", "comms-correlate-form", "btn-fit", "ach-refresh",
                 "tab-graph", "btn-case-status", "btn-case-share"):
        assert read not in ids, read
    css = re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"), flags=re.S)
    assert re.search(r"\.case-read-only \.case-ro-off\s*\{[^}]*opacity", css)


def test_the_rail_keys_skip_a_tab_the_read_only_case_turned_off():
    tabs = _fn("initTabs")
    assert "tabs.filter((t) => !t.inert)" in tabs
    assert "next = tabs[" not in tabs


def test_clearing_pins_on_a_read_only_case_does_not_try_to_save():
    assert "!caseReadOnly()" in _fn("clearPins")
    # Each clear the Undo card counts keeps its own `store` (merged
    # 2026-09-24: one sticky card may count two clears).
    assert "push({ caseId, token, before, store })" in _fn("clearPins")
    assert "restorePins(c.caseId, c.token, c.before, c.store);" in _fn("clearPins")
    assert "if (!store) return;" in _fn("restorePins")


def test_placements_on_a_read_only_case_are_never_marked_or_stored():
    """Hand placements are marked unsaved, asked about as the page is left
    and stored as the case is left (ux03 pin-layout-work-lost). None of
    that can happen on a read-only case, whose layout the server refuses
    to change: the Save dot would sit on a control that is off, the page
    would ask about work it cannot keep, and leaving would draw a 409."""
    js = _js()
    assert "if (!caseReadOnly()) state.layoutDirty.add(g.drag.id);" in js
    assert "if (!caseReadOnly()) state.layoutDirty.add(n.id);" in _fn("togglePin")
    assert "if (caseReadOnly()) return;" in _fn("guardLayout")
    assert "if (caseReadOnly()) { state.layoutCarry = null; return; }" in _fn("leaveLayout")


def test_nothing_still_says_the_server_accepts_the_writes():
    for path in (APP_JS, INDEX):
        text = path.read_text(encoding="utf-8")
        assert "does not refuse such writes" not in text, path.name
        assert "server does\n       not refuse" not in text, path.name


def test_the_read_only_copy_is_in_house_style():
    js = _js()
    start = js.index("const CASE_STATE_TEXT = {")
    table = js[start:js.index("};", start)]
    for state in ("CLOSED", "ARCHIVED", "PURGED"):
        entry = table[table.index(state + ":"):]
        entry = entry[:entry.index("',\n") if "',\n" in entry else len(entry)]
        assert "read-only" in entry, state
    assert not re.search(OFF_STYLE, table)


# ---------------------------------------------------------------------------
# Every console write on a case, and what turns it off
#
# The first pass turned off the markup's controls and left every control a
# pane draws at render time live: on a CLOSED case the tag, exhibit-link,
# retract, reverse, proposal, stance and assumption controls all worked up
# to the server's 409, under a strip saying they were off, and the palette
# still offered "Save layout" and "Go to Add entity" (verifier,
# 2026-09-23). This holds the console the way the tables above hold the
# routes: every function that sends a write to one case is named, and each
# content write says what turns it off.
# ---------------------------------------------------------------------------

#: A console function that writes one case's CONTENT, and what turns it off
#: on a read-only case:
#: ("id", container, trigger): the trigger sits in `container`, a control
#:   in the markup that CASE_CONTENT_CONTROLS lists;
#: ("drawn", selector, builder, marker): `builder` draws the control (it
#:   contains `marker`) and CASE_CONTENT_RENDERED matches it by `selector`;
#: ("guard", function): a path with no control of its own (a key, the
#:   palette, a local action) that asks caseReadOnly() first.
CONSOLE_CONTENT = {
    "saveLayout": [("id", "btn-save-layout", "btn-save-layout")],
    "clearPins": [("guard", "clearPins")],
    # Clear pins' Undo stores only what clearPins stored (`store`).
    "restorePins": [("guard", "clearPins")],
    # Its one caller drops a read-only case's placements first.
    "saveLayoutOnLeave": [("guard", "leaveLayout")],
    # Unsaved placements, stored before a status change shuts the case
    # (u10, 2026-09-24); it asks whether the case is still open first.
    "saveLayoutBeforeShut": [("guard", "saveLayoutBeforeShut")],
    "uploadEvidence": [("id", "ev-form", "ev-form")],
    "renderTags": [("drawn", ".tag-x", "renderTags", "'tag-x'"),
                   ("drawn", ".insp-linker", "renderTags", "'insp-linker'")],
    "wireElementActions": [("id", "insp-actions", "btn-edit-element"),
                           ("id", "insp-actions", "btn-retire-element")],
    "retractAssertion": [("drawn", ".assert-actions", "renderAssertions",
                          "'assert-actions'")],
    "addTieClaim": [("id", "insp-claim", "claim-form")],
    # Correct... opens this form from #insp-actions; the form itself is
    # listed too, so one left open when the case closes is turned off.
    "submitCorrection": [("id", "insp-fix", "fix-form")],
    # The note and the verbs; the state, what it means and the history
    # above them stay readable.
    "submitTieReview": [("id", "review-form", "review-accept"),
                        ("id", "review-form", "review-dispute"),
                        ("id", "review-form", "review-reopen")],
    "renderEvidenceLinker": [("drawn", ".insp-linker", "renderEvidenceLinker",
                              "'insp-linker'")],
    "createNode": [("id", "node-form", "node-form")],
    "createEdge": [("id", "edge-form", "edge-form")],
    "initCommsBind": [("id", "comms-bind-form", "comms-bind-form")],
    "initCommsBlocks": [("id", "comms-block-form", "comms-block-form")],
    # Raising a merge approval is part of the same press.
    "runMerge": [("id", "merge-run", "merge-run")],
    # A merge's Approve, Reject and Execute merge; Withdraw and a
    # case.delete decision are governance and carry no `case-write`.
    # The buttons are built in approvalActions (ux08-triage:approval-row-
    # uuids-no-requester); Execute merge stays on the row.
    "approvalActions": [
        ("drawn", ".case-write", "approvalActions",
         "const write = a.operation === MERGE_OPERATION ? ' case-write' : '';"),
        ("drawn", ".case-write", "approvalActions",
         "el('button', 'btn ghost small' + write, label)"),
    ],
    "approvalRow": [
        ("drawn", ".case-write", "approvalRow",
         "el('button', 'btn small case-write', 'Execute merge')"),
    ],
    "reverseMerge": [("drawn", "#merge-history button", "loadMergeHistory",
                      "reverseMerge(m)")],
    "disposition": [("drawn", ".triage-actions", "triageActions", "'triage-actions'"),
                    ("guard", "acceptProposal"), ("guard", "rejectProposal"),
                    ("guard", "deferProposal")],
    "runCapture": [("id", "capture-box", "cap-run")],
    "wireAssumptions": [("id", "asm-create", "asm-create")],
    "reviewAssumption": [("drawn", "#asm-list .row-actions", "assumptionRow",
                          "reviewAssumption(a, status, b, msg)")],
    "saveStance": [("drawn", ".ach-cell-btn", "renderAchMatrix", "'ach-cell-btn'"),
                   ("id", "ach-score-card", "ach-evidence-add"),
                   # The next-test line's shortcut to the first blank cell
                   # (u15, 2026-09-24: live beside cells that were off).
                   ("drawn", ".case-write", "renderAchRanking",
                    "el('button', 'btn small ach-next-go case-write', "
                    "'Score it now')")],
    # Clear is in the stance chooser, which only a cell opens.
    "clearStance": [("drawn", ".ach-cell-btn", "renderAchMatrix", "'ach-cell-btn'")],
    "openHypothesisStatus": [("drawn", ".case-write", "achCard",
                              "el('button', 'btn small case-write', 'Status…')")],
    "openHypothesisReword": [("drawn", ".case-write", "achCard",
                              "el('button', 'btn small case-write', 'Reword…')")],
    # The whole card, summary included: listing its three controls left
    # "Add a hypothesis" opening at full strength on a closed case.
    "addHypothesis": [("id", "ach-add-card", "ach-add")],
    "verifyPgp": [("id", "comms-pgp-form", "comms-pgp-form")],
    # The deception pane's new-record forms and its proposals (g09).
    "saveCapture": [("id", "dcp-cap-new", "dcp-capf-save")],
    "saveEmail": [("id", "dcp-eml-new", "dcp-emlf-save")],
    "saveCall": [("id", "dcp-call-new", "dcp-callf-save")],
    "dcpProposeBar": [("drawn", ".case-write", "dcpProposeBar",
                       "el('button', 'btn small case-write', 'Propose')")],
    # The Feeds queue's triage verbs on a record in the case's own queue
    # (u3, 2026-09-24): live under the strip, refused with the 409. A
    # quarantined record belongs to no case and its row stays live.
    "applyTriage": [
        ("drawn", ".case-write", "ingestRow",
         "const write = r.case_id ? ' case-write' : '';"),
        ("drawn", ".case-write", "ingestRow",
         "const verb = (label, title, handler) => button(label, title, handler, write);"),
        ("drawn", ".case-write", "ingestRow", "verb('Mark triaged', "),
        ("drawn", ".case-write", "ingestRow", "verb('Link…', "),
        ("drawn", ".case-write", "ingestRow", "verb('Discard…', "),
        ("drawn", ".case-write", "ingestRow", "verb('Back to new', "),
        # A Link or Discard form left open when the case turns read-only.
        ("drawn", ".case-write", "rowForm",
         "el('div', 'row-inline' + (spec.write || ''))"),
    ],
    # Correct category, and Attach: a quarantined record into a case the
    # picker offers only when it is not read-only (`attachTargets`, whose
    # behaviour is tested below).
    "ingestRow": [
        ("drawn", ".case-write", "ingestRow", "verb('Correct category…', "),
        ("drawn", ".case-write", "ingestRow", "const cases = attachTargets();"),
    ],
}

#: Console writes on one case that stay live, and why (NOT_CONTENT above
#: is the server's half of each).
CONSOLE_GOVERNANCE = {
    "verifyExhibit": "Verify (logged): an integrity check that adds nothing",
    "produceExhibit": "producing attacker markup is an export: a read with a "
                      "custody record, and disclosure happens after closure",
    "lengthenLocks": "the storage locks follow the retention date, which is "
                     "governance and stays open on a closed case",
    # The case's own record and its status, reopen included: once written
    # in wireCaseActions, now the record and status dialogs' own (ux02-cases).
    "submitStatus": "the status dialog: the lifecycle, reopen included",
    "saveCaseRecord": "the case's own record (the metadata PATCH)",
    "buildReport": "builds a document and audits it",
    "releaseReport": "the egress decision",
    "watchHitRow": "watch-hit triage stays open on a closed case",
    "adminAssignBox": "sharing",
    "shareRow": "unsharing",
    "submitShare": "sharing",
    "runNodeCheck": "a read sent as POST so the label stays out of the URL",
    # A record's score is derived from the case's watches, not content, and
    # the server recomputes it on a closed case too (u3, 2026-09-24).
    "rescoreRecord": "a derived score, recomputed on a closed case too",
    "rescoreAll": "the same, for every record in the case's queue",
}


def _console_case_writes() -> dict[str, set[int]]:
    """Enclosing top-level function -> line numbers, for every `api(` call
    with an unsafe method whose path is one case's (`cpath(` or
    '/cases/' + ...), or a Feeds record's, which belongs to one case
    ('/ingest/records/...'). The record writers were never scanned, so the
    triage and category verbs stayed live on a closed case (u3,
    2026-09-24)."""
    js = _js()
    starts = [(m.start(), m.group(1)) for m in
              re.finditer(r"(?m)^(?:async )?function (\w+)\(", js)]
    out: dict[str, set[int]] = {}
    for m in re.finditer(r"\bapi\(", js):
        seg = js[m.start():m.start() + 400]
        method = re.search(r"method:\s*'(POST|PUT|PATCH|DELETE)'", seg)
        if not method or "api(" in seg[4:method.start()]:
            continue
        path = seg[4:seg.index(",")]
        if ("cpath(" not in path and "'/cases/'" not in path
                and "'/ingest/records/" not in path):
            continue
        owner = [n for s, n in starts if s < m.start()][-1]
        out.setdefault(owner, set()).add(js.count("\n", 0, m.start()) + 1)
    assert len(out) > 20, f"only {len(out)} writers found: the scan broke"
    return out


def _const(name: str) -> str:
    """A top-level `const`, from its line to the first line that ends it:
    its own, or the first unindented one ending in a semicolon."""
    js = _js()
    m = re.search(rf"(?m)^const {re.escape(name)} = ", js)
    assert m, f"app.js has no top-level const {name}"
    first_end = js.index("\n", m.start())
    if js[first_end - 1] == ";":
        return js[m.start():first_end + 1]
    end = re.compile(r"(?m)^\S[^\n]*;$").search(js, first_end)
    return js[m.start():end.end() + 1]


def _rendered_selectors() -> list[str]:
    block = _const("CASE_CONTENT_RENDERED")
    return re.findall(r"'([^']+)'", block.split("].join(")[0])


def _markup_ids() -> list[str]:
    block = _const("CASE_CONTENT_CONTROLS")
    return re.findall(r"'([a-z0-9-]+)'", block)


def _element(html: str, ident: str) -> str:
    """The markup of the element with id `ident`, its tag to its match."""
    at = html.index(f'id="{ident}"')
    start = html.rindex("<", 0, at)
    tag = re.match(r"<(\w+)", html[start:]).group(1)
    depth = 0
    for m in re.compile(rf"<(/?){tag}\b[^>]*>").finditer(html, start):
        depth += -1 if m.group(1) else 1
        if depth == 0:
            return html[start:m.end()]
    raise AssertionError(f"#{ident} is never closed")


def test_every_console_write_on_a_case_is_classified():
    """A new write in the console must be named here, which is the moment
    somebody decides what turns it off on a closed case."""
    found = set(_console_case_writes())
    assert not set(CONSOLE_CONTENT) & set(CONSOLE_GOVERNANCE)
    known = set(CONSOLE_CONTENT) | set(CONSOLE_GOVERNANCE)
    unclassified = sorted(found - known)
    assert not unclassified, (
        f"console functions that write a case and are not classified: "
        f"{unclassified}. Put each in CONSOLE_CONTENT with what turns it "
        f"off on a read-only case, or in CONSOLE_GOVERNANCE with the reason.")
    stale = sorted(known - found)
    assert not stale, f"classified console writers that no longer write: {stale}"


@pytest.mark.parametrize("writer", sorted(CONSOLE_CONTENT))
def test_every_console_content_write_is_turned_off(writer):
    html = re.sub(r"<!--.*?-->", "", INDEX.read_text(encoding="utf-8"), flags=re.S)
    workspace = _element(html, "view-workspace")
    markup, rendered = _markup_ids(), _rendered_selectors()
    for how in CONSOLE_CONTENT[writer]:
        if how[0] == "id":
            _, box, trigger = how
            assert box in markup, f"{writer}: #{box} is not in CASE_CONTENT_CONTROLS"
            assert f'id="{trigger}"' in _element(html, box), (
                f"{writer}: #{trigger} is not inside #{box}, so turning "
                f"#{box} off leaves it live")
        elif how[0] == "drawn":
            _, selector, builder, marker = how
            assert selector in rendered, (
                f"{writer}: {selector} is not in CASE_CONTENT_RENDERED")
            assert marker in _fn(builder), (
                f"{writer}: {builder} no longer draws {marker}")
            if selector.startswith("#"):
                box = selector.split()[0][1:]
                assert f'id="{box}"' in workspace, (
                    f"#{box} is outside the workspace the observer watches")
        else:
            body = _fn(how[1])
            assert "caseReadOnly()" in body, f"{how[1]} does not ask first"


def test_every_rendered_selector_is_one_the_harness_models():
    """The behaviour test below models three selector shapes; a fourth
    would make it lie, so a new shape has to extend it first."""
    for sel in _rendered_selectors():
        assert re.fullmatch(r"\.[a-z-]+|#[a-z-]+ (?:\.[a-z-]+|[a-z]+)", sel), sel
    readable = re.search(r"^const CASE_CONTENT_READABLE = '([^']+)';", _js(),
                         flags=re.M)
    assert readable and readable.group(1) in _rendered_selectors()


def test_withdrawing_a_request_stays_live_on_a_closed_case():
    """Withdraw is governance (NOT_CONTENT), so it must never share the
    merge decision's marker."""
    row = _fn("approvalActions")
    assert "el('button', 'btn ghost small', 'Withdraw')" in row
    assert "case-write', 'Withdraw'" not in row


def test_the_triage_undo_is_off_on_a_read_only_case():
    """An accept's Undo retires or retracts what it wrote; its request is
    built from a variable, so the writer scan above cannot see it."""
    assert "el('button', 'btn ghost small case-write', 'Undo')" in _fn(
        "showTriageOutcome")
    assert "'.case-write'" in _const("CASE_CONTENT_RENDERED")


def test_the_palette_offers_no_control_the_case_turned_off():
    palette = _fn("buildPaletteItems")
    assert "if (caseControlOff('tab-' + key)) continue;" in palette
    assert "if (!caseControlOff('btn-save-layout')) {" in palette
    assert "CASE_CONTENT_CONTROLS.includes(id) && caseReadOnly()" in _fn("caseControlOff")


def test_a_closed_cases_ach_cell_stays_readable():
    """Disabled, not inert and not dimmed: the stance is the record."""
    css = re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"), flags=re.S)
    assert re.search(r"\.ach-cell-btn:disabled\s*\{[^}]*cursor: default", css)
    mark = _fn("markCaseContent")
    assert "node.disabled = on; return;" in mark


_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")


def _node() -> str | None:
    import shutil
    return shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)


needs_node = pytest.mark.skipif(not _node(), reason="Node is not installed here")


def _run_node(script: str, tmp_path: Path) -> dict:
    import json
    import subprocess
    path = tmp_path / "run.js"
    path.write_text(script, encoding="utf-8")
    out = subprocess.run([_node(), str(path)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


#: Just enough DOM for `applyCaseReadOnly`: ids, classes, a parent chain,
#: the three selector shapes CASE_CONTENT_RENDERED uses, and an observer
#: that is told about each append under the node it watches (a browser
#: tells it a microtask later, before paint; the order is the same).
_FAKE_DOM = r"""
const Node = { ELEMENT_NODE: 1 };
let observers = [];
class MutationObserver {
  constructor(cb) { this.cb = cb; this.root = null; }
  observe(root) { this.root = root; observers.push(this); }
  disconnect() { this.root = null; observers = observers.filter((o) => o !== this); }
}
const byId = new Map();
class El {
  constructor(tag, id, cls) {
    this.tagName = tag.toUpperCase(); this.nodeType = 1; this.id = id || '';
    this.cls = new Set((cls || '').split(' ').filter(Boolean));
    this.children = []; this.parent = null; this.inert = false; this.disabled = false;
    const self = this;
    this.classList = {
      toggle(c, on) { if (on) self.cls.add(c); else self.cls.delete(c); },
    };
  }
  appendChild(c) {
    c.parent = this; this.children.push(c);
    const reg = (n) => { if (n.id) byId.set(n.id, n); n.children.forEach(reg); };
    reg(c);
    for (const o of observers.slice()) {
      if (o.root && this.within(o.root)) o.cb([{ addedNodes: [c] }]);
    }
    return c;
  }
  within(root) { for (let n = this; n; n = n.parent) if (n === root) return true; return false; }
  one(sel) {
    const parts = sel.trim().split(/\s+/);
    const last = parts[parts.length - 1];
    if (!(last[0] === '.' ? this.cls.has(last.slice(1))
                          : this.tagName === last.toUpperCase())) return false;
    if (parts.length === 1) return true;
    for (let n = this.parent; n; n = n.parent) if (n.id === parts[0].slice(1)) return true;
    return false;
  }
  matches(list) { return list.split(',').some((s) => this.one(s)); }
  querySelectorAll(list) {
    const out = [];
    const walk = (n) => { for (const c of n.children) { if (c.matches(list)) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
}
const document = { getElementById: (id) => byId.get(id) || null };
function $(id) { return byId.get(id); }
const make = (parent, tag, id, cls) => parent.appendChild(new El(tag, id, cls));
const ws = new El('section', 'view-workspace');
byId.set('view-workspace', ws);
"""


@needs_node
def test_a_read_only_case_turns_off_what_panes_draw_and_reopening_restores_it(tmp_path):
    names = ("CASE_STATES_SHUT", "CASE_CONTENT_CONTROLS", "CASE_CONTENT_RENDERED",
             "CASE_CONTENT_READABLE", "caseContentWatch")
    script = (_FAKE_DOM + "".join(_const(n) for n in names)
              + "".join(_fn(n) for n in ("caseReadOnly", "caseControlOff",
                                          "markCaseContent", "applyCaseReadOnly"))
              + r"""
const state = { caseRec: null };
for (const id of CASE_CONTENT_CONTROLS) {
  make(ws, id.startsWith('tab-') ? 'button' : 'div', id);
}
const tags = make(ws, 'div', 'insp-tags');
const chip = make(tags, 'span', '', 'chip tag-chip');
const el = {
  chip: chip,
  tagX: make(chip, 'button', '', 'tag-x'),
  tagLinker: make(tags, 'div', '', 'insp-linker'),
  retract: make(make(ws, 'div', 'insp-assertions'), 'div', '', 'assert-actions'),
  reverse: make(make(make(ws, 'div', 'merge-history'), 'div', '', 'sel-item'),
                'button', '', 'btn small'),
  verdicts: make(make(make(ws, 'div', 'triage-list'), 'div', '', 'triage-card'),
                 'div', '', 'triage-actions'),
  cell: make(make(ws, 'div', 'ach-matrix'), 'button', '', 'ach-cell-btn'),
  review: make(make(ws, 'div', 'asm-list'), 'div', '', 'row-actions'),
  search: make(ws, 'form', 'search-form'),
  glass: make(make(ws, 'div', 'glass-list'), 'div', '', 'row-actions'),
};
const apr = make(make(ws, 'div', 'apr-list'), 'div', '', 'row-actions');
el.mergeDecide = make(apr, 'button', '', 'btn ghost small case-write');
el.withdraw = make(apr, 'button', '', 'btn ghost small');
el.deleteDecide = make(apr, 'button', '', 'btn ghost small');
const snap = () => {
  const o = {};
  for (const [k, n] of Object.entries(el)) {
    o[k] = [n.inert, n.disabled, n.cls.has('case-ro-off')];
  }
  o.markup = CASE_CONTENT_CONTROLS.every((id) => $(id).inert && $(id).cls.has('case-ro-off'));
  o.markupLive = CASE_CONTENT_CONTROLS.every((id) => !$(id).inert && !$(id).cls.has('case-ro-off'));
  o.wsClass = ws.cls.has('case-read-only');
  o.watching = observers.length;
  return o;
};
const out = {};
state.caseRec = { status: 'ACTIVE', read_only: false };
applyCaseReadOnly();
out.active = snap();
out.activeOff = [caseControlOff('tab-add-node'), caseControlOff('btn-save-layout')];

state.caseRec = { status: 'CLOSED', read_only: true };
applyCaseReadOnly();
out.closed = snap();
out.closedOff = [caseControlOff('tab-add-node'), caseControlOff('btn-save-layout'),
                 caseControlOff('search-form')];

// A pane redraws while the case is closed: a new card, built detached and
// then put in the list, and a new cell straight into the matrix.
const card = new El('div', '', 'triage-card');
const fresh = card.appendChild(new El('div', '', 'triage-actions'));
$('triage-list').appendChild(card);
const cell2 = make($('ach-matrix'), 'button', '', 'ach-cell-btn');
out.redrawn = [fresh.inert, fresh.cls.has('case-ro-off'), cell2.disabled, cell2.inert];

// A record from before the field: the status decides.
out.legacy = [caseReadOnly({ status: 'ARCHIVED' }), caseReadOnly({ status: 'DORMANT' })];

state.caseRec = { status: 'ACTIVE', read_only: false };
applyCaseReadOnly();
out.reopened = snap();
out.redrawnReopened = [fresh.inert, fresh.cls.has('case-ro-off'), cell2.disabled];
const later = make($('triage-list'), 'div', '', 'triage-actions');
out.later = [later.inert, later.cls.has('case-ro-off')];
console.log(JSON.stringify(out));
""")
    got = _run_node(script, tmp_path)
    live = [False, False, False]
    assert all(v == live for k, v in got["active"].items()
               if isinstance(v, list)), got["active"]
    assert got["active"]["markupLive"] and not got["active"]["wsClass"]
    assert got["active"]["watching"] == 0 and got["activeOff"] == [False, False]

    closed = got["closed"]
    assert closed["wsClass"] and closed["markup"] and closed["watching"] == 1
    off = [True, False, True]
    for k in ("tagX", "tagLinker", "retract", "reverse", "verdicts", "review",
              "mergeDecide"):
        assert closed[k] == off, (k, closed[k])
    assert closed["cell"] == [False, True, False], "a cell stays readable"
    for k in ("chip", "search", "glass", "withdraw", "deleteDecide"):
        assert closed[k] == live, (k, "reads and governance stay live")
    assert got["closedOff"] == [True, True, False]
    assert got["redrawn"] == [True, True, True, False], "a redraw is marked too"
    assert got["legacy"] == [True, False]

    reopened = got["reopened"]
    assert all(v == live for k, v in reopened.items() if isinstance(v, list)), reopened
    assert reopened["markupLive"] and reopened["watching"] == 0
    assert got["redrawnReopened"] == [False, False, False]
    assert got["later"] == [False, False], "nothing watches an open case"


@needs_node
def test_the_triage_keys_ask_nothing_on_a_read_only_case(tmp_path):
    """a, r and d reach the verdicts without the buttons; a reject or a
    defer asked for a reason the server then refused to record."""
    script = (_const("CASE_STATES_SHUT") + _fn("caseReadOnly")
              + "".join(_fn(n) for n in ("acceptProposal", "rejectProposal",
                                          "deferProposal",
                                          # The prompts name their card
                                          # (g01, final review c14).
                                          "triageNamed", "triageTitle",
                                          "triageClaimValue")) + r"""
const calls = [];
const window = { prompt() { calls.push('prompt'); return 'because'; } };
function disposition(p, path) { calls.push(path); }
function banner() { calls.push('banner'); }
function triageChosenLevel() { return null; }
const state = { caseRec: { status: 'CLOSED', read_only: true } };
acceptProposal({ id: 1 }); rejectProposal({ id: 1 }); deferProposal({ id: 1 });
const closed = calls.splice(0);
state.caseRec = { status: 'ACTIVE', read_only: false };
acceptProposal({ id: 1 }); rejectProposal({ id: 1 }); deferProposal({ id: 1 });
console.log(JSON.stringify({ closed: closed, open: calls }));
""")
    got = _run_node(script, tmp_path)
    assert got["closed"] == []
    assert got["open"] == ["accept", "prompt", "reject", "prompt", "defer"]


@needs_node
def test_a_read_only_refusal_is_not_called_already_dispositioned(tmp_path):
    js = _js()
    cls = js[js.index("class ApiError extends Error {"):]
    cls = cls[:cls.index("\n}\n") + 3]
    script = (cls + _const("CASE_READ_ONLY_TITLE") + _fn("disposition") + r"""
const out = { banners: [], fails: [] };
function banner(t) { out.banners.push(t); }
function fail(e) { out.fails.push(e.title); }
async function loadTriage() {}
function invalidateAnalytics() {}
async function reloadAll() {}
function cpath(p) { return p; }
let answer = null;
async function api() { throw answer; }
(async () => {
  answer = new ApiError(409, CASE_READ_ONLY_TITLE, 'This case is CLOSED.');
  await disposition({ id: 'p' }, 'accept', { note: null }, 'accepted');
  answer = new ApiError(409, 'Conflict', 'proposal is ACCEPTED');
  await disposition({ id: 'p' }, 'accept', { note: null }, 'accepted');
  console.log(JSON.stringify(out));
})();
""")
    got = _run_node(script, tmp_path)
    assert got["fails"] == ["Case is read-only"]
    # A real race keeps its banner, in ux08-triage's words ("Not <verb>").
    assert got["banners"] == ["Not accepted"]


@needs_node
def test_the_lab_does_not_offer_a_read_only_case_for_a_sample(tmp_path):
    script = _fn("fillSampleCase") + r"""
const box = { value: '' };
function $() { return box; }
let offered = null;
function opts(select, pairs, chosen) {
  offered = pairs.map((p) => p[0]); select.value = chosen;
}
const state = { caseRec: { code: 'OP-X', status: 'CLOSED', read_only: true } };
fillSampleCase();
const closed = { offered: offered, value: box.value };
state.caseRec = { code: 'OP-X', status: 'ACTIVE', read_only: false };
box.value = '';
fillSampleCase();
console.log(JSON.stringify({ closed: closed, open: { offered: offered, value: box.value } }));
"""
    got = _run_node(script, tmp_path)
    assert got["closed"] == {"offered": ["none"], "value": "none"}
    assert got["open"] == {"offered": ["case", "none"], "value": "case"}


@needs_node
def test_attach_offers_no_read_only_case(tmp_path):
    """u3 (2026-09-24): the picker compared the status with CLOSED and
    ARCHIVED, so a PURGED case was offered and then refused. It reads each
    case's own `read_only` now, and the status only for a record without
    it."""
    script = (_const("CASE_STATES_SHUT")
              + "".join(_fn(n) for n in ("caseReadOnly", "attachTargets")) + r"""
const state = { cases: [
  { id: 'a', status: 'ACTIVE', read_only: false },
  { id: 'c', status: 'CLOSED', read_only: true },
  { id: 'r', status: 'ARCHIVED', read_only: true },
  { id: 'p', status: 'PURGED', read_only: true },
  { id: 'd', status: 'DORMANT' },
  { id: 'old', status: 'PURGED' },
] };
console.log(JSON.stringify(attachTargets().map((c) => c.id)));
""")
    assert _run_node(script, tmp_path) == ["a", "d"]
    row = _fn("ingestRow")
    assert "c.status !== 'CLOSED'" not in row, (
        "the attach picker keeps its own copy of the read-only rule")
    # A read-only open case is not offered, so it is not the default either:
    # a value no option has leaves the picker blank.
    assert "value: cases.some((c) => c.id === state.caseId)" in row


#: Just enough of `el` for the Lab card's builders: a tree of tags,
#: classes and text that can be searched afterwards.
_FAKE_EL = r"""
class N {
  constructor(tag, cls, text) {
    this.tag = tag; this.cls = cls || ''; this.text = text == null ? '' : String(text);
    this.children = []; this.attrs = {};
  }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener() {}
  setAttribute(k, v) { this.attrs[k] = v; }
  all() { return [this].concat(...this.children.map((c) => c.all ? c.all() : [])); }
}
function el(tag, cls, text) { return new N(tag, cls, text); }
const document = { createTextNode: (t) => new N('#text', '', t) };
function visibleText(s) { return String(s); }
function copyable(node) { return node; }
function downloadSample() {}
const smpPolicy = { sample_origin: 'https://samples.example' };
const state = { cases: [], userId: 'u' };
const summary = (box) => {
  const nodes = box.all();
  return {
    controls: nodes.filter((n) => ['button', 'input', 'select', 'textarea']
      .includes(n.tag)).map((n) => n.text || n.tag),
    said: nodes.filter((n) => n.tag === 'p').map((n) => n.text).join(' '),
  };
};
"""


@needs_node
def test_the_lab_card_offers_no_work_on_a_read_only_cases_sample(tmp_path):
    """c21 (2026-09-24): the card drew assign, record an analysis, propose,
    detonate and reject for a CLOSED case's sample, all refused by the
    server. The row's own `case_read_only` decides it, never the open
    case, because the Lab lists samples from every case; the download, a
    read, stays."""
    names = ("smpCaseShut", "sampleWorkPanel", "detonationPanel",
             "extractedSelector", "sampleActions")
    script = (_FAKE_EL + "".join(_fn(n) for n in names) + r"""
const you = { analyse: true, detonate: true, download: true };
const s = { id: 's', sha256: 'ab'.repeat(32), state: 'QUARANTINED',
            case_id: 'c', case_read_only: true };
const sel = { selector_type: 'DOMAIN', value: 'c2.example' };
const out = {
  work: summary(sampleWorkPanel(s, you, { assignees: [] })),
  detonation: summary(detonationPanel(s, [], you, null)),
  propose: summary(extractedSelector(s, { id: 'a' }, sel, 0, you)),
  actions: summary(sampleActions(s)),
  openPropose: summary(extractedSelector(Object.assign({}, s,
    { case_read_only: false }), { id: 'a' }, sel, 0, you)),
};
console.log(JSON.stringify(out));
""")
    got = _run_node(script, tmp_path)
    for panel in ("work", "detonation"):
        assert got[panel]["controls"] == [], (panel, got[panel])
        assert "read-only" in got[panel]["said"], panel
    assert got["propose"]["controls"] == []
    assert got["openPropose"]["controls"] == ["Propose to the case"]
    assert got["actions"]["controls"] == ["Download encrypted archive"], (
        "reject is still offered, or the download went with it")
    assert "read-only" in got["actions"]["said"]
    shut = _fn("smpCaseShut")
    assert not re.search(OFF_STYLE, shut)
    # The state is not named: the reader may not be able to open the case.
    assert "CLOSED" not in shut and "ARCHIVED" not in shut
