"""Rule 1 of `http/errors.py`, enforced across every router.

    **Never stringify a database exception into a client-visible message.**

That rule was written after an adversarial pass, and it was enforced only
for exceptions that reached the registered handlers. A router that CAUGHT
a service error and re-raised `Problem(400, ..., str(exc))` bypassed all
of it — and on 2026-08-07 that was **71 sites across 15 routers**.

It leaked, and not in a theoretical way. Six services (`cases`, `graph`,
`proposals`, `retention`, `samples`, `contact_blocks`) wrap psycopg errors
as `XError(str(exc)) from exc`, so the message the router handed back
already contained the raw PQ text. Reproduced against the live database:

    RAW        insert or update on table "node" violates foreign key
               constraint "node_case_id_fkey"
               DETAIL: Key (case_id)=(0000…0001) is not present in "case".
    SANITISED  a referenced record does not exist (ref 825fdc707847)

The constraint name describes the schema; `DETAIL` echoes the offending
column VALUE, which on a real deployment is case data.

Static, because the alternative is a live test per endpoint and there are
141 of them. This reads the source and asserts the shape — weaker than
exercising every path, and it is the check that would have caught all 71
at once.

Pure: no database, no app import.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROUTERS = (Path(__file__).resolve().parents[1]
           / "src" / "noctornal_api" / "http" / "routers")

#: `raise Problem(..., str(exc))` in any spacing or line arrangement.
#: DOTALL because these are routinely wrapped across two or three lines.
_LEAK = re.compile(r"raise\s+Problem\((?:[^()]|\([^()]*\))*?str\(\s*exc\s*\)",
                   re.S)


def _routers() -> list[Path]:
    found = sorted(p for p in ROUTERS.glob("*.py") if p.name != "__init__.py")
    assert found, f"no routers under {ROUTERS} — has the tree moved?"
    return found


@pytest.mark.parametrize("path", _routers(), ids=lambda p: p.name)
def test_no_router_stringifies_an_exception_into_a_problem(path: Path) -> None:
    """Use `safe_detail(exc)`, never `str(exc)`.

    `safe_detail` returns `str(exc)` unchanged when the cause is NOT a
    psycopg error, so authored service messages are unaffected. It only
    replaces the ones that carry database text, and logs those against a
    correlation id that goes back to the caller.
    """
    hits = _LEAK.findall(path.read_text(encoding="utf-8"))
    assert not hits, (
        f"{path.name} builds a Problem from str(exc). If the exception "
        f"wraps a psycopg error — six services do exactly that — this "
        f"returns constraint names and offending column values to the "
        f"client. Use safe_detail(exc) from noctornal_api.http.errors."
    )


def test_the_sanitiser_is_actually_imported_where_it_is_used() -> None:
    """A router calling `safe_detail` must import it.

    Guards the mechanical substitution that fixed the 71 sites: a
    find-and-replace that misses the import turns a leak into a
    NameError at request time, which is a different defect and a worse
    one to discover in production.
    """
    missing = []
    for path in _routers():
        src = path.read_text(encoding="utf-8")
        if "safe_detail(" in src and "import" in src:
            imported = re.search(
                r"from noctornal_api\.http\.errors import [^\n]*safe_detail",
                src)
            if not imported:
                missing.append(path.name)
    assert not missing, f"call safe_detail without importing it: {missing}"


# --- safe_detail must unwrap however deep the chain goes -----------------

def test_safe_detail_unwraps_a_nested_service_chain():
    """One level was not enough, and the gap was reachable.

    `proposals.py:327` wraps a GraphWriteError:

        except GraphWriteError as exc:
            raise ProposalError(f"could not apply proposal: {exc}") from exc

    so accepting a proposal produced ProposalError -> GraphWriteError ->
    psycopg. The original one-level check found a GraphWriteError, decided
    there was no database cause, and returned `str(exc)` — which by then
    had the raw PQ text interpolated into it twice.
    """
    import psycopg

    from noctornal_api.graph import GraphWriteError
    from noctornal_api.http.errors import safe_detail

    db = psycopg.errors.ForeignKeyViolation(
        'insert or update on table "node" violates foreign key constraint '
        '"node_case_id_fkey"\nDETAIL:  Key (case_id)=(secret-uuid) is not '
        'present in table "case".')

    one = GraphWriteError(str(db))
    one.__cause__ = db
    two = Exception(f"could not apply proposal: {one}")
    two.__cause__ = one
    three = Exception(f"outer: {two}")
    three.__cause__ = two

    for depth, exc in (("one", one), ("two", two), ("three", three)):
        detail = safe_detail(exc)
        assert "node_case_id_fkey" not in detail, f"{depth}: constraint leaked"
        assert "secret-uuid" not in detail, f"{depth}: column VALUE leaked"
        assert "DETAIL" not in detail, f"{depth}: DETAIL line leaked"
        assert "ref " in detail, f"{depth}: no correlation id to find the log by"


def test_safe_detail_leaves_an_authored_message_alone():
    """Only DB-wrapped errors are replaced.

    Without this the sanitiser could be "fixed" by returning a fixed string
    for everything, which would erase every useful refusal the services
    write by hand.
    """
    from noctornal_api.graph import GraphWriteError
    from noctornal_api.http.errors import safe_detail

    assert safe_detail(GraphWriteError("label cannot be blank")) == \
        "label cannot be blank"


def test_safe_detail_terminates_on_a_cyclic_chain():
    """`__cause__` is not guaranteed acyclic, and this runs on the error
    path where a hang is least affordable."""
    from noctornal_api.http.errors import safe_detail

    a, b = Exception("a"), Exception("b")
    a.__cause__, b.__cause__ = b, a
    assert safe_detail(a) == "a"


# ---------------------------------------------------------------------------
# A control must not publish a field that can only ever say one thing
# ---------------------------------------------------------------------------

_SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


def test_break_glass_publishes_a_use_count_only_if_something_counts_uses():
    """`action_count` and `used_at` are written by exactly one function,
    `BreakGlassService.record_use`, and it has no caller outside its own
    test. Both are therefore constant on every grant that has ever
    existed: zero, and NULL.

    Publishing that zero to the security officer's review queue answers
    "was this grant used?" with a fact about the wiring, in the direction
    that CLOSES the question -- the reviewer sees a number, believes it,
    and the grant that was never used is exactly the interesting review
    case the field was added to surface.

    So the two must move together: either something counts uses, or the
    count is not published. This test fails whichever one is reintroduced
    without the other.
    """
    service = (_SRC / "break_glass.py").read_text(encoding="utf-8")
    router = (_SRC / "http" / "routers" / "governance.py").read_text(
        encoding="utf-8")

    published = '"action_count"' in router or '"used_at"' in router
    # Parsed, not grepped. The reasoning for the withdrawal is written in
    # break_glass.py's own docstring and NAMES `record_use()` twice, so a
    # text scan counts the explanation as an implementation -- the same
    # trap the innerHTML check in the UI suite had to avoid. An AST walk
    # sees calls and nothing else.
    counted = any(
        isinstance(node, ast.Call)
        and getattr(node.func, "attr", getattr(node.func, "id", None))
        == "record_use"
        for node in ast.walk(ast.parse(service)))

    assert published == counted, (
        "break-glass publishes a use count that nothing increments"
        if published else
        "something now records break-glass use, but the API no longer "
        "publishes it -- republish action_count/used_at")


def test_break_glass_does_not_promise_an_elevation_it_does_not_perform():
    """`invoke()` writes a grant carrying `granted_classification`, audits
    it, alerts the officer and queues the review -- and no access decision
    reads that row. Effective clearance comes from `iam.app_user`.

    An analyst who believes the elevation worked stops looking for another
    way in, at 3am, during the incident the control exists for. So the
    response says what it does; if the elevation is ever implemented, the
    grant will be read somewhere outside this module and this test should
    be updated in the same change.
    """
    stores = (_SRC / "stores.py").read_text(encoding="utf-8")
    deps = (_SRC / "http" / "deps.py").read_text(encoding="utf-8")
    router = (_SRC / "http" / "routers" / "governance.py").read_text(
        encoding="utf-8")

    reads_grant = "break_glass" in stores or "iam.break_glass" in deps
    if not reads_grant:
        assert "does NOT currently raise your clearance" in router, (
            "nothing reads the break-glass grant, and the invoke response "
            "does not say so -- an analyst will believe the elevation "
            "applied")
