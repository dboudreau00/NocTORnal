"""Rule 1 of `http/errors.py`, enforced across every router.

    **Never stringify a database exception into a client-visible message.**

Enforcing it only for exceptions that reach the registered handlers is not enough: a router that CATCHES a
service error and re-raises `Problem(400, ..., str(exc))` bypasses all of it. Six services (`cases`,
`graph`, `proposals`, `retention`, `samples`, `contact_blocks`) wrap psycopg errors as
`XError(str(exc)) from exc`, so the message the router hands back already contains the raw PQ text:

    RAW        insert or update on table "node" violates foreign key
               constraint "node_case_id_fkey"
               DETAIL: Key (case_id)=(0000...0001) is not present in "case".
    SANITISED  a referenced record does not exist (ref 825fdc707847)

The constraint name describes the schema; `DETAIL` echoes the offending column VALUE, which on a real
deployment is case data.

Static, because the alternative is a live test per endpoint. This reads the source and asserts the shape:
weaker than exercising every path, but it covers every router at once.

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
    """`safe_detail` unwraps however deep the chain goes.

    `proposals.py` wraps a GraphWriteError:

        except GraphWriteError as exc:
            raise ProposalError(f"could not apply proposal: {exc}") from exc

    so accepting a proposal produces ProposalError -> GraphWriteError -> psycopg. A one-level check would
    find a GraphWriteError, decide there was no database cause, and return `str(exc)`, which by then has
    the raw PQ text interpolated into it twice.
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
    """`action_count` and `used_at` are written by exactly one function, `BreakGlassService.record_use`.
    If nothing on the access path called it, both would be constant on every grant (zero, and NULL), and
    publishing a zero to the security officer's review queue would answer "was this grant used?" with a fact
    about the wiring, in the direction that CLOSES the question.

    `PgAccessResolver.resolve` (stores.py) calls `record_use()` whenever a live grant is what made an access
    possible, so the fields are published. The two must move together: either something on the access path
    counts uses, or the count is not published. This test fails whichever one is introduced without the
    other.
    """
    router = (_SRC / "http" / "routers" / "governance.py").read_text(
        encoding="utf-8")
    published = '"action_count"' in router or '"used_at"' in router

    # Parsed, not grepped, and over the ACCESS PATH as well as the service: break_glass.py's own docstring
    # names `record_use()` while explaining it, so a text scan would count the explanation as an
    # implementation. An AST walk sees calls and nothing else. stores.py is where the call lives (the single
    # construction site of the five-part gate's context); break_glass.py stays in the walk so that a move
    # back into the service is still seen.
    counted = False
    for name in ("stores.py", "break_glass.py"):
        source = (_SRC / name).read_text(encoding="utf-8")
        counted = counted or any(
            isinstance(node, ast.Call)
            and getattr(node.func, "attr", getattr(node.func, "id", None))
            == "record_use"
            for node in ast.walk(ast.parse(source)))

    assert published == counted, (
        "break-glass publishes a use count that nothing increments"
        if published else
        "something now records break-glass use, but the API no longer "
        "publishes it -- republish action_count/used_at")


def test_break_glass_does_not_promise_an_elevation_it_does_not_perform():
    """The invoke response says what the elevation does. `invoke()` writes a grant carrying
    `granted_classification`, audits it, alerts the officer and queues the review.

    An analyst misled about whether the elevation applied either stops looking for another way in, at 3am,
    during the incident the control exists for, or is sent looking while the door is open. So the notice
    must match whether the access path reads the grant.
    """
    stores = (_SRC / "stores.py").read_text(encoding="utf-8")
    deps = (_SRC / "http" / "deps.py").read_text(encoding="utf-8")
    router = (_SRC / "http" / "routers" / "governance.py").read_text(
        encoding="utf-8")

    reads_grant = "iam.break_glass" in stores or "iam.break_glass" in deps
    if not reads_grant:
        assert "does NOT currently raise your clearance" in router, (
            "nothing reads the break-glass grant, and the invoke response "
            "does not say so -- an analyst will believe the elevation "
            "applied")
    else:
        # The elevation is implemented (PgAccessResolver.resolve reads iam.break_glass), so the opposite
        # claim is the dangerous one: a notice that still says the grant raises nothing would send the
        # analyst looking for another way in while the door is open.
        assert "does NOT currently raise your clearance" not in router, (
            "the access path reads the break-glass grant, but the invoke "
            "response still tells the analyst the elevation did not apply")
        # The notice is computed per grant: it names the level raised FROM and TO when the grant raises,
        # and says "raises nothing" when it does not, rather than one sentence conditional on the reader.
        assert "Your clearance is raised from" in router, (
            "the invoke response must say the clearance is raised, and to "
            "what, now that it is")
        assert "raises nothing" in router, (
            "a grant that names no level, or one the caller already holds, "
            "must be told so rather than described as access")
