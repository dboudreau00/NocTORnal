"""The Telegram end-to-end check: enrolment, one read-only poll, a join check
and a logout, as a persona, through the real egress proxy. An operator runs it
with the deployment's own Telegram account (docs/17 F31, 2026-10-02).

    python scripts/telegram_live_check.py --persona <uuid> [--source <uuid>]
    python scripts/telegram_live_check.py --persona <uuid> --self-check

In production it runs in the collector service, as telegram_persona.py does
(`docker compose -f infra/production/compose.yml run --rm collector python
scripts/telegram_live_check.py ...`): the enrolment, the poll and the
logout open the persona's credential and session with the persona key,
which only the collector holds (the persona vault split, decision 174), and
it refuses anywhere else in production before it asks anybody to sign in.

## What it does, in order, and what it prints

One line per step, `[PASS]`, `[FAIL]` or `[SKIP]`, each followed by a
sentence this codebase wrote (never a library's text, never a value that
could be a secret: every line passes through the credential redactor
before it is printed, and the transcript names no phone number, code,
password, session or token). Exit 0 when nothing failed, 1 on any failure,
2 when the environment is not usable at all.

1. environment: the egress proxy is configured and in force, Telethon is
   installed, the Telegram ceiling is declared, the deployment is ready;
2. operator: the person running this signs in as the console verifies
   them (password and a current authenticator code; a recovery code is
   refused), and holds collection_account.manage;
3. persona: `--persona` names a Telegram persona with an exit;
4. authority: a live collection authority, recorded by one person and
   confirmed by another, covers the persona (and, with `--source`, the
   source): nothing below runs without one (docs/16 L3);
5. routes: the persona's run, act and stop contexts resolve on the egress
   proxy, without connecting;
6. enrolment: the persona is enrolled (telegram_persona.enrol, the
   operator typing the account's code at the prompt), or already is;
7. poll: one read-only poll of the persona's Telegram source through
   run_once, the adapter, the persona's route and the proxy;
8. join check: the persona's own membership of a member chat is read, and
   nothing is joined (TelegramChats.check_membership);
9. logout: the session is logged out at Telegram through a stop route and
   destroyed here (telegram_persona.logout).

## What it never does

It joins nothing, posts nothing, reads nothing it is not authorised to
read, and prints no secret.

## --self-check

Steps 1 and 3 to 5 run exactly as above, against the database and the
environment, connecting to nothing; step 2 is skipped (the check runs as
the system); steps 6 to 9 run only when a transport factory has been set
on this module (`TRANSPORT_FACTORY`, the test suite's fakes), and are
reported SKIP otherwise. That is the dry run: it proves the gates, the
authority and the three routes, and the shape of the transcript, before
anybody signs in to Telegram.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from uuid import UUID

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from _env import load_env_local  # noqa: E402

VIA = "scripts/telegram_live_check.py"
REASON = "telegram live check: the session is logged out at the end of the check"

#: Replaced by the tests with a fake transport factory; None is Telethon.
TRANSPORT_FACTORY = None

STEPS = ("environment", "operator", "persona", "authority", "routes",
         "enrolment", "poll", "join_check", "logout")


class Line:
    """One transcript line. A plain class, not a dataclass: the test suite
    loads this script by path, where a dataclass's annotations cannot be
    resolved against sys.modules."""

    def __init__(self, step: str, verdict: str, sentence: str):
        self.step = step
        self.verdict = verdict
        self.sentence = sentence

    def text(self) -> str:
        from noctornal_api.pinned_http import redact
        return f"[{self.verdict}] {self.step}: {redact(self.sentence)}"


class Transcript:
    def __init__(self, out=None):
        self.lines: list[Line] = []
        self._out = out or sys.stdout

    def say(self, step: str, verdict: str, sentence: str) -> None:
        line = Line(step, verdict, sentence)
        self.lines.append(line)
        print(line.text(), file=self._out)

    @property
    def failed(self) -> bool:
        return any(line.verdict == "FAIL" for line in self.lines)


def _persona_script():
    """scripts/telegram_persona.py as a module: its sign-in, enrolment and
    logout are the ones this check runs, not a second copy of them."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telegram_persona.py")
    spec = importlib.util.spec_from_file_location("telegram_persona", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.TRANSPORT_FACTORY = TRANSPORT_FACTORY
    return module


def _sentence(exc: BaseException) -> str:
    from noctornal_api.collection import attended_answer
    answer = attended_answer(exc)
    if answer is not None:
        return answer[1]
    # The class only: a library's own text can quote a phone number or an
    # address with a user name, and the redactor does not mask either (2026-10-03).
    return f"{type(exc).__name__} (the exception's own text is not printed)"


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def step_environment(conn, t: Transcript) -> bool:
    from noctornal_api import egress, telegram
    from noctornal_api.collection_authority import source_ceiling
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers.collection import refuse_unready

    ok = True
    try:
        settings = egress.proxy_settings()
    except Exception as exc:  # noqa: BLE001 - the sentence is the answer
        t.say("environment", "FAIL", _sentence(exc))
        return False
    if settings is None:
        t.say("environment", "FAIL", "No egress proxy is configured "
              "(NOCTORNAL_EGRESS_PROXY_URL), and a persona never leaves without one.")
        ok = False
    elif not egress.boundary().in_force:
        t.say("environment", "FAIL", "The egress boundary is not in force on this host.")
        ok = False
    available, sentence = telegram.client_available()
    if not available:
        t.say("environment", "FAIL", sentence)
        ok = False
    ceiling, why = source_ceiling("TELEGRAM")
    if ceiling is None:
        t.say("environment", "FAIL", why)
        ok = False
    try:
        refuse_unready(conn)
    except Problem as problem:
        t.say("environment", "FAIL", problem.detail or
              "This deployment is not ready to collect.")
        ok = False
    if ok:
        t.say("environment", "PASS", f"The egress proxy is configured, {sentence} "
              f"The Telegram ceiling is {ceiling}.")
    return ok


def step_operator(conn, t: Transcript, *, self_check: bool):
    if self_check:
        t.say("operator", "SKIP", "A self-check runs as the system and signs nobody in.")
        return None
    script = _persona_script()
    try:
        actor = script.sign_in(conn)
    except script.Refused as exc:
        t.say("operator", "FAIL", str(exc))
        return False
    t.say("operator", "PASS", "The operator signed in and holds "
          "collection_account.manage.")
    return actor


def step_persona(conn, persona_id: UUID, t: Transcript) -> dict | None:
    row = conn.execute(
        """SELECT handle, platform::text, status, egress_profile_id,
                  coalesce(octet_length(secret_ciphertext), 0) > 0,
                  session_enrolled_at IS NOT NULL
             FROM collect.collection_account WHERE id = %s""", (persona_id,)).fetchone()
    if row is None or row[1] != "TELEGRAM":
        t.say("persona", "FAIL", "No Telegram persona has that id.")
        return None
    if row[3] is None:
        t.say("persona", "FAIL", "This persona has no egress profile, so it cannot reach "
              "anything.")
        return None
    if row[2] == "BURNED":
        t.say("persona", "FAIL", "This persona is burnt and must not be used again.")
        return None
    persona = {"id": persona_id, "handle": row[0], "status": row[2],
               "egress_profile_id": row[3], "credential": bool(row[4]),
               "enrolled": bool(row[5])}
    t.say("persona", "PASS", f"Persona {row[0]} is a Telegram account in status "
          f"{row[2]}" + (", enrolled." if row[5] else ", not enrolled yet."))
    return persona


def _sources_of(conn, persona_id: UUID) -> list[tuple]:
    return conn.execute(
        """SELECT s.id, s.name, c.access_mode
             FROM collect.source s
             LEFT JOIN collect.telegram_chat c ON c.source_id = s.id
            WHERE s.collection_account_id = %s AND s.kind = 'TELEGRAM'
            ORDER BY s.is_active DESC, s.name""", (persona_id,)).fetchall()


def step_authority(conn, persona_id: UUID, source_id: UUID | None,
                   t: Transcript) -> bool:
    from noctornal_api.collection_authority import (
        AuthorityMissing,
        CollectionAuthorityService,
    )

    service = CollectionAuthorityService(conn)
    try:
        live = service.require(persona_id=persona_id, source_id=None,
                               need="PUBLIC_READ")
    except AuthorityMissing as exc:
        t.say("authority", "FAIL", str(exc))
        return False
    if source_id is not None:
        try:
            need = "MEMBER_READ" if any(
                r[2] == "MEMBER" for r in _sources_of(conn, persona_id)
                if r[0] == source_id) else "PUBLIC_READ"
            live = service.require(persona_id=persona_id, source_id=source_id,
                                   need=need)
        except AuthorityMissing as exc:
            t.say("authority", "FAIL", str(exc))
            return False
    t.say("authority", "PASS", f"A live {live.scope} authority covers the persona, "
          f"confirmed by a second person, valid until "
          f"{live.valid_until.strftime('%Y-%m-%d')}.")
    return True


def step_routes(conn, persona: dict, t: Transcript) -> bool:
    from uuid import uuid4

    from noctornal_api import egress
    from noctornal_api.pinned_http import RouteUnavailable

    name = str(persona["egress_profile_id"])
    modes = []
    for context in (f"run:{uuid4()}", f"act:{persona['id']}", f"stop:{persona['id']}"):
        try:
            route = egress.route_for("persona", name, conn=conn, context=context)
        except RouteUnavailable as exc:
            t.say("routes", "FAIL", f"The {context.split(':')[0]} route did not resolve: "
                  f"{exc}")
            return False
        if not route.proxied:
            t.say("routes", "FAIL", f"The {context.split(':')[0]} route is not through "
                  f"the egress proxy, and a persona never leaves directly.")
            return False
        modes.append(context.split(":")[0])
    t.say("routes", "PASS", "The run, act and stop contexts each resolve on the "
          "egress proxy; nothing was connected.")
    return True


def step_enrolment(conn, persona: dict, actor_id, t: Transcript) -> bool:
    if persona["enrolled"] and persona["credential"]:
        t.say("enrolment", "PASS", "The persona is enrolled already; nothing was "
              "typed and nothing was sent.")
        return True
    if actor_id is None:
        t.say("enrolment", "SKIP", "An enrolment needs the operator at the prompt; "
              "run without --self-check.")
        return True
    script = _persona_script()
    try:
        script.enrol(conn, persona["id"], actor_id=actor_id, replace=False)
    except script.Refused as exc:
        t.say("enrolment", "FAIL", str(exc))
        return False
    except Exception as exc:  # noqa: BLE001 - a sentence, never a traceback
        t.say("enrolment", "FAIL", _sentence(exc))
        return False
    persona["enrolled"] = persona["credential"] = True
    # In this transcript's own words: the persona script's line names the
    # key and the account in shapes the redactor masks.
    t.say("enrolment", "PASS", "The persona is now enrolled; what Telegram "
          "handed it is sealed here and was not printed.")
    return True


def _adapters():
    from noctornal_api.collection import default_adapters
    adapters = default_adapters()
    if TRANSPORT_FACTORY is not None:
        from noctornal_api.telegram import TelegramAdapter
        adapters["telegram"] = TelegramAdapter(TRANSPORT_FACTORY)
    return adapters


def step_poll(conn, persona: dict, source_id: UUID | None, actor_id, clearance,
              t: Transcript, held=None) -> bool:
    from noctornal_api.collection import CollectionError, CollectionService

    sources = _sources_of(conn, persona["id"])
    if source_id is not None:
        sources = [r for r in sources if r[0] == source_id]
    if not sources:
        t.say("poll", "SKIP", "This persona reads no Telegram source, so there is "
              "nothing to poll; add a chat under it first.")
        return True
    sid, name, _mode = sources[0]
    try:
        result = CollectionService(conn, _adapters()).run_once(
            sid, actor_id=actor_id, clearance=clearance, compartments=held)
    except CollectionError as exc:
        t.say("poll", "FAIL", _sentence(exc))
        return False
    row = conn.execute("SELECT error_detail FROM collect.collection_run WHERE id = %s",
                       (result.run_id,)).fetchone()
    if result.status in ("OK", "PARTIAL"):
        t.say("poll", "PASS", f"One read-only poll of {name} finished {result.status}: "
              f"{result.items_seen} items seen, {result.items_new} new, "
              f"through the persona's route.")
        return True
    t.say("poll", "FAIL", f"The poll of {name} ended {result.status}: "
          f"{(row[0] if row else None) or 'no detail was recorded'}")
    return False


def step_join_check(conn, persona: dict, source_id: UUID | None, actor_id, clearance,
                    t: Transcript, held=None) -> bool:
    from noctornal_api.collection import CollectionError
    from noctornal_api.telegram_service import TelegramChats

    members = [r for r in _sources_of(conn, persona["id"]) if r[2] == "MEMBER"
               and (source_id is None or r[0] == source_id)]
    if not members:
        t.say("join_check", "SKIP", "This persona reads no chat as a member, so "
              "there is no membership to check; nothing is ever joined by this "
              "check.")
        return True
    if actor_id is None:
        t.say("join_check", "SKIP", "A membership check is an attended act and "
              "needs the signed-in operator; run without --self-check.")
        return True
    sid, name, _mode = members[0]
    try:
        out = TelegramChats(conn, transport_factory=TRANSPORT_FACTORY).check_membership(
            sid, actor_id=actor_id, clearance=clearance, compartments=held)
    except CollectionError as exc:
        t.say("join_check", "FAIL", _sentence(exc))
        return False
    t.say("join_check", "PASS", f"Telegram reports the persona "
          f"{'a member' if out['member'] else 'not a member'} of {name}; nothing was "
          f"joined.")
    return True


def step_logout(conn, persona: dict, actor_id, t: Transcript) -> bool:
    if actor_id is None:
        t.say("logout", "SKIP", "A logout needs the signed-in operator; run without "
              "--self-check.")
        return True
    script = _persona_script()
    try:
        line = script.logout(conn, persona["id"], actor_id=actor_id, reason=REASON,
                             local_only=False)
    except script.Refused as exc:
        t.say("logout", "FAIL", str(exc))
        return False
    except Exception as exc:  # noqa: BLE001
        t.say("logout", "FAIL", _sentence(exc))
        return False
    remote = "here only" not in line
    t.say("logout", "PASS", "The persona was logged out "
          + ("at Telegram and " if remote else "here only, Telegram did not confirm it, and ")
          + "its enrolment is destroyed here.")
    return True


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------

def run_check(conn, persona_id: UUID, *, source_id: UUID | None, self_check: bool,
              actor_id=None, out=None) -> int:
    """The nine steps. `actor_id` is the test's way to run the attended
    steps under --self-check with the fakes, as a named person."""
    from noctornal_api.collection import CollectionError
    from psycopg.types.json import Json

    t = Transcript(out)
    if not step_environment(conn, t):
        return 2
    actor = actor_id
    if actor is None:
        actor = step_operator(conn, t, self_check=self_check)
        if actor is False:
            return 1
    clearance = None
    held = frozenset()
    if actor is not None:
        row = conn.execute("SELECT tlp_clearance::text FROM iam.app_user WHERE id = %s",
                           (actor,)).fetchone()
        clearance = row[0] if row else None
        # The operator's own compartments (F43): a chat filed under a key
        # they do not hold is as missing to them as one above their ceiling.
        from noctornal_api.http.deps import user_ceiling
        held = user_ceiling(conn, actor)[1]
    persona = step_persona(conn, persona_id, t)
    if persona is None:
        return 1
    if not step_authority(conn, persona_id, source_id, t):
        return 1
    if not step_routes(conn, persona, t):
        return 1
    attended = actor is not None and (not self_check or TRANSPORT_FACTORY is not None)
    try:
        if attended:
            step_enrolment(conn, persona, actor, t) and \
                step_poll(conn, persona, source_id, actor, clearance, t, held) and \
                step_join_check(conn, persona, source_id, actor, clearance, t, held)
            step_logout(conn, persona, actor, t)
        else:
            for step in ("enrolment", "poll", "join_check", "logout"):
                t.say(step, "SKIP", "A self-check connects to nothing; run without "
                      "--self-check to run this step against Telegram.")
    except CollectionError as exc:
        t.say("check", "FAIL", _sentence(exc))
    conn.execute(
        """INSERT INTO audit.event (actor_id, actor_kind, action, object_type, object_id,
                                    outcome, detail)
           VALUES (%s, %s, 'TELEGRAM_LIVE_CHECK', 'collection_account', %s, %s, %s)""",
        (actor, "USER" if actor else "SYSTEM", persona_id,
         "FAILED" if t.failed else "SUCCESS",
         Json({"via": VIA, "self_check": self_check,
               "steps": [{"step": line.step, "verdict": line.verdict}
                         for line in t.lines]})))
    return 1 if t.failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the Telegram adapter end to end, as a persona, through "
                    "the egress proxy: enrolment, one read-only poll, a join check "
                    "and a logout, each reported PASS or FAIL, with no secret printed.")
    parser.add_argument("--persona", required=True, help="the Telegram persona's id")
    parser.add_argument("--source", default=None,
                        help="the Telegram source (chat) to poll and check; the "
                             "persona's first otherwise")
    parser.add_argument("--self-check", action="store_true",
                        help="prove the gates, the authority and the routes against "
                             "the database and connect to nothing")
    args = parser.parse_args(argv)
    try:
        persona_id = UUID(args.persona)
        source_id = UUID(args.source) if args.source else None
    except ValueError:
        print("--persona and --source take ids.", file=sys.stderr)
        return 1
    load_env_local()
    from noctornal_api.config import enforce_persona_key_boundary
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.security import persona_envelope

    # The persona vault split (2026-10-02): every step that touches the
    # persona's credential or session needs the persona key, which in
    # production only the collector holds. Refused before the operator is
    # asked to sign in, and the ring is read here too, everywhere, as
    # telegram_persona.py reads it (nothing is asked of anyone when the key
    # is missing, the way a login burnt a code and then failed to seal).
    try:
        enforce_persona_key_boundary(collector=True)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        persona_envelope.ring()
    except persona_envelope.PersonaKeyError as exc:
        print(f"The persona key ring is not usable here, so nothing was "
              f"asked of anyone: {exc}", file=sys.stderr)
        return 2
    try:
        conn = connect_system(SystemPurpose.COLLECTION)
    except Exception as exc:  # noqa: BLE001 - the environment, said once
        print(f"The database could not be reached ({type(exc).__name__}).",
              file=sys.stderr)
        return 2
    try:
        return run_check(conn, persona_id, source_id=source_id,
                         self_check=args.self_check)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
