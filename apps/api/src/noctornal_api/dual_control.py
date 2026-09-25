"""The deployment's two-person policy, and the only way it changes (F9,
2026-09-24).

Two things are policy here:

- which operations need a second signature: the catalogue in
  `approvals.OPERATIONS` sets each operation's floor, and
  `iam.dual_control_operation` can make a configurable one stricter
  (`node.merge`: PER_CASE, where each case asks with its own switch, or
  ALWAYS);
- which permission pairs no role may hold together (`iam.separated_duty`,
  0062): the two halves of a two-person control.

Changing either takes two people too. An administrator (`dual_control.
manage`) PROPOSES a change, which raises a `dual_control.policy` approval;
a Security officer (`dual_control.countersign`) who is not also an
administrator COUNTERSIGNS it through the global approvals route; the
administrator APPLIES it, which consumes the approval and inserts one row
in `iam.dual_control_policy_change` in the same transaction. That insert is
the only way the two policy tables move, and the database refuses it unless
the approval it names was consumed there, for exactly that change, by two
people who may still act (migration dual_control_policy).

## What a change is bound to

Each payload carries `based_on`: the change the operation's row, or the
pair, was last set by. An approval is therefore for one version of the
policy, and one approved but never applied cannot come back to life after
later changes and be spent on a policy nobody was looking at (approvals.py:
"an approval is spent, not held").

## Counts, and whose

The screen says how many cases ask for a second signature on merges. Only
ever over the cases the VIEWER can open: labels they dominate AND a live
assignment (2026-09-24). A pure administrator holds no
case, so sees no number at all; a count across cases someone has no
relationship with would tell them when a case they cannot see turns its
switch on. No deployment-wide total is returned anywhere.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.approvals import (
    APPROVED,
    OPERATIONS,
    PENDING,
    ApprovalError,
    ApprovalRequest,
    ApprovalService,
    countersign_block,
    countersign_block_sentence,
    eligible_signers_sql,
    holds_global_permission,
    policy_mode,
    record_out_of_band,
    seasoning_days,
    utc_text,
)
from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.wording import agree, count_of

log = logging.getLogger(__name__)

#: The approvals catalogue key of a policy change. Written as the literal at
#: the consume call too, so the catalogue test finds it there.
OPERATION = "dual_control.policy"

#: The three kinds of change.
CHANGES = ("OPERATION_MODE", "SEPARATED_DUTY_ADD", "SEPARATED_DUTY_REMOVE")

#: A pair added from the screen says why, in at least this many characters
#: (the ledger's `dual_control_change_pair_says_why` holds the same bar).
MIN_WHY = 10

#: How far back the change card looks for the latest event that took over
#: the countersigner's account, to say so beside the countersignature.
PROVENANCE_DAYS = 90

MANAGE = "dual_control.manage"
COUNTERSIGN = "dual_control.countersign"


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class OtherControl:
    """A two-person control held per row outside `approvals.OPERATIONS` and
    `iam.separated_duty`, so the screen can list every act that takes two
    people and not only the ones this module changes. `enforced_at` names
    the function that holds it, "relative/path.py::Qualname", which
    test_approvals_catalogue.py resolves."""

    key: str
    act: str
    first: str
    second: str
    enforced_at: str


#: Two-person controls held outside the approvals table: the collection
#: authority (docs/00 decision 69), the lookup sign-off (docs/00 decision
#: 75), the exposure change and the sandbox detonation sign-off.
#: Append-only, one entry per control; the screen shows the section only
#: when this is not empty.
OTHER_TWO_PERSON_CONTROLS: tuple[OtherControl, ...] = (
    # The collection authority (2026-09-24; docs/00 decision 69).
    OtherControl(
        key="collection.authority",
        act="Reading a forum or Telegram source, public boards included",
        first=("A collection manager records the written authority and the "
               "sources under it"),
        second=("A security officer confirms the authority and each source, "
                "never the person who recorded it or added the source"),
        enforced_at="collection_authority.py::CollectionAuthorityService.confirm"),
    # F15.2 and F15.3 (2026-09-24; docs/00 decision 75). Held per row by
    # CHECKs and a trigger (0098, 0099).
    OtherControl(
        "lookup.signoff",
        "Send a case selector to a vendor or public lookup provider",
        "The analyst who asks for the lookup and names who signs it off",
        "The named lead investigator, in a separate action with a fresh "
        "sign-in, before the request lapses",
        "lookups.py::LookupService.sign_off"),
    OtherControl(
        "provider.exposure_lowering",
        "Lower a lookup provider's exposure, or determine a new one below PUBLIC",
        "The administrator who asks, with a written basis",
        "A different administrator holding integration.manage, within 72 hours",
        "providers.py::ProviderRegistry.decide_exposure_change"),
    # F14, 2026-09-24. Held per row on lab.detonation (0103's CHECKs
    # and the service), not an approvals operation: the second person is a
    # lead investigator on the sample's case, not a holder of the
    # requester's verb.
    OtherControl(
        key="sample.detonation.signoff",
        act="Send a sample to a sandbox whose exposure is not NONE, or whose "
            "network route or analysis machine is live",
        first="the requester, holding sample.detonate",
        second="a Lead investigator on the sample's case (the Lead "
               "investigator role for a sample with no case), cleared for the "
               "sample, never the requester",
        enforced_at="sandbox.py::SandboxService.sign_off"),
)

#: The screen's words for a mode.
MODE_WORDS = {"PER_CASE": "where the case asks for it", "ALWAYS": "every time"}


def _roles_for(conn: psycopg.Connection, keys: list[str]) -> dict[str, list]:
    rows = conn.execute(
        """SELECT rp.permission_key, r.key, r.display_name
             FROM iam.role_permission rp JOIN iam.role r ON r.key = rp.role_key
            WHERE rp.permission_key = ANY(%s)
            ORDER BY r.display_name""", (keys,)).fetchall()
    out: dict[str, list] = {k: [] for k in keys}
    for perm, key, name in rows:
        out[perm].append({"key": key, "display_name": name})
    return out


class DualControlPolicyService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- reads --------------------------------------------------------------

    def signers(self) -> dict:
        """Who could take part in a change today. `countersigners` counts
        only accounts that could actually countersign: active, holding
        dual_control.countersign and NOT dual_control.manage, because an
        account holding both is one person and cannot be the second one.
        The one reader used by `propose` and by the readiness row."""
        row = self._c.execute(
            """SELECT
                 (SELECT count(*) FROM iam.app_user u
                   WHERE u.is_active AND EXISTS (
                     SELECT 1 FROM iam.user_role ur
                       JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                      WHERE ur.user_id = u.id
                        AND rp.permission_key = %(requester)s)),
                 (SELECT count(*) FROM iam.app_user u
                   WHERE """ + eligible_signers_sql("u") + ")",
            {"signer": COUNTERSIGN, "requester": MANAGE}).fetchone()
        proposers, countersigners = int(row[0]), int(row[1])
        return {"proposers": proposers, "countersigners": countersigners,
                "distinct_pair": proposers > 0 and countersigners > 0}

    def _cases_requiring(self, viewer_id: UUID, *, clearance: str,
                         compartments: frozenset[str]) -> int | None:
        """How many of the cases the viewer can open have the merge switch
        on, among those whose content is not read-only. None when the
        viewer can open none at all, so nothing reads "0 of your cases" to
        someone who has no cases."""
        row = self._c.execute(
            """SELECT count(*), count(*) FILTER (WHERE c.dual_control_merge)
                 FROM core."case" c
                WHERE c.status <> ALL(%s)
                  AND c.classification <= %s::core.tlp
                  AND c.compartments <@ %s::text[]
                  AND EXISTS (
                    SELECT 1 FROM iam.case_assignment ca
                     WHERE ca.case_id = c.id AND ca.user_id = %s
                       AND (ca.expires_at IS NULL OR ca.expires_at > now()))""",
            (list(CONTENT_READ_ONLY_STATES), clearance, sorted(compartments),
             viewer_id)).fetchone()
        return None if not row[0] else int(row[1])

    def overview(self, viewer_id: UUID, *, clearance: str,
                 compartments: frozenset[str]) -> dict:
        """Everything the Two-person controls screen draws."""
        rows = {r[0]: r for r in self._c.execute(
            """SELECT operation, mode, changed_at, change_id
                 FROM iam.dual_control_operation""").fetchall()}
        perms = sorted({p for op in OPERATIONS.values()
                        for p in (op.permission, op.signer_permission)})
        roles = _roles_for(self._c, perms)
        requiring = self._cases_requiring(viewer_id, clearance=clearance,
                                          compartments=compartments)
        operations = []
        for op in OPERATIONS.values():
            row = rows.get(op.key)
            item = {
                "key": op.key, "description": op.description,
                "scope": op.scope, "mode": policy_mode(self._c, op.key),
                "modes": list(op.modes), "configurable": op.configurable,
                "enforced": op.enforced_at is not None,
                "not_enforced_because": op.not_enforced_because,
                "ttl_seconds": int(op.ttl.total_seconds()),
                "asks": {"permission": op.permission,
                         "roles": roles.get(op.permission, [])},
                "signs": {"permission": op.signer_permission,
                          "roles": roles.get(op.signer_permission, [])},
                "changed_at": row[2] if row else None,
                "change_id": str(row[3]) if row and row[3] else None,
            }
            if op.configurable and "PER_CASE" in op.modes:
                item["cases_requiring"] = requiring
            operations.append(item)
        return {
            "operations": operations,
            "separated_duties": self._pairs(),
            "violations": [
                {"role": r[0], "permission_a": r[1], "permission_b": r[2]}
                for r in self._c.execute(
                    "SELECT role_key, permission_a, permission_b "
                    "FROM iam.separated_duty_violations()").fetchall()],
            "signers": self.signers(),
            "other_controls": [asdict(c) for c in OTHER_TWO_PERSON_CONTROLS],
            "permissions": [
                {"key": r[0], "description": r[1]}
                for r in self._c.execute(
                    "SELECT key, description FROM iam.permission "
                    "ORDER BY key").fetchall()],
            "seasoning_days": seasoning_days(self._c),
        }

    def _pairs(self) -> list[dict]:
        rows = self._c.execute(
            """SELECT s.permission_a, s.permission_b, s.why, s.origin,
                      s.added_at, s.added_by_change, p.display_name,
                      cs.display_name
                 FROM iam.separated_duty s
                 LEFT JOIN iam.dual_control_policy_change c
                        ON c.id = s.added_by_change
                 LEFT JOIN iam.app_user p ON p.id = c.requested_by
                 LEFT JOIN iam.app_user cs ON cs.id = c.countersigned_by
                ORDER BY s.origin, s.permission_a, s.permission_b""").fetchall()
        roles = _roles_for(self._c, sorted({k for r in rows for k in r[:2]}))
        return [{"permission_a": r[0], "permission_b": r[1], "why": r[2],
                 "origin": r[3], "added_at": r[4],
                 "added_by_change": str(r[5]) if r[5] else None,
                 "proposer_name": r[6], "countersigner_name": r[7],
                 "a_roles": roles.get(r[0], []),
                 "b_roles": roles.get(r[1], [])} for r in rows]

    def history(self, limit: int = 100) -> list[dict]:
        """Every change applied, newest first, each in a past-tense sentence
        with no count in it: a count of cases today says nothing about a
        change made last month (2026-09-24)."""
        rows = self._c.execute(
            """SELECT c.id, c.seq, c.change, c.operation, c.mode_from,
                      c.mode_to, c.permission_a, c.permission_b, c.why,
                      c.applied_at, c.requested_by, p.display_name,
                      c.countersigned_by, s.display_name,
                      c.approval_request_id, c.based_on
                 FROM iam.dual_control_policy_change c
                 JOIN iam.app_user p ON p.id = c.requested_by
                 JOIN iam.app_user s ON s.id = c.countersigned_by
                ORDER BY c.seq DESC LIMIT %s""", (limit,)).fetchall()
        out = []
        for r in rows:
            payload = {"change": r[2], "operation": r[3], "from": r[4],
                       "to": r[5], "permission_a": r[6], "permission_b": r[7]}
            out.append({
                "id": str(r[0]), "seq": r[1], "change": r[2],
                "operation": r[3], "from": r[4], "to": r[5],
                "permission_a": r[6], "permission_b": r[7], "why": r[8],
                "applied_at": r[9], "requested_by": str(r[10]),
                "proposer_name": r[11], "countersigned_by": str(r[12]),
                "countersigner_name": r[13],
                "approval_request_id": str(r[14]),
                "based_on": str(r[15]) if r[15] else None,
                "effect": past_effect(payload)})
        return out

    # -- proposing ----------------------------------------------------------

    def propose(self, *, change: dict, justification: str,
                requested_by: UUID) -> ApprovalRequest:
        """Validate a change, fill in what the database knows (`from`,
        `based_on`, the sorted pair) and raise the approval. Every refusal
        is a sentence, and every one that the database would make at apply
        is made here first, so no signature is spent on a change that
        cannot happen."""
        payload = self._payload(change)
        signers = self.signers()
        if not signers["countersigners"]:
            raise PolicyError(
                "Nobody could countersign this: no active account holds "
                "dual_control.countersign without also holding "
                "dual_control.manage. Give the Security officer role to "
                "someone who is not an administrator first; a change nobody "
                "else can sign is a change nobody reviews.")
        return ApprovalService(self._c).request(
            operation=OPERATION, case_id=None, payload=payload,
            justification=justification, requested_by=requested_by)

    def _payload(self, change: dict) -> dict:
        kind = change.get("change")
        if kind not in CHANGES:
            raise PolicyError(
                f"unknown change {kind!r}; one of {', '.join(CHANGES)}")
        if kind == "OPERATION_MODE":
            return self._mode_payload(change)
        return self._pair_payload(kind, change)

    def _mode_payload(self, change: dict) -> dict:
        key = change.get("operation")
        op = OPERATIONS.get(key or "")
        if op is None:
            raise PolicyError(f"unknown operation {key!r}")
        if not op.configurable:
            raise PolicyError(
                f"{op.description} always needs two people: a release sets "
                f"that")
        to = change.get("to")
        if to not in op.modes:
            raise PolicyError(
                f"{op.description} can be set to {' or '.join(op.modes)}")
        row = self._c.execute(
            """SELECT mode, change_id FROM iam.dual_control_operation
                WHERE operation = %s""", (key,)).fetchone()
        if row is None:
            raise PolicyError(
                f"{op.description} has no policy row, so the database cannot "
                f"change it: run alembic upgrade head")
        if row[0] == to:
            raise PolicyError(
                f"{op.description} already needs a second signature "
                f"{MODE_WORDS[to]}")
        return {"change": "OPERATION_MODE", "operation": key, "from": row[0],
                "to": to, "based_on": str(row[1]) if row[1] else None}

    def _latest_pair_change(self, a: str, b: str) -> str | None:
        row = self._c.execute(
            """SELECT id FROM iam.dual_control_policy_change
                WHERE change IN ('SEPARATED_DUTY_ADD', 'SEPARATED_DUTY_REMOVE')
                  AND permission_a = %s AND permission_b = %s
                ORDER BY seq DESC LIMIT 1""", (a, b)).fetchone()
        return str(row[0]) if row else None

    def _declared(self, a: str, b: str) -> str | None:
        """The pair's origin when it is declared, in either order."""
        row = self._c.execute(
            """SELECT origin FROM iam.separated_duty
                WHERE (permission_a, permission_b) IN ((%s, %s), (%s, %s))""",
            (a, b, b, a)).fetchone()
        return row[0] if row else None

    def _both_holders(self, a: str, b: str) -> list[str]:
        return [r[0] for r in self._c.execute(
            """SELECT DISTINCT x.role_key FROM iam.role_permission x
                 JOIN iam.role_permission y ON y.role_key = x.role_key
                WHERE x.permission_key = %s AND y.permission_key = %s
                ORDER BY 1""", (a, b)).fetchall()]

    def _pair_payload(self, kind: str, change: dict) -> dict:
        a = (change.get("permission_a") or "").strip()
        b = (change.get("permission_b") or "").strip()
        if not a or not b:
            raise PolicyError("a pair names two permissions")
        if a == b:
            raise PolicyError("a pair names two different permissions")
        a, b = sorted((a, b))
        known = {r[0] for r in self._c.execute(
            "SELECT key FROM iam.permission WHERE key IN (%s, %s)",
            (a, b)).fetchall()}
        unknown = [k for k in (a, b) if k not in known]
        if unknown:
            raise PolicyError(
                f"no such {agree(len(unknown), 'permission', 'permissions')}: "
                f"{', '.join(unknown)}")
        origin = self._declared(a, b)
        based_on = self._latest_pair_change(a, b)
        if kind == "SEPARATED_DUTY_ADD":
            if origin is not None:
                raise PolicyError(
                    f"{a} and {b} are already a pair no role may hold")
            why = (change.get("why") or "").strip()
            if len(why) < MIN_WHY:
                raise PolicyError(
                    f"say why no role may hold both, in at least {MIN_WHY} "
                    f"characters: it is what the screen shows beside the "
                    f"pair")
            holders = self._both_holders(a, b)
            if holders:
                raise PolicyError(
                    f"{agree(len(holders), 'role', 'roles')} "
                    f"{', '.join(holders)} already "
                    f"{agree(len(holders), 'holds', 'hold')} both {a} and "
                    f"{b}: revoke one of them first, or the change would be "
                    f"refused when it is applied")
            return {"change": kind, "permission_a": a, "permission_b": b,
                    "why": why, "based_on": based_on}
        if origin is None:
            raise PolicyError(f"{a} and {b} are not a declared pair")
        if origin != "policy":
            raise PolicyError(
                f"{a} and {b} were installed with the software or by the "
                f"database owner, so only the same way removes them")
        return {"change": kind, "permission_a": a, "permission_b": b,
                "based_on": based_on}

    # -- what a waiting change would do ---------------------------------------

    def preview(self, payload: dict, *, viewer_id: UUID, clearance: str,
                compartments: frozenset[str]) -> dict:
        """The sentence a change card leads with, whether it still applies
        to the policy as it stands, and what would refuse it at apply."""
        kind = payload.get("change")
        refusal = None
        cases = None
        if kind == "OPERATION_MODE":
            row = self._c.execute(
                """SELECT mode, change_id FROM iam.dual_control_operation
                    WHERE operation = %s""",
                (payload.get("operation"),)).fetchone()
            stale = (row is None or row[0] != payload.get("from")
                     or (str(row[1]) if row[1] else None)
                     != payload.get("based_on"))
            cases = self._cases_requiring(viewer_id, clearance=clearance,
                                          compartments=compartments)
        else:
            a, b = payload.get("permission_a"), payload.get("permission_b")
            origin = self._declared(a, b)
            moved = self._latest_pair_change(a, b) != payload.get("based_on")
            if kind == "SEPARATED_DUTY_ADD":
                stale = origin is not None or moved
                holders = self._both_holders(a, b)
                if holders and not stale:
                    refusal = (
                        f"{agree(len(holders), 'Role', 'Roles')} "
                        f"{', '.join(holders)} "
                        f"{agree(len(holders), 'holds', 'hold')} both halves "
                        f"now, so applying this would be refused until one "
                        f"is revoked.")
            else:
                stale = origin != "policy" or moved
        return {"effect": effect(payload, cases), "stale": stale,
                "refusal": refusal, "cases_affected": cases}

    def countersign_view(self, request: ApprovalRequest,
                         viewer_id: UUID) -> dict | None:
        """What the viewer may do with a waiting change, and why not when
        they may not. None when they are not someone who signs it at all."""
        op = OPERATIONS.get(request.operation)
        if (op is None or request.state != PENDING or request.is_expired()
                or viewer_id == request.requested_by
                or not holds_global_permission(self._c, viewer_id,
                                               op.signer_permission)):
            return None
        if op.approver_permission and holds_global_permission(
                self._c, viewer_id, op.permission):
            return {"allowed": False, "may_refuse": True,
                    "reason": ("You can also propose these changes, so you "
                               "cannot be the second person on one. You may "
                               "still refuse it."),
                    "may_sign_after": None}
        block = countersign_block(
            self._c, viewer_id, op.signer_permission,
            proposer_id=request.requested_by,
            proposer_permission=op.permission) if op.countersigner_seasoned \
            else None
        if block is not None:
            return {"allowed": False, "may_refuse": True,
                    "reason": countersign_block_sentence(
                        block, days=seasoning_days(self._c)),
                    "may_sign_after": block["may_sign_after"]}
        return {"allowed": True, "may_refuse": True, "reason": None,
                "may_sign_after": None}

    def provenance(self, request: ApprovalRequest) -> dict | None:
        """For a decided change: the latest event in the 90 days before the
        countersignature in which someone else took over the countersigner's
        account or gave it the role that countersigns, said beside the
        signature so a reader can weigh it."""
        if request.decided_by is None or request.decided_at is None:
            return None
        block = countersign_block(
            self._c, request.decided_by, COUNTERSIGN,
            as_of=request.decided_at, lookback_days=PROVENANCE_DAYS)
        if block is None or not block["own"]:
            return None
        who = self._c.execute(
            "SELECT display_name FROM iam.app_user WHERE id = %s",
            (request.decided_by,)).fetchone()
        return {"action": block["action"], "at": block["at"],
                "by_name": block["by_name"],
                "sentence": provenance_sentence(
                    who[0] if who else "The countersigner", block)}

    # -- applying -----------------------------------------------------------

    def apply(self, request_id: UUID, *, actor_id: UUID) -> dict:
        """Spend a countersigned change and put it in force.

        The consume is the FIRST write of the transaction (the module rule
        in approvals.py), the ledger row follows it in the same one, and
        the database checks everything again at that insert. A refusal
        from the ledger rolls the consume back, so the signature is not
        spent on a change that did not happen, and it is recorded out of
        band only AFTER the rollback (2026-09-24), never
        from inside a transaction that has already audited."""
        svc = ApprovalService(self._c)
        approval = svc.get(request_id)
        if (approval is None or approval.operation != OPERATION
                or approval.case_id is not None):
            raise PolicyError("no such two-person change")
        if approval.state == APPROVED and approval.decided_by is not None:
            block = countersign_block(
                self._c, approval.decided_by, COUNTERSIGN,
                as_of=approval.decided_at, proposer_id=approval.requested_by,
                proposer_permission=MANAGE)
            if block is not None:
                self._refused(request_id, actor_id,
                              "countersigner_seasoning")
                raise PolicyError(
                    "The countersignature cannot be used: "
                    + ("the countersigner's account was taken over by "
                       "someone else in the seven days before they signed"
                       if block["own"] else
                       "the countersigner changed your account in the seven "
                       "days before they signed")
                    + ". Propose it again.")
        payload = approval.payload or {}
        try:
            with self._c.transaction():
                svc.consume(request_id, actor_id=actor_id,
                            operation="dual_control.policy", case_id=None,
                            payload=payload)
                row = self._c.execute(
                    """INSERT INTO iam.dual_control_policy_change
                           (approval_request_id, change, operation, mode_from,
                            mode_to, permission_a, permission_b, why, based_on,
                            requested_by, countersigned_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       RETURNING id, seq, applied_at""",
                    (request_id, payload.get("change"),
                     payload.get("operation"), payload.get("from"),
                     payload.get("to"), payload.get("permission_a"),
                     payload.get("permission_b"), payload.get("why"),
                     payload.get("based_on"), approval.requested_by,
                     approval.decided_by)).fetchone()
                detail = {
                    "change": payload.get("change"),
                    "operation": payload.get("operation"),
                    "from": payload.get("from"), "to": payload.get("to"),
                    "permission_a": payload.get("permission_a"),
                    "permission_b": payload.get("permission_b"),
                    "why": payload.get("why"),
                    "based_on": payload.get("based_on"),
                    "approval_request_id": str(request_id),
                    "countersigned_by": str(approval.decided_by)}
                self._c.execute(
                    """INSERT INTO audit.event
                           (actor_id, actor_kind, action, object_type,
                            object_id, detail)
                       VALUES (%s, 'USER', 'DUAL_CONTROL_POLICY_CHANGED',
                               'dual_control_policy_change', %s, %s)""",
                    (actor_id, row[0], Json(detail)))
        except ApprovalError as exc:
            # consume() recorded its own refusal, out of band, before
            # anything else in the transaction had audited.
            raise PolicyError(str(exc)) from exc
        except (psycopg.errors.RaiseException, psycopg.errors.CheckViolation,
                psycopg.errors.UniqueViolation,
                psycopg.errors.ForeignKeyViolation) as exc:
            first = str(exc).splitlines()[0].strip()
            self._refused(request_id, actor_id, first)
            raise PolicyError(first) from exc
        svc.attach_result(request_id, row[0])
        return {"change": {"id": str(row[0]), "seq": row[1],
                           "applied_at": row[2], **{k: payload.get(k) for k in (
                               "change", "operation", "from", "to",
                               "permission_a", "permission_b", "why",
                               "based_on")}},
                "effect": past_effect(payload)}

    def _refused(self, request_id: UUID, actor_id: UUID, reason: str) -> None:
        record_out_of_band(
            self._c, action="DUAL_CONTROL_APPLY_REFUSED", actor_id=actor_id,
            object_type="approval_request", object_id=request_id,
            case_id=None,
            detail={"reason": reason, "approval_request_id": str(request_id)})


# -- sentences ---------------------------------------------------------------

def effect(payload: dict, cases: int | None) -> str:
    """What a waiting change would do, in the present tense. `cases` is the
    count over the viewer's own cases, or None for a viewer with none, in
    which case no number is said."""
    kind = payload.get("change")
    if kind == "OPERATION_MODE":
        op = OPERATIONS.get(payload.get("operation") or "")
        what = op.description if op else payload.get("operation")
        if payload.get("to") == "ALWAYS":
            said = ("Every merge on this deployment will need a second "
                    "signature." if payload.get("operation") == "node.merge"
                    else f"{what} will need a second signature in every case.")
            if cases is not None:
                said += (f" Today {cases} of the cases you are assigned to "
                         f"{agree(cases, 'asks', 'ask')} for it.")
            return said
        said = ("Merges will need a second signature only where the case "
                "asks for it" if payload.get("operation") == "node.merge"
                else f"{what} will need a second signature only where the "
                     f"case asks for it")
        if cases is None:
            return said + ", and every other case would stop requiring it."
        return (said + f": {cases} of the cases you are assigned to "
                f"{agree(cases, 'does', 'do')} today, and the others would "
                f"stop requiring it.")
    a, b = payload.get("permission_a"), payload.get("permission_b")
    if kind == "SEPARATED_DUTY_ADD":
        return (f"No role may hold both {a} and {b}. A release that later "
                f"grants both to one role will stop at upgrade until this "
                f"pair is removed.")
    return f"A role may again hold both {a} and {b}."


def past_effect(payload: dict) -> str:
    """What an applied change did, in the past tense and with no count."""
    kind = payload.get("change")
    if kind == "OPERATION_MODE":
        noun = ("merges" if payload.get("operation") == "node.merge"
                else payload.get("operation"))
        if payload.get("to") == "ALWAYS":
            return f"{noun} were set to need a second signature every time"
        return (f"{noun} were set to need a second signature only where the "
                f"case asks for it")
    a, b = payload.get("permission_a"), payload.get("permission_b")
    if kind == "SEPARATED_DUTY_ADD":
        return f"{a} and {b} were declared a pair no role may hold"
    return f"the pair {a} and {b} was removed, so one role may hold both again"


_PROVENANCE = {
    "PASSWORD_RESET": "{who}'s password was reset by {by} on {at}",
    "TOTP_REENROLLED": "{who}'s authenticator was re-enrolled by {by} on {at}",
    "USER_REACTIVATED": "{who}'s account was reactivated by {by} on {at}",
    "USER_UNLOCKED": "{who}'s account was unlocked by {by} on {at}",
    "ROLE_GRANTED": "{who} was given the role {role} by {by} on {at}",
    "USER_CREATED": "{who}'s account was created by {by} on {at}",
}


def provenance_sentence(who: str, block: dict) -> str:
    return _PROVENANCE.get(block["action"], "{who}'s account was changed by "
                           "{by} on {at}").format(
        who=who, by=block["by_name"] or "another account",
        at=utc_text(block["at"]), role=block.get("role_name") or "that countersigns")


def readiness_evidence(signers: dict) -> str:
    """The readiness row's evidence, from `signers()`."""
    return (f"{count_of(signers['proposers'], 'active account', 'active accounts')} "
            f"may propose a change and "
            f"{signers['countersigners']} may countersign one")
