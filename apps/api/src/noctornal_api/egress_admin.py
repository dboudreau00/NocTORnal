"""Configuring where anything may leave this deployment: egress profiles and
their sealed exits, integration routes and their exact destinations, and the
passive default (S2, the egress proxy, 2026-09-24; docs/00 decision 68).

## Every write is step-up, audited, and says what it widened

The routes (http/routers/egress.py) require egress.manage, a step-up
permission held by SYS_ADMIN; scripts/egress_setup.py signs the operator
in with a password and a current authenticator code. Every change writes
one audit.event row naming the action and, for a policy, the before and
after. A change that makes a profile reach further than before is decided
by the database (collect.egress_profile_reach, 0085), reported back as
`widened`, and costs every collection authority recorded before it: the
egress proxy refuses them until a new authority is recorded and confirmed
by a second person.

## Exits are sealed here and never shown again

An exit's address and credentials are HPKE-sealed to the egress proxy's
public key (security/egress_seal.py); this process cannot open what it
seals. The plaintext is never stored, logged, audited or returned: the
answer says it was sealed and cannot be shown again. A RESIDENTIAL or VPN
exit reached in clear across the internet (http or SOCKS5 to a public
upstream) is refused unless the administrator acknowledges it in the same
call, which is audited and shown on the profile.

## Labels

A profile's policy names the forums its sources target, so the overview
labels it at the greater of its ceiling and the highest label among the
sources bound to it (through its personas or directly), and, once
collect.source carries compartments, by their union. Above the caller's
clearance or compartments only its name, kind, exit kind and state are
shown, the dry-run check answers 404, and the withheld profiles are
counted.

## Destinations are egress_policy rules and nothing else

An integration entry is one rule in parse_rule's form (NAME:PORTS,
NAME@CIDR:PORTS or CIDR:PORTS) validated by egress_policy.validate_rule:
no wildcard, no suffix, the /16 and /64 caps, no reserved service name,
nothing overlapping this deployment's own networks (in production the
proxy's exits network included; the models network stays nameable, since
an embeddings entry naming it is how a local model is reached), loopback
only outside production. The proxy admits with the same functions.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import egress, egress_policy, egress_routes
from noctornal_api.egress_policy import (
    Refusal,
    Rule,
    check_destination,
    format_rule,
    parse_rule,
    validate_rule,
)
from noctornal_api.pinned_http import RouteUnavailable
from noctornal_api.security import egress_seal

PROFILE_KINDS = ("RESIDENTIAL", "DATACENTRE", "TOR", "VPN")
TLP_NAMES = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")

ONE_PERSONA_NOTICE = ("One persona, one profile: two personas sharing an exit can be "
                      "correlated by any competent forum admin.")
CLEARTEXT_REFUSAL = ("The exit's credentials and every target name would cross the "
                     "internet in clear to this provider. Use an https exit, or "
                     "acknowledge it.")
CLEARTEXT_NOTICE = ("The exit's credentials and every target name cross the internet "
                    "in clear to this provider.")
RESOLVE_NOTICE = ("Every target name this persona visits is then looked up by this "
                  "platform's own resolver, which the exit is meant to hide.")


class EgressAdminError(Exception):
    """A refusal with the HTTP status the router answers: 404 for an id
    that is not there (or not shown to the caller), 409 for a rule."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def _not_found(what: str) -> EgressAdminError:
    return EgressAdminError(f"no such {what}", 404)


def _tlp_index(name: str) -> int:
    return TLP_NAMES.index(name)


def _production(env=None) -> bool:
    return egress._production(env)


def _internal(env=None):
    env = os.environ if env is None else env
    try:
        return egress_policy.internal_networks(env, production=_production(env))
    except ValueError as exc:
        raise EgressAdminError(str(exc)) from None


class EgressAdminService:
    """One transaction per write. `actor_kind` is USER for the console and
    for the headless script, which signs its operator in; `via` detail says
    where a change came from."""

    def __init__(self, conn: psycopg.Connection, *, env=None):
        self._c = conn
        self._env = os.environ if env is None else env

    # --- reading -------------------------------------------------------------

    def _has_bindings(self) -> bool:
        """Whether the collection framework's binding columns exist."""
        return self._c.execute(
            """SELECT count(*) = 2 FROM information_schema.columns
                WHERE table_schema = 'collect' AND table_name = 'source'
                  AND column_name IN ('collection_account_id', 'egress_profile_id')"""
        ).fetchone()[0]

    def _has_authorities(self) -> bool:
        return self._c.execute(
            "SELECT to_regclass('collect.collection_authority') IS NOT NULL").fetchone()[0]

    def _has_compartments(self) -> bool:
        return self._c.execute(
            """SELECT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'collect' AND table_name = 'source'
                  AND column_name = 'compartments')""").fetchone()[0]

    def _profile_facts(self) -> dict[UUID, dict]:
        """Per profile: the highest label and the compartments among the
        sources bound to it, how many personas it carries and how many
        live authorities (by label) stand behind them."""
        facts: dict[UUID, dict] = {}
        for pid, personas in self._c.execute(
                """SELECT egress_profile_id, count(*) FROM collect.collection_account
                    WHERE egress_profile_id IS NOT NULL GROUP BY 1""").fetchall():
            facts.setdefault(pid, {})["personas"] = personas
        if not self._has_bindings():
            return facts
        comp = ", s.compartments" if self._has_compartments() else ", '{}'::text[]"
        rows = self._c.execute(
            f"""SELECT coalesce(a.egress_profile_id, s.egress_profile_id),
                       s.classification::text{comp}
                  FROM collect.source s
                  LEFT JOIN collect.collection_account a ON a.id = s.collection_account_id
                 WHERE coalesce(a.egress_profile_id, s.egress_profile_id) IS NOT NULL"""
        ).fetchall()
        for pid, label, comps in rows:
            entry = facts.setdefault(pid, {})
            if _tlp_index(label) > _tlp_index(entry.get("label", "CLEAR")):
                entry["label"] = label
            entry.setdefault("compartments", set()).update(comps or ())
            entry["sources"] = entry.get("sources", 0) + 1
        if self._has_authorities():
            for pid, label, count in self._c.execute(
                    """SELECT coalesce(a.egress_profile_id, s.egress_profile_id),
                              au.classification::text, count(DISTINCT au.id)
                         FROM collect.collection_authority au
                         LEFT JOIN collect.collection_account a
                                ON a.id = au.collection_account_id
                         LEFT JOIN collect.collection_authority_target t
                                ON t.authority_id = au.id AND au.collection_account_id IS NULL
                         LEFT JOIN collect.source s ON s.id = t.source_id
                        WHERE au.confirmed_at IS NOT NULL AND au.revoked_at IS NULL
                          AND au.valid_from <= now() AND now() < au.valid_until
                          AND coalesce(a.egress_profile_id, s.egress_profile_id) IS NOT NULL
                        GROUP BY 1, 2""").fetchall():
                entry = facts.setdefault(pid, {})
                entry.setdefault("authorities", {})[label] = count
        return facts

    def _profiles(self) -> list[egress_routes.ProfileRow]:
        return [egress_routes.profile_from(r) for r in self._c.execute(
            f"SELECT {egress_routes.PROFILE_COLUMNS} FROM collect.egress_profile "
            f"ORDER BY retired_at IS NOT NULL, name").fetchall()]

    def _profile(self, profile_id: UUID) -> egress_routes.ProfileRow:
        row = self._c.execute(
            f"SELECT {egress_routes.PROFILE_COLUMNS} FROM collect.egress_profile "
            f"WHERE id = %s", (profile_id,)).fetchone()
        if row is None:
            raise _not_found("egress profile")
        return egress_routes.profile_from(row)

    def _visible(self, label: str, comps: set[str], clearance: str,
                 held: frozenset[str]) -> bool:
        return _tlp_index(label) <= _tlp_index(clearance) and set(comps) <= set(held)

    def profile_label(self, profile: egress_routes.ProfileRow,
                      facts: dict | None = None) -> tuple[str, set[str]]:
        facts = self._profile_facts() if facts is None else facts
        entry = facts.get(profile.id, {})
        label = profile.ceiling
        if _tlp_index(entry.get("label", "CLEAR")) > _tlp_index(label):
            label = entry["label"]
        return label, set(entry.get("compartments", ()))

    def _seal_facts(self, profile_id: UUID) -> dict:
        row = self._c.execute(
            """SELECT p.exit_sealed_at, u.display_name, p.cleartext_upstream_ack
                 FROM collect.egress_profile p
                 LEFT JOIN iam.app_user u ON u.id = p.exit_sealed_by
                WHERE p.id = %s""", (profile_id,)).fetchone()
        return {"exit_sealed_at": row[0].isoformat() if row and row[0] else None,
                "exit_sealed_by": row[1] if row else None,
                "cleartext_upstream_ack": bool(row and row[2])}

    def overview(self, *, clearance: str, compartments=frozenset()) -> dict:
        facts = self._profile_facts()
        held = frozenset(compartments)
        profiles, withheld = [], 0
        for p in self._profiles():
            label, comps = self.profile_label(p, facts)
            entry = facts.get(p.id, {})
            base = {"id": str(p.id), "name": p.name, "kind": p.kind,
                    "exit_kind": p.exit_kind, "is_active": p.is_active,
                    "retired": p.retired, "is_passive_default": p.is_passive_default}
            if not self._visible(label, comps, clearance, held):
                withheld += 1
                profiles.append({**base, "withheld": True})
                continue
            authorities = entry.get("authorities", {})
            within = sum(n for lvl, n in authorities.items()
                         if _tlp_index(lvl) <= _tlp_index(clearance))
            profiles.append({
                **base, "withheld": False, "region": p.region, "ceiling": p.ceiling,
                "label": label,
                "policy": {"allowed_ports": list(p.allowed_ports),
                           "any_public_host": p.any_public_host,
                           "allowed_host_suffixes": list(p.suffixes),
                           "allowed_cidrs": list(p.cidrs), "allow_onion": p.allow_onion,
                           "resolve_at_proxy": p.resolve_at_proxy,
                           "idle_timeout_s": p.idle_timeout_s,
                           "max_session_s": p.max_session_s,
                           "max_concurrent": p.max_concurrent},
                "exit_seal_key_id": p.exit_seal_key_id,
                **self._seal_facts(p.id),
                "reach_changed_at": (p.reach_changed_at.isoformat()
                                     if p.reach_changed_at else None),
                "persona_count": entry.get("personas", 0),
                "source_count": entry.get("sources", 0),
                "live_authorities": within,
                "authorities_above_clearance": within != sum(authorities.values()),
                "persona_capable": bool(p.is_active and not p.retired
                                        and not p.is_passive_default
                                        and p.exit_kind in egress_seal.SEALED_EXIT_KINDS),
            })
        passive = next((p["id"] for p in profiles if p["is_passive_default"]), None)
        return {
            "proxy": self.proxy_facts(),
            "profiles": profiles,
            "withheld": withheld,
            "routes": self.routes(),
            "integrations": sorted(egress.INTEGRATIONS),
            "families": sorted(egress.INTEGRATION_FAMILIES),
            "presets": egress_routes.presets(),
            "passive_default_id": passive,
            "notice": ONE_PERSONA_NOTICE,
            "production": _production(self._env),
        }

    def proxy_facts(self) -> dict:
        try:
            settings = egress.proxy_settings(self._env)
            problem = None
        except RouteUnavailable as exc:
            settings, problem = None, str(exc)
        key_id = None
        try:
            key_id = egress_seal.key_id(egress_seal.public_from_env(self._env))
        except egress_seal.SealError:
            pass
        if problem is not None:
            mode = "misconfigured"
        elif settings is not None:
            mode = "proxy"
        elif _production(self._env):
            mode = "production_without_proxy"
        else:
            mode = "development"
        return {"mode": mode, "problem": problem,
                "address": (f"{settings.host}:{settings.port}" if settings else None),
                "seal_key_id": key_id,
                "sealing_available": key_id is not None and self._fingerprint_ok()}

    def _fingerprint_ok(self) -> bool:
        try:
            egress_seal.fingerprint_key(self._env)
        except egress_seal.SealError:
            return False
        return True

    def routes(self) -> list[dict]:
        rows = self._c.execute(
            """SELECT id, name, description, is_active, retired_at, retire_reason,
                      idle_timeout_s, max_session_s, max_concurrent, created_at
                 FROM collect.egress_integration_route
                ORDER BY retired_at IS NOT NULL, name, created_at DESC""").fetchall()
        entries: dict[UUID, list] = {}
        for d in self._c.execute(
                """SELECT id, route_id, entry, note, created_at, retired_at
                     FROM collect.egress_destination ORDER BY created_at""").fetchall():
            network = None
            try:
                rule = parse_rule(d[2])
                for net in egress_policy.rule_networks(rule):
                    if egress_policy._wholly_private(net):
                        network = str(net)
            except ValueError:
                pass
            entries.setdefault(d[1], []).append({
                "id": str(d[0]), "entry": d[2], "note": d[3],
                "created_at": d[4].isoformat(), "retired": d[5] is not None,
                "private_network": network})
        return [{"id": str(r[0]), "name": r[1], "description": r[2], "is_active": r[3],
                 "retired": r[4] is not None, "retire_reason": r[5],
                 "idle_timeout_s": r[6], "max_session_s": r[7], "max_concurrent": r[8],
                 "created_at": r[9].isoformat(),
                 "destinations": entries.get(r[0], [])} for r in rows]

    # --- auditing ------------------------------------------------------------

    def _audit(self, actor_id: UUID, action: str, object_type: str, object_id,
               detail: dict, *, via: dict | None = None) -> None:
        body = dict(detail)
        if via:
            body.update(via)
        self._c.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action, object_type,
                                        object_id, detail)
               VALUES (%s, 'USER', %s, %s, %s, %s)""",
            (actor_id, action, object_type, object_id, Json(body)))

    # --- profiles -------------------------------------------------------------

    def _validate_policy(self, kind: str, policy: dict) -> dict:
        production = _production(self._env)
        internal = _internal(self._env)
        out: dict[str, Any] = {}
        ports = policy.get("allowed_ports")
        if ports is not None:
            try:
                ports = sorted({int(p) for p in ports})
            except (TypeError, ValueError):
                raise EgressAdminError("Ports are whole numbers from 1 to 65535.") from None
            if not 1 <= len(ports) <= 16 or not all(1 <= p <= 65535 for p in ports):
                raise EgressAdminError("Give between 1 and 16 ports, each from 1 to 65535.")
            out["allowed_ports"] = ports
        check_ports = frozenset(out.get("allowed_ports") or [443])
        suffixes = policy.get("allowed_host_suffixes")
        if suffixes is not None:
            cleaned = []
            for text in suffixes:
                text = str(text).strip()
                if not text:
                    continue
                try:
                    rule = Rule(check_ports, suffix=text)
                except ValueError:
                    raise EgressAdminError(f"{text}: not a host name suffix.") from None
                problems = validate_rule(rule, kind="persona", production=production,
                                         internal=internal)
                if problems:
                    raise EgressAdminError(problems[0])
                cleaned.append(rule.suffix)
            if len(cleaned) > 64:
                raise EgressAdminError("A profile names at most 64 host suffixes.")
            out["allowed_host_suffixes"] = sorted(set(cleaned))
        cidrs = policy.get("allowed_cidrs")
        if cidrs is not None:
            cleaned = []
            for text in cidrs:
                text = str(text).strip()
                if not text:
                    continue
                try:
                    rule = Rule(check_ports, network=text)
                except ValueError:
                    raise EgressAdminError(f"{text}: not a network.") from None
                problems = validate_rule(rule, kind="persona", production=production,
                                         internal=internal)
                if problems:
                    raise EgressAdminError(problems[0])
                cleaned.append(str(rule.network))
            if len(cleaned) > 64:
                raise EgressAdminError("A profile names at most 64 networks.")
            out["allowed_cidrs"] = sorted(set(cleaned))
        for flag in ("any_public_host", "allow_onion", "resolve_at_proxy"):
            if policy.get(flag) is not None:
                out[flag] = bool(policy[flag])
        if out.get("allow_onion") and kind != "TOR":
            raise EgressAdminError("Only a TOR profile reaches onion services.")
        if out.get("resolve_at_proxy") and kind == "TOR":
            raise EgressAdminError("A TOR profile never resolves target names here: its "
                                   "exit relay does.")
        for name, low, high in (("idle_timeout_s", 5, 3600), ("max_session_s", 10, 86400),
                                ("max_concurrent", 1, 64)):
            if policy.get(name) is not None:
                value = int(policy[name])
                if not low <= value <= high:
                    raise EgressAdminError(f"{name} is from {low} to {high}.")
                out[name] = value
        return out

    def create_profile(self, *, actor_id: UUID, name: str, kind: str, region: str | None,
                       ceiling: str, policy: dict, via: dict | None = None) -> dict:
        name = (name or "").strip()
        if not 3 <= len(name) <= 80:
            raise EgressAdminError("Name the profile in 3 to 80 characters.")
        if kind not in PROFILE_KINDS:
            raise EgressAdminError("A profile is RESIDENTIAL, DATACENTRE, TOR or VPN.")
        if ceiling not in TLP_NAMES:
            raise EgressAdminError("Choose the highest label this profile may carry.")
        values = self._validate_policy(kind, policy)
        columns = ["name", "kind", "region", "ceiling", "created_by"] + list(values)
        params = [name, kind, (region or "").strip() or None, ceiling, actor_id] + [
            values[k] for k in values]
        casts = ["%s", "%s", "%s", "%s::core.tlp", "%s"] + [
            "%s::cidr[]" if k == "allowed_cidrs" else "%s" for k in values]
        with self._c.transaction():
            if self._c.execute(
                    "SELECT EXISTS (SELECT 1 FROM collect.egress_profile WHERE name = %s)",
                    (name,)).fetchone()[0]:
                # Names are unique for life (0010's constraint): a retired
                # profile keeps its name in the record.
                raise EgressAdminError("A profile already has that name, retired or not.")
            pid = self._c.execute(
                f"INSERT INTO collect.egress_profile ({', '.join(columns)}) "
                f"VALUES ({', '.join(casts)}) RETURNING id", params).fetchone()[0]
            self._audit(actor_id, "EGRESS_PROFILE_CREATED", "egress_profile", pid,
                        {"name": name, "kind": kind, "ceiling": ceiling,
                         "policy": self._policy_of(self._profile(pid))}, via=via)
        return {"id": str(pid)}

    @staticmethod
    def _policy_of(p: egress_routes.ProfileRow) -> dict:
        return {"ceiling": p.ceiling, "allowed_ports": list(p.allowed_ports),
                "any_public_host": p.any_public_host,
                "allowed_host_suffixes": list(p.suffixes),
                "allowed_cidrs": list(p.cidrs), "allow_onion": p.allow_onion,
                "resolve_at_proxy": p.resolve_at_proxy, "idle_timeout_s": p.idle_timeout_s,
                "max_session_s": p.max_session_s, "max_concurrent": p.max_concurrent}

    def authorities_on(self, profile_id: UUID, *, clearance: str) -> tuple[int, bool]:
        """(live authorities for the personas and persona-less sources bound
        to this profile within the caller's clearance, whether some are
        above it)."""
        entry = self._profile_facts().get(profile_id, {}).get("authorities", {})
        within = sum(n for lvl, n in entry.items() if _tlp_index(lvl) <= _tlp_index(clearance))
        return within, within != sum(entry.values())

    def set_policy(self, *, actor_id: UUID, profile_id: UUID, clearance: str,
                   policy: dict, via: dict | None = None) -> dict:
        before = self._profile(profile_id)
        if before.retired:
            raise EgressAdminError("A retired profile keeps its policy.")
        values = self._validate_policy(before.kind, policy)
        if "ceiling" in policy and policy["ceiling"] is not None:
            if policy["ceiling"] not in TLP_NAMES:
                raise EgressAdminError("Choose the highest label this profile may carry.")
            values["ceiling"] = policy["ceiling"]
        if not values:
            raise EgressAdminError("Nothing to change.")
        affected, above = self.authorities_on(profile_id, clearance=clearance)
        personas = self._c.execute(
            "SELECT count(*) FROM collect.collection_account WHERE egress_profile_id = %s",
            (profile_id,)).fetchone()[0]
        sets = ", ".join(
            f"{k} = %s::core.tlp" if k == "ceiling" else
            f"{k} = %s::cidr[]" if k == "allowed_cidrs" else f"{k} = %s" for k in values)
        with self._c.transaction():
            self._c.execute(f"UPDATE collect.egress_profile SET {sets}, updated_by = %s "
                            f"WHERE id = %s", [*values.values(), actor_id, profile_id])
            after = self._profile(profile_id)
            widened = after.reach_changed_at != before.reach_changed_at
            self._audit(actor_id, "EGRESS_PROFILE_POLICY_CHANGED", "egress_profile",
                        profile_id, {"before": self._policy_of(before),
                                     "after": self._policy_of(after), "widened": widened},
                        via=via)
        return {"profile": str(profile_id), "widened": widened,
                "authorities_affected": affected if widened else 0,
                "authorities_above_clearance": above and widened,
                "personas_affected": personas if widened else 0}

    def seal_exit(self, *, actor_id: UUID, profile_id: UUID, exit_kind: str,
                  endpoint: egress_seal.ExitEndpoint | None,
                  cleartext_ack: bool = False, via: dict | None = None) -> dict:
        """Seal an exit (or set DIRECT). Returns the key id and whether the
        profile now reaches further; never any part of the endpoint."""
        before = self._profile(profile_id)
        if before.retired:
            raise EgressAdminError("A retired profile takes no exit.")
        if exit_kind not in egress_seal.EXIT_KINDS:
            raise EgressAdminError("An exit is DIRECT, HTTP, HTTPS or SOCKS5.")
        if before.is_passive_default and exit_kind != "DIRECT":
            raise EgressAdminError("The passive default leaves from this deployment's "
                                   "own address: its exit is DIRECT.")
        if exit_kind == "DIRECT":
            if before.kind != "DATACENTRE":
                raise EgressAdminError("Only a DATACENTRE profile leaves from this "
                                       "deployment's own address.")
            with self._c.transaction():
                self._c.execute(
                    """UPDATE collect.egress_profile
                          SET exit_kind = 'DIRECT', exit_sealed = NULL,
                              exit_seal_key_id = NULL, exit_fingerprint = NULL,
                              exit_sealed_at = now(), exit_sealed_by = %s,
                              cleartext_upstream_ack = false, updated_by = %s
                        WHERE id = %s""", (actor_id, actor_id, profile_id))
                widened = self._profile(profile_id).reach_changed_at != before.reach_changed_at
                self._audit(actor_id, "EGRESS_EXIT_SEALED", "egress_profile", profile_id,
                            {"exit_kind": "DIRECT", "key_id": None, "widened": widened},
                            via=via)
            return {"exit_kind": "DIRECT", "key_id": None, "widened": widened,
                    "notice": "This profile leaves from this deployment's own address."}
        if endpoint is None:
            raise EgressAdminError("Give the exit's host and port.")
        if before.kind == "TOR" and exit_kind != "SOCKS5":
            raise EgressAdminError("A TOR profile's exit is SOCKS5.")
        try:
            egress_seal.validate_endpoint(exit_kind, endpoint)
            public = egress_seal.public_from_env(self._env)
            fp_key = egress_seal.fingerprint_key(self._env)
        except egress_seal.SealError as exc:
            raise EgressAdminError(str(exc)) from None
        cleartext = (before.kind in ("RESIDENTIAL", "VPN")
                     and exit_kind in ("HTTP", "SOCKS5")
                     and _public_upstream(endpoint.host))
        if cleartext and not cleartext_ack:
            raise EgressAdminError(CLEARTEXT_REFUSAL)
        try:
            blob, kid = egress_seal.seal(public, profile_id=profile_id,
                                         exit_kind=exit_kind, endpoint=endpoint)
        except egress_seal.SealError as exc:
            raise EgressAdminError(str(exc)) from None
        fingerprint = egress_seal.fingerprint(fp_key, exit_kind, endpoint)
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.egress_profile
                      SET exit_kind = %s, exit_sealed = %s, exit_seal_key_id = %s,
                          exit_fingerprint = %s, exit_sealed_at = now(),
                          exit_sealed_by = %s, cleartext_upstream_ack = %s,
                          updated_by = %s
                    WHERE id = %s""",
                (exit_kind, blob, kid, fingerprint, actor_id, bool(cleartext),
                 actor_id, profile_id))
            widened = self._profile(profile_id).reach_changed_at != before.reach_changed_at
            self._audit(actor_id, "EGRESS_EXIT_SEALED", "egress_profile", profile_id,
                        {"exit_kind": exit_kind, "key_id": kid, "widened": widened,
                         "cleartext_acknowledged": bool(cleartext)}, via=via)
        return {"exit_kind": exit_kind, "key_id": kid, "widened": widened,
                "notice": egress_seal.SEALED_NOTICE,
                "cleartext_acknowledged": bool(cleartext)}

    def set_passive_default(self, *, actor_id: UUID, profile_id: UUID,
                            via: dict | None = None) -> dict:
        target = self._profile(profile_id)
        if target.retired or not target.is_active:
            raise EgressAdminError("Only an active profile can be the passive default.")
        if target.kind != "DATACENTRE" or target.exit_kind not in (None, "DIRECT"):
            raise EgressAdminError("The passive default is a DATACENTRE profile that leaves "
                                   "from this deployment's own address.")
        if self._c.execute(
                "SELECT EXISTS (SELECT 1 FROM collect.collection_account "
                "WHERE egress_profile_id = %s)", (profile_id,)).fetchone()[0]:
            raise EgressAdminError("A persona is bound to this profile, so it cannot carry "
                                   "the passive feed traffic too.")
        with self._c.transaction():
            previous = self._c.execute(
                """UPDATE collect.egress_profile SET is_passive_default = false,
                          updated_by = %s
                    WHERE is_passive_default AND id <> %s RETURNING id""",
                (actor_id, profile_id)).fetchone()
            self._c.execute(
                """UPDATE collect.egress_profile SET is_passive_default = true,
                          exit_kind = coalesce(exit_kind, 'DIRECT'), updated_by = %s
                    WHERE id = %s""", (actor_id, profile_id))
            self._audit(actor_id, "EGRESS_PASSIVE_DEFAULT_SET", "egress_profile",
                        profile_id, {"previous_id": str(previous[0]) if previous else None},
                        via=via)
        return {"passive_default_id": str(profile_id),
                "previous_id": str(previous[0]) if previous else None}

    def set_active(self, *, actor_id: UUID, profile_id: UUID, active: bool,
                   via: dict | None = None) -> dict:
        before = self._profile(profile_id)
        if before.retired:
            raise EgressAdminError("A retired profile stays off.")
        if not active and before.is_passive_default:
            raise EgressAdminError("Make another profile the passive default before "
                                   "switching this one off, or retire it.")
        with self._c.transaction():
            self._c.execute("UPDATE collect.egress_profile SET is_active = %s, "
                            "updated_by = %s WHERE id = %s", (active, actor_id, profile_id))
            widened = self._profile(profile_id).reach_changed_at != before.reach_changed_at
            self._audit(actor_id, "EGRESS_PROFILE_ACTIVATED" if active
                        else "EGRESS_PROFILE_DEACTIVATED", "egress_profile", profile_id,
                        {"widened": widened}, via=via)
        return {"profile": str(profile_id), "is_active": active, "widened": widened}

    def retire(self, *, actor_id: UUID, profile_id: UUID, reason: str,
               via: dict | None = None) -> dict:
        before = self._profile(profile_id)
        if before.retired:
            raise EgressAdminError("The profile is already retired.")
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise EgressAdminError("Say why, in at least five characters.")
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.egress_profile
                      SET is_active = false, is_passive_default = false,
                          retired_at = now(), retired_by = %s, retire_reason = %s,
                          updated_by = %s
                    WHERE id = %s""", (actor_id, reason, actor_id, profile_id))
            self._audit(actor_id, "EGRESS_PROFILE_RETIRED", "egress_profile", profile_id,
                        {"reason": reason,
                         "was_passive_default": before.is_passive_default}, via=via)
        return {"profile": str(profile_id), "retired": True,
                "passive_default_cleared": before.is_passive_default,
                "notice": ("It was the passive default: feeds have no route until "
                           "another profile is made the passive default.")
                if before.is_passive_default else None}

    # --- integration routes ------------------------------------------------------

    @staticmethod
    def route_name(name: str) -> str:
        name = (name or "").strip()
        if name in egress.INTEGRATIONS:
            return name
        for prefix in egress.INTEGRATION_FAMILIES:
            if name.startswith(prefix):
                try:
                    return egress_policy.family_route_name(prefix, name[len(prefix):])
                except ValueError:
                    break
        raise EgressAdminError("A route is named for a registered integration ("
                               + ", ".join(sorted(egress.INTEGRATIONS)) + ") or a lookup "
                               "provider (lookup-<provider key>).")

    def _route(self, route_id: UUID) -> tuple:
        row = self._c.execute(
            """SELECT id, name, is_active, retired_at IS NOT NULL
                 FROM collect.egress_integration_route WHERE id = %s""",
            (route_id,)).fetchone()
        if row is None:
            raise _not_found("egress route")
        return row

    def create_route(self, *, actor_id: UUID, name: str, description: str,
                     limits: dict | None = None, via: dict | None = None) -> dict:
        name = self.route_name(name)
        description = (description or "").strip()
        if not 5 <= len(description) <= 500:
            raise EgressAdminError("Describe the route in 5 to 500 characters.")
        values = self._limits(limits or {})
        with self._c.transaction():
            if self._c.execute(
                    """SELECT EXISTS (SELECT 1 FROM collect.egress_integration_route
                        WHERE name = %s AND retired_at IS NULL)""", (name,)).fetchone()[0]:
                raise EgressAdminError("A live route already has that name: change it, or "
                                       "retire it first.")
            columns = ["name", "description", "created_by"] + list(values)
            rid = self._c.execute(
                f"INSERT INTO collect.egress_integration_route ({', '.join(columns)}) "
                f"VALUES ({', '.join(['%s'] * len(columns))}) RETURNING id",
                [name, description, actor_id, *values.values()]).fetchone()[0]
            self._audit(actor_id, "EGRESS_ROUTE_CREATED", "egress_route", rid,
                        {"name": name, "description": description, **values}, via=via)
        return {"id": str(rid), "name": name}

    @staticmethod
    def _limits(limits: dict) -> dict:
        out = {}
        for name, low, high in (("idle_timeout_s", 5, 3600), ("max_session_s", 10, 86400),
                                ("max_concurrent", 1, 64)):
            if limits.get(name) is not None:
                value = int(limits[name])
                if not low <= value <= high:
                    raise EgressAdminError(f"{name} is from {low} to {high}.")
                out[name] = value
        return out

    def update_route(self, *, actor_id: UUID, route_id: UUID, description: str | None,
                     limits: dict | None, is_active: bool | None,
                     via: dict | None = None) -> dict:
        row = self._route(route_id)
        if row[3]:
            raise EgressAdminError("A retired route stays retired.")
        values = self._limits(limits or {})
        if description is not None:
            description = description.strip()
            if not 5 <= len(description) <= 500:
                raise EgressAdminError("Describe the route in 5 to 500 characters.")
            values["description"] = description
        if is_active is not None:
            values["is_active"] = bool(is_active)
        if not values:
            raise EgressAdminError("Nothing to change.")
        with self._c.transaction():
            self._c.execute(
                f"UPDATE collect.egress_integration_route SET "
                f"{', '.join(f'{k} = %s' for k in values)}, updated_by = %s WHERE id = %s",
                [*values.values(), actor_id, route_id])
            self._audit(actor_id, "EGRESS_ROUTE_CHANGED", "egress_route", route_id,
                        {"name": row[1], **values}, via=via)
        return {"id": str(route_id), **values}

    def retire_route(self, *, actor_id: UUID, route_id: UUID, reason: str,
                     via: dict | None = None) -> dict:
        row = self._route(route_id)
        if row[3]:
            raise EgressAdminError("The route is already retired.")
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise EgressAdminError("Say why, in at least five characters.")
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.egress_integration_route
                      SET is_active = false, retired_at = now(), retired_by = %s,
                          retire_reason = %s, updated_by = %s
                    WHERE id = %s""", (actor_id, reason, actor_id, route_id))
            self._audit(actor_id, "EGRESS_ROUTE_RETIRED", "egress_route", route_id,
                        {"name": row[1], "reason": reason}, via=via)
        return {"id": str(route_id), "retired": True}

    def validate_entry(self, text: str) -> Rule:
        production = _production(self._env)
        internal = egress_routes.integration_internal(_internal(self._env), production)
        try:
            rule = parse_rule(text)
        except ValueError as exc:
            raise EgressAdminError(str(exc)) from None
        problems = validate_rule(rule, kind="integration", production=production,
                                 internal=internal)
        if problems:
            raise EgressAdminError(problems[0])
        return rule

    def add_destination(self, *, actor_id: UUID, route_id: UUID, entry: str, note: str,
                        via: dict | None = None) -> dict:
        row = self._route(route_id)
        if row[3]:
            raise EgressAdminError("A retired route takes no destination.")
        rule = self.validate_entry(entry)
        text = format_rule(rule)
        note = (note or "").strip()
        if not 5 <= len(note) <= 500:
            raise EgressAdminError("Note why this destination is allowed, in 5 to 500 "
                                   "characters.")
        with self._c.transaction():
            if self._c.execute(
                    """SELECT EXISTS (SELECT 1 FROM collect.egress_destination
                        WHERE route_id = %s AND entry = %s AND retired_at IS NULL)""",
                    (route_id, text)).fetchone()[0]:
                raise EgressAdminError("The route already allows that destination.")
            did = self._c.execute(
                """INSERT INTO collect.egress_destination (route_id, entry, note, created_by)
                   VALUES (%s, %s, %s, %s) RETURNING id""",
                (route_id, text, note, actor_id)).fetchone()[0]
            self._audit(actor_id, "EGRESS_DESTINATION_ADDED", "egress_destination", did,
                        {"route": row[1], "entry": text, "note": note}, via=via)
        return {"id": str(did), "entry": text}

    def retire_destination(self, *, actor_id: UUID, route_id: UUID, destination_id: UUID,
                           via: dict | None = None) -> dict:
        row = self._route(route_id)
        found = self._c.execute(
            """SELECT entry, retired_at IS NOT NULL FROM collect.egress_destination
                WHERE id = %s AND route_id = %s""", (destination_id, route_id)).fetchone()
        if found is None:
            raise _not_found("destination")
        if found[1]:
            raise EgressAdminError("The destination is already retired.")
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.egress_destination SET retired_at = now(), retired_by = %s
                    WHERE id = %s""", (actor_id, destination_id))
            self._audit(actor_id, "EGRESS_DESTINATION_RETIRED", "egress_destination",
                        destination_id, {"route": row[1], "entry": found[0]}, via=via)
        return {"id": str(destination_id), "retired": True}

    # --- the dry run ------------------------------------------------------------

    def check(self, *, route_kind: str, route_id: UUID, host: str, port: int,
              clearance: str, compartments=frozenset()) -> dict:
        """Would the route allow host:port? egress_policy.check_destination
        on the route's policy: no DNS and no connection. A profile above the
        caller's clearance answers 404, like an unknown id, so this is no
        oracle of what a RED profile targets."""
        production = _production(self._env)
        internal = _internal(self._env)
        if route_kind == "persona":
            profile = self._profile(route_id)
            label, comps = self.profile_label(profile)
            if not self._visible(label, comps, clearance, frozenset(compartments)):
                raise _not_found("egress profile")
            policy = egress_routes.persona_policy(profile, internal=internal)
        elif route_kind == "integration":
            row = self._route(route_id)
            integration = egress_routes.load_integration(self._c, row[1])
            if integration is None or integration.id != row[0]:
                raise EgressAdminError("That route is retired.")
            policy = egress_routes.integration_policy(
                integration, internal=internal, production=production)
        else:
            raise EgressAdminError("A route is persona or integration.")
        # Names only: a literal is matched, never classified here, so the
        # check never looks anything up.
        policy = replace(policy, admission="proxy")
        try:
            rule = check_destination(policy, host, int(port))
        except Refusal as refusal:
            return {"allowed": False, "reason": refusal.code,
                    "sentence": egress_policy.explain(refusal.code), "entry": None}
        return {"allowed": True, "reason": "allowed",
                "sentence": "The route allows this destination by name; the proxy still "
                            "checks every address it resolves to.",
                "entry": format_rule(rule) if rule is not None else None}

    # --- for persona forms (GET /collection/egress-profiles) -------------------------

    def listing_facts(self, rows: list[dict]) -> list[dict]:
        """The egress-profile rows of GET /collection/egress-profiles, with
        exit_kind, persona_capable and ceiling added, never an exit field."""
        ids = [UUID(str(r["id"])) for r in rows if r.get("id")]
        facts = {r[0]: r[1:] for r in self._c.execute(
            """SELECT id, exit_kind, persona_capable, ceiling::text
                 FROM collect.egress_profile WHERE id = ANY(%s)""", (ids,)).fetchall()}
        out = []
        for row in rows:
            extra = facts.get(UUID(str(row.get("id")))) if row.get("id") else None
            out.append({**row, "exit_kind": extra[0] if extra else None,
                        "persona_capable": bool(extra and extra[1]),
                        "ceiling": extra[2] if extra else None})
        return out

    def listing_for_personas(self) -> list[dict]:
        rows = self._c.execute(
            """SELECT p.id, p.name, p.kind, p.region, p.ceiling::text, p.exit_kind,
                      p.persona_capable, p.is_active, p.is_passive_default,
                      p.retired_at IS NOT NULL,
                      (SELECT count(*) FROM collect.collection_account a
                        WHERE a.egress_profile_id = p.id)
                 FROM collect.egress_profile p ORDER BY p.name""").fetchall()
        return [{"id": str(r[0]), "name": r[1], "kind": r[2], "region": r[3],
                 "ceiling": r[4], "exit_kind": r[5], "persona_capable": r[6],
                 "is_active": r[7], "is_passive_default": r[8], "retired": r[9],
                 "persona_count": r[10]} for r in rows]

    def check_persona_binding(self, profile_id: UUID) -> str | None:
        row = self._c.execute(
            """SELECT exit_kind, is_passive_default, is_active AND retired_at IS NULL
                 FROM collect.egress_profile WHERE id = %s""", (profile_id,)).fetchone()
        if row is None:
            return "There is no such egress profile."
        if not row[2]:
            return "This profile cannot carry a persona: it is switched off or retired."
        if row[1]:
            return "This profile cannot carry a persona: it is the passive default."
        if row[0] is None:
            return "This profile cannot carry a persona: it has no sealed exit."
        if row[0] == "DIRECT":
            return ("This profile cannot carry a persona: it leaves from this "
                    "deployment's own address.")
        return None

    # --- adopting an existing deployment ------------------------------------------

    def adopt_proposal(self, *, resolve: bool = True) -> dict:
        """What an upgraded deployment needs to keep its feeds and deliveries
        working through the proxy: a passive default that reads what RSS
        always read (any public host, the ports the feeds use plus 80 and
        443, a ceiling at the highest feed label or AMBER), and smtp and
        webhook routes for the configured relay and hook. A relay whose
        name answers a private address is proposed as NAME@<network>, which
        the operator confirms (2026-09-24).
        Proposes only what does not exist."""
        proposal: dict[str, Any] = {"passive_default": None, "routes": []}
        exists = self._c.execute(
            "SELECT EXISTS (SELECT 1 FROM collect.egress_profile WHERE is_passive_default)"
        ).fetchone()[0]
        if not exists:
            ports = {80, 443}
            highest = "AMBER"
            for base_url, label in self._c.execute(
                    """SELECT base_url, classification::text FROM collect.source
                        WHERE is_active AND parser_key = %s
                          AND kind::text = ANY(%s)""",
                    (egress_routes.PASSIVE_PARSER,
                     sorted(egress_routes.PASSIVE_SOURCE_KINDS))).fetchall():
                try:
                    ports.add(egress_policy.split_url(base_url or "").port)
                except Refusal:
                    pass
                if _tlp_index(label) > _tlp_index(highest):
                    highest = label
            taken = {r[0] for r in self._c.execute(
                "SELECT name FROM collect.egress_profile WHERE name LIKE 'passive%'").fetchall()}
            name = "passive"
            suffix = 2
            while name in taken:
                name, suffix = f"passive-{suffix}", suffix + 1
            proposal["passive_default"] = {
                "name": name, "kind": "DATACENTRE", "exit_kind": "DIRECT",
                "ceiling": highest, "allowed_ports": sorted(ports)[:16],
                "any_public_host": True}
        live = {r[0] for r in self._c.execute(
            "SELECT name FROM collect.egress_integration_route WHERE retired_at IS NULL"
        ).fetchall()}
        smtp_host = self._env.get("SMTP_HOST", "").strip()
        if smtp_host and "smtp" not in live:
            try:
                port = int(self._env.get("SMTP_PORT", "") or 587)
            except ValueError:
                port = 587
            proposal["routes"].append(self._proposed_route(
                "smtp", "Email notifications to the configured relay", smtp_host, port,
                resolve=resolve))
        hook = self._env.get("NOCTORNAL_WEBHOOK_URL", "").strip()
        if hook and "webhook" not in live:
            parts = urlsplit(hook)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if parts.hostname:
                proposal["routes"].append(self._proposed_route(
                    "webhook", "Notifications posted to the configured webhook",
                    parts.hostname, port, resolve=resolve))
        return proposal

    def _proposed_route(self, name: str, description: str, host: str, port: int, *,
                        resolve: bool) -> dict:
        network = _private_network_of(host, port, resolve=resolve)
        try:
            host = egress_policy.normalise_host(host)
        except Refusal:
            pass
        literal = _literal(host)
        if literal is not None:
            entry = f"[{host}]:{port}" if literal.version == 6 else f"{host}:{port}"
            network = None
        elif network is not None:
            entry = f"{host}@{_net_text(network)}:{port}"
        else:
            entry = f"{host}:{port}"
        return {"name": name, "description": description, "entry": entry,
                "network": str(network) if network else None,
                "confirm_network": network is not None}

    def adopt(self, *, actor_id: UUID, proposal: dict, via: dict | None = None) -> dict:
        """Create what an administrator confirmed from adopt_proposal, all
        of it or none of it: one transaction around every step (each step's
        own transaction becomes a savepoint inside it), so a refused entry
        halfway through leaves no passive default without its routes and
        no route without its entry for the operator to find and retire by
        hand (S2, 2026-09-25)."""
        created: list[str] = []
        passive = proposal.get("passive_default")
        with self._c.transaction():
            if passive:
                made = self.create_profile(
                    actor_id=actor_id, name=passive["name"], kind="DATACENTRE",
                    region=None, ceiling=passive["ceiling"],
                    policy={"allowed_ports": passive["allowed_ports"],
                            "any_public_host": passive.get("any_public_host", True)},
                    via=via)
                pid = UUID(made["id"])
                self.seal_exit(actor_id=actor_id, profile_id=pid, exit_kind="DIRECT",
                               endpoint=None, via=via)
                self.set_passive_default(actor_id=actor_id, profile_id=pid, via=via)
                created.append("passive default")
            for route in proposal.get("routes", []):
                made = self.create_route(actor_id=actor_id, name=route["name"],
                                         description=route["description"], via=via)
                self.add_destination(actor_id=actor_id, route_id=UUID(made["id"]),
                                     entry=route["entry"],
                                     note="Adopted from this deployment's configuration.",
                                     via=via)
                created.append(f"{route['name']} route")
            self._audit(actor_id, "EGRESS_ADOPTED", "egress_route", None,
                        {"created": created}, via=via)
        return {"created": created}


def _literal(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _net_text(network) -> str:
    return f"[{network}]" if network.version == 6 else str(network)


def _public_upstream(host: str) -> bool:
    """Whether an upstream is reached across the internet: a public literal,
    or any NAME (a name cannot be judged without a lookup, and a provider's
    name is public in practice). A private literal is a local sidecar."""
    literal = _literal(host)
    if literal is None:
        return True
    return not egress_policy.is_blocked(literal)


def _private_network_of(host: str, port: int, *, resolve: bool):
    """The /24 (or /64) around the first private answer for `host`, for the
    operator to confirm, or None. One lookup of an operator's own relay name,
    made only when adopting."""
    literal = _literal(host)
    answers = []
    if literal is not None:
        answers = [literal]
    elif resolve:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            infos = []
        answers = [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos
                   if i[0] in (socket.AF_INET, socket.AF_INET6)]
    for address in answers:
        if egress_policy.classify(address) is egress_policy.AddressClass.PRIVATE:
            prefix = 24 if address.version == 4 else 64
            return ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    return None

