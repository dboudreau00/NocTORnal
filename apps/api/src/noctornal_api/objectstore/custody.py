"""Who holds the bytes: a store inside the deployment, or one somebody else runs.

Invariant 8 says AMBER_STRICT and RED never leave the boundary, and the exhibits and samples this product stores
are plaintext to whoever runs the store: the application encrypts nothing at the object level, so a vendor and
anyone with its administrative or storage access can read them (docs/22, docs/16 C2). A store somebody else
operates is therefore outside the boundary until the agency decides otherwise in writing, and that decision is
counsel's, not an operator's setting.

So an endpoint is read for what it names, never resolved (a lookup at probe or upload time is fragile and
answers for the moment, not the deployment): a single-label name (a compose service, `minio`), `localhost`, or a
loopback, private (RFC 1918, ULA) or link-local address is INSIDE; anything else is OFF-HOST, which is what a
vendor-operated store looks like from here. An off-host store

- is reported by the readiness row `object_store_custody_declared` until `NOCTORNAL_OBJECT_STORE_CUSTODY` names
  who operates it, the jurisdiction and the legal-process contact, in free text; and
- refuses an AMBER_STRICT or RED exhibit or sample until `NOCTORNAL_OBJECT_STORE_COUNSEL_DECLARATION` records
  counsel's written decision that this store may hold them (a reference to that decision, in free text).

A private DNS name with dots (`s3.internal.example`) reads as off-host. That is the safe direction: the
declaration is one sentence, and the alternative is a vendor's store let in unremarked.
"""
from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass

from noctornal_api.objectstore.settings import chain, endpoint_label, first_set

CUSTODY_ENV = "NOCTORNAL_OBJECT_STORE_CUSTODY"
COUNSEL_ENV = "NOCTORNAL_OBJECT_STORE_COUNSEL_DECLARATION"
#: The labels that never leave the boundary (invariant 8).
RESTRICTED = ("AMBER_STRICT", "RED")


def _hostname(endpoint: str) -> str:
    label = endpoint_label(endpoint)
    if label.startswith("["):
        return label[1:label.index("]")]
    return label.rsplit(":", 1)[0] if label.count(":") == 1 else label


def is_inside(endpoint: str) -> bool:
    """Whether an endpoint names a store inside the deployment, by the name alone (see the module)."""
    host = _hostname(endpoint).strip().lower().rstrip(".")
    if not host:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost" or "." not in host
    return address.is_loopback or address.is_private or address.is_link_local


@dataclass(frozen=True)
class StoreCustody:
    """One role's store as custody sees it. `custody` and `counsel` are the declarations, empty when unset."""
    role: str
    host: str
    inside: bool
    custody: str
    counsel: str

    @property
    def may_hold_restricted(self) -> bool:
        return self.inside or bool(self.counsel)


def custody_of(role: str, env: Mapping[str, str] | None = None) -> StoreCustody:
    env = os.environ if env is None else env
    endpoint = first_set(env, chain(role, "ENDPOINT"))[1]
    return StoreCustody(role=role, host=endpoint_label(endpoint), inside=is_inside(endpoint),
                        custody=env.get(CUSTODY_ENV, "").strip(),
                        counsel=env.get(COUNSEL_ENV, "").strip())


def restricted_refusal(role: str, classification: str,
                       env: Mapping[str, str] | None = None) -> str | None:
    """The sentence refusing an AMBER_STRICT or RED write to an off-host store with no declaration from
    counsel, or None when the write may go ahead. Names the variable to set and never a value."""
    if str(classification).upper() not in RESTRICTED:
        return None
    held = custody_of(role, env)
    if held.may_hold_restricted:
        return None
    return (f"this deployment's {_ROLE_WORDS.get(role, role)} store is operated outside it, "
            f"and AMBER_STRICT and RED material never leaves the boundary "
            f"unless counsel has decided in writing that this store may hold "
            f"it; that decision is recorded in {COUNSEL_ENV}. Nothing "
            f"was stored.")


_ROLE_WORDS = {"evidence": "evidence", "sample": "sample", "preserve": "preservation"}
