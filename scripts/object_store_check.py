"""A read-only preflight for the object store, before an agency points a deployment at it (docs/22).

    python scripts/object_store_check.py            # what the settings resolve to, and each bucket's own account
    python scripts/object_store_check.py --prove    # and the two write-once proofs the readiness register runs

It writes nothing to a bucket by default, and it never creates one (`object_store_provision.py --apply` does).
For every role it prints the profile, the endpoint host, whether TLS is on, the region and the addressing, then
a table of each bucket (exists, versioning, object lock, default retention). The table is ADVISORY: a store can
report a lock it does not enforce (docs/17 F24). `--prove` runs the register's own proofs for the evidence and
preservation buckets (`evidence_bucket_object_lock`, `preservation_bucket_object_lock`); they write only the
one-day canaries the register already writes, and they are what shows write-once. Last it prints the actions
each account needs (the three policies in docs/22).

Exit 1 when a bucket is red or a proof fails. A key or a secret is never printed, only the names of the
variables that supplied them.
"""
from __future__ import annotations

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from object_store_provision import _judge  # noqa: E402
from noctornal_api.objectstore import errors  # noqa: E402
from noctornal_api.objectstore.pools import bounded_http  # noqa: E402
from noctornal_api.objectstore.settings import (  # noqa: E402
    LOCKED_ROLES,
    ROLES,
    StoreConfigError,
    resolve,
)
from noctornal_api.objectstore.store import open_store  # noqa: E402

#: The actions each account needs on its buckets, as docs/22 section 4 lists them. A test holds the page's
#: three policies to these sets.
IAM_ACTIONS = {
    "api (evidence, raw and collected-markup buckets)": (
        "s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObject", "s3:DeleteObjectVersion",
        "s3:PutObjectRetention", "s3:GetObjectRetention", "s3:GetObjectLegalHold", "s3:ListBucket",
        "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetBucketVersioning",
        "s3:GetBucketObjectLockConfiguration"),
    "samples": ("s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation"),
    "preservation": (
        "s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectLegalHold",
        "s3:PutObjectLegalHold (only with s3:object-lock-legal-hold ON)", "s3:ListBucket",
        "s3:GetBucketLocation", "s3:GetBucketObjectLockConfiguration"),
}


def _prove_with_register():
    """`[(name, ok, evidence)]` from the register's own two checks. Module level so a test can hand a stand-in.
    The register reads the process environment, as the API does."""
    from noctornal_api import readiness
    rows = [("evidence_bucket_object_lock", readiness._evidence_lock_check(None))]
    disposition, _raw = readiness.rejected_sample_disposition()
    rows.append(("preservation_bucket_object_lock",
                 None if disposition == "destroy" else readiness._preservation_lock_check(None)))
    return rows


def run(argv=None, env=None, *, out=sys.stdout, store_for=None, prove_with=None) -> int:
    """The script's work; `store_for(settings)` builds the store and `prove_with()` runs the proofs (a test
    hands stand-ins)."""
    parser = argparse.ArgumentParser(prog="object_store_check.py")
    parser.add_argument("--prove", action="store_true",
                        help="also run the register's two write-once proofs (writes one-day canaries)")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    store_for = store_for or (lambda s: open_store(s, http=bounded_http(resend_writes=False)))
    prove_with = prove_with or _prove_with_register

    red = 0
    rows = []
    print("settings", file=out)
    for role in ROLES:
        try:
            s = resolve(role, env)
        except StoreConfigError as exc:
            print(f"refused: {exc}.", file=out)
            return 1
        if not s.configured:
            print(f"  {role:11}  red   {s.sources['endpoint']} and its credentials are not set", file=out)
            red += 1
            continue
        print(f"  {role:11}  profile {s.profile}, host {s.host}, secure {str(s.secure).lower()}, "
              f"region {s.region or 'asked of the store'}, addressing {s.addressing}, bucket {s.bucket}",
              file=out)
        rows.append((role, s))

    print("buckets", file=out)
    for role, s in rows:
        locked = role in LOCKED_ROLES
        try:
            caps = store_for(s).bucket_capabilities(s.bucket)
        except errors.StoreError as exc:
            print(f"  red   {role:11}  {s.bucket:28}  the store did not answer as S3 "
                  f"({type(exc).__name__}: {getattr(exc, 'code', None) or exc})", file=out)
            red += 1
            continue
        verdict, detail = _judge(role, caps, locked)
        red += verdict == "red"
        retention = caps.default_retention
        default = (f"{retention.mode} {retention.days or retention.years} "
                   f"{'days' if retention.days else 'years'}" if retention and retention.mode else "none")
        print(f"  {verdict:4}  {role:11}  {s.bucket:28}  exists {caps.exists}, versioning {caps.versioning}, "
              f"object lock {caps.object_lock}, default retention {default}; {detail}", file=out)
    print("advisory: a bucket's account of itself is not a proof; the readiness register proves write-once.",
          file=out)

    if args.prove:
        print("proofs", file=out)
        for name, check in prove_with():
            if check is None:
                print(f"  skip  {name}: NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy, so the register does "
                      f"not probe it without a database", file=out)
                continue
            print(f"  {'ok' if check.ok else 'red':4}  {name}: {check.evidence}", file=out)
            red += not check.ok
    else:
        print("proofs not run: add --prove to run evidence_bucket_object_lock and "
              "preservation_bucket_object_lock (one-day canaries are written).", file=out)

    print("actions each account needs (docs/22 section 4)", file=out)
    for account, actions in IAM_ACTIONS.items():
        print(f"  {account}: {', '.join(actions)}", file=out)
    print("never grant s3:BypassGovernanceRetention.", file=out)
    return 1 if red else 0


if __name__ == "__main__":
    load_env_local()
    sys.exit(run())
