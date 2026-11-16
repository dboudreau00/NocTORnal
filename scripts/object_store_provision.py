"""Create and check the five buckets through the S3 API, on any store: the bundled MinIO's `minio-init` without mc.

    python scripts/object_store_provision.py            # --check, read only: exit 1 on anything red
    python scripts/object_store_provision.py --apply    # create what is missing, then check

The buckets and how each must be made (docs/22):

| role          | variable             | default                 | object lock |
|---------------|----------------------|-------------------------|-------------|
| `evidence`    | `EVIDENCE_BUCKET`    | `noctornal-evidence`    | required, and a COMPLIANCE default retention |
| `ingest`      | `INGEST_BUCKET`      | `noctornal-raw`         | never       |
| `collect_raw` | `COLLECT_RAW_BUCKET` | `noctornal-collect-raw` | never       |
| `sample`      | `SAMPLE_BUCKET`      | `noctornal-samples`     | never       |
| `preserve`    | `PRESERVE_BUCKET`    | `noctornal-preserved`   | required, no default retention |

`--check` asks each bucket's own account of itself (`bucket_capabilities`): that it exists, and that its lock is
on where it must be and off where it must not. That account is ADVISORY: a store can report a lock it does not
enforce (docs/17 F24), and the readiness register's rows `evidence_bucket_object_lock` and
`preservation_bucket_object_lock` are what prove write-once. A lock the store will not report is red for the two
locked buckets and noted for the others.

`--apply` creates a missing bucket with or without a lock as the table says and sets the evidence bucket's
COMPLIANCE default retention (`--evidence-default-days`, 365, equal to EVIDENCE_RETENTION_DAYS' default as
`minio-init` sets it by hand). It never alters an existing bucket's lock: object lock cannot be switched on
afterwards on most stores, so a bucket made wrongly has to be made again, by a person. It creates no account and
no policy; those are the store's own (docs/22 has the three policies).

Each bucket is reached at its role's endpoint (`objectstore.settings`). The credential is
OBJECT_STORE_ADMIN_ACCESS_KEY / OBJECT_STORE_ADMIN_SECRET_KEY when both are set, else the role's own; in
production `--apply` refuses without the admin pair, so the API's runtime credential is never the one that makes
buckets. Nothing printed names a key or a secret.
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api.config import is_production  # noqa: E402
from noctornal_api.objectstore import errors  # noqa: E402
from noctornal_api.objectstore.pools import bounded_http  # noqa: E402
from noctornal_api.objectstore.settings import (  # noqa: E402
    LOCKED_ROLES,
    ROLES,
    StoreConfigError,
    resolve,
)
from noctornal_api.objectstore.store import open_store  # noqa: E402

ADMIN_ACCESS = "OBJECT_STORE_ADMIN_ACCESS_KEY"
ADMIN_SECRET = "OBJECT_STORE_ADMIN_SECRET_KEY"


def _settings(role: str, env) -> object:
    s = resolve(role, env)
    access, secret = env.get(ADMIN_ACCESS, "").strip(), env.get(ADMIN_SECRET, "").strip()
    if access and secret:
        s = replace(s, access_key=access, secret_key=secret)
    return s


def _row(role: str, bucket: str, verdict: str, detail: str) -> str:
    return f"{verdict:4}  {role:11}  {bucket:28}  {detail}"


def run(argv=None, env=None, *, out=sys.stdout, store_for=None) -> int:
    """The script's work; `store_for(settings)` builds the store (a test hands a stand-in)."""
    parser = argparse.ArgumentParser(prog="object_store_provision.py")
    parser.add_argument("--apply", action="store_true",
                        help="create missing buckets, then check (default: check only)")
    parser.add_argument("--evidence-default-days", type=int, default=365)
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    store_for = store_for or (lambda s: open_store(s, http=bounded_http(resend_writes=False)))

    if args.apply and is_production(env) and not (
            env.get(ADMIN_ACCESS, "").strip() and env.get(ADMIN_SECRET, "").strip()):
        print(f"refused: --apply in production needs {ADMIN_ACCESS} and {ADMIN_SECRET}, so the "
              f"API's runtime credential is not the one that makes buckets (docs/22).", file=out)
        return 1
    red = 0
    for role in ROLES:
        try:
            s = _settings(role, env)
        except StoreConfigError as exc:
            print(f"refused: {exc}.", file=out)
            return 1
        if not s.configured:
            print(_row(role, s.bucket, "red", f"{s.sources['endpoint']} and its credentials are not set"),
                  file=out)
            red += 1
            continue
        store = store_for(s)
        locked = role in LOCKED_ROLES
        where = f"store: {s.profile} at {s.host}"
        try:
            caps = store.bucket_capabilities(s.bucket)
            if args.apply and caps.exists is False:
                store.make_bucket(s.bucket, object_lock=locked)
                did = "created with object lock" if locked else "created without object lock"
                if role == "evidence":
                    store.set_default_retention(s.bucket, days=args.evidence_default_days)
                    did += f" and a COMPLIANCE default of {args.evidence_default_days} days"
                print(_row(role, s.bucket, "made", f"{did}; {where}"), file=out)
                caps = store.bucket_capabilities(s.bucket)
        except errors.StoreError as exc:
            print(_row(role, s.bucket, "red", f"the store did not answer as S3 ({type(exc).__name__}: "
                                              f"{getattr(exc, 'code', None) or exc}); {where}"), file=out)
            red += 1
            continue
        verdict, detail = _judge(role, caps, locked)
        red += verdict == "red"
        print(_row(role, s.bucket, verdict, f"{detail}; {where}"), file=out)
    print("advisory: a bucket's account of itself is not a proof; the readiness register proves "
          "write-once (evidence_bucket_object_lock, preservation_bucket_object_lock).", file=out)
    return 1 if red else 0


def _judge(role: str, caps, locked: bool) -> tuple[str, str]:
    if caps.exists is False:
        return "red", "does not exist (run with --apply, or create it as docs/22 says)"
    if caps.exists is None:
        return "red", "the store would not say whether it exists"
    if locked:
        if caps.object_lock is True:
            default = caps.default_retention
            text = "object lock on"
            if role == "evidence":
                text += (f", default {default.mode} {default.days or default.years} "
                         f"{'days' if default.days else 'years'}" if default and default.mode
                         else ", no default retention (every exhibit still carries its own)")
            return "ok", text
        if caps.object_lock is False:
            return "red", ("has NO object lock, which cannot be switched on afterwards: make the bucket "
                           "again with object lock and versioning on")
        return "red", "the store would not say whether object lock is on; the register will prove it"
    if caps.object_lock is True:
        return "red", ("has object lock, and this bucket must be destroyable (docs/11, decisions 50 and "
                       "74): make it again without")
    return "ok", "no object lock" if caps.object_lock is False else "object lock not reported"


if __name__ == "__main__":
    load_env_local()
    sys.exit(run())
