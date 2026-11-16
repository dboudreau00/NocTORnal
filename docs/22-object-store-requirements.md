# 22. The object store: what a store must do, and running on one other than MinIO

**For an operator or an agency that keeps evidence on an S3 store of its own.** The bundled MinIO stays the
default and nothing changes for a deployment that keeps it. This page says what any store must do for the
product to keep exhibits on it, how to point a deployment at one, how to prove it, and the custody questions a
store somebody else operates raises. Nothing here promises that a named product qualifies: a store qualifies by
passing the conformance suite and the readiness register, measured, and the table below says exactly what has
been measured.

The code is one seam (`apps/api/src/noctornal_api/objectstore/`, decision 235): one settings reader, one adapter
over the client library, one rule per profile for reading a refused delete. Every bucket the product writes goes
through it.

---

## What has been measured (2026-11-15)

Both runs used the conformance suite (section 5) with a 20-second lock, its own scratch buckets, and the
register's two write-once rows run against the store with the product's own code.

| Store | Profile | Required checks | Register rows | A locked version's delete is refused with | Keyless delete of an absent key |
|---|---|---|---|---|---|
| MinIO `RELEASE.2025-04-22T22-12-26Z` (the pinned build, the development stack) | `minio` | 23 of 23 passed; the one optional check skipped (no read-only credential given) | both PROVEN on `minio`; both red on `s3`, failing closed because the permission control cannot run | `InvalidRequest` "Object is WORM protected and cannot be overwritten" (400) | adds **no** delete marker |
| Zenko CloudServer 8.8.32 (`ghcr.io/scality/cloudserver@sha256:e958e5547d69120ee4c1064de4bc6e009597766e0674af897cf22c04f4a1c93d`, `S3BACKEND=mem`) | `s3` | 23 of 23 passed; the optional check skipped | both PROVEN on `s3`; both red on `minio` ("a permissions refusal says nothing about write-once") | `AccessDenied` "Access Denied" (403), AWS's own shape | adds a marker, removable by its version id |

On both stores the probe pointed at a bucket made without object lock went red, quoting the store's refusal of
the locked write. CloudServer was run on its in-memory backend in a throwaway container: that measures the S3
semantics of its code, it is not a recommendation of a production store, and CloudServer's own documentation
does not describe Object Lock. Ceph RGW, AWS S3 and the rest of the list in section 8 have not been run.

What each store answered for every refusal class is written by the suite to `store-measurements.json`; keep it
with the run.

---

## 1. What a store must do

Each line is a check in `apps/api/store_conformance/checks.py`, named after what it holds.

* **S3 with SigV4 over TLS the API trusts.** The application's processes trust the system roots plus
  `./tls/public.crt` (the compose commands build `SSL_CERT_FILE` from both), so a private CA goes there.
* **Versioning, and object lock enabled when the bucket is made**, for the evidence and preservation buckets.
  Object lock cannot be switched on afterwards on most stores; a bucket made without it is made again.
* **A COMPLIANCE retention that a delete naming the version cannot defeat**
  (`a_version_delete_of_a_locked_version_is_refused_and_the_version_survives`), from the API's credential.
  Ask the vendor whether its own administrators or support can: the register proves it from the API's
  credential, which is not the vendor's.
* **Retention read back as COMPLIANCE, to the second** (`the_retention_reads_back_as_compliance_at_the_requested_instant`);
  a store that records GOVERNANCE for a COMPLIANCE request fails, because GOVERNANCE yields to
  `s3:BypassGovernanceRetention`.
* **A retention that can be lengthened and never shortened** (`extend_lock_lengthens_every_version_and_reads_back`,
  `a_compliance_retention_cannot_be_shortened`, `an_unlocked_version_in_a_locked_bucket_is_raised_to_compliance`).
* **A legal hold set in the PUT, read back ON, refusing a delete, with no retention** (`a_legal_hold_set_in_the_put_reads_back_on`,
  `a_held_version_cannot_be_deleted_and_survives`, `a_hold_only_object_has_no_retention`).
* **ListObjectVersions, HEAD and GET by version id, and delete markers** (`list_versions_returns_every_version_and_flags_markers`,
  `a_keyless_delete_only_adds_a_marker_and_the_locked_bytes_remain`).
* **A multipart upload that carries its retention** (`a_multipart_put_carries_its_retention_and_returns_one_version`,
  11 MiB, over the client's 5 MiB part size; exhibits up to the size cap take this path).
* **Normal S3 errors** for a missing key, version and bucket (`missing_bucket_key_and_version_are_normalised`).
* **No lifecycle rule on the evidence or preservation bucket** that expires versions, and no account-level
  "delete after N days" policy. Either is a destruction path nothing records. The suite cannot see one; the
  operator confirms it.
* **Working buckets that really delete.** The raw ingest, collected markup and samples buckets are made
  **without** object lock, because a retention clock or a deletion order must be able to remove what is in them
  (docs/11, decisions 50 and 74). On a versioned working bucket the product removes every version, so that
  account also needs `s3:ListBucketVersions` and `s3:DeleteObjectVersion` there.

---

## 2. The two profiles

`NOCTORNAL_OBJECT_STORE` chooses how a refused delete is read. It never chooses a different client.

* **`minio`, the default.** A refusal is a lock when its code says so (`RetentionPeriodNotMet`,
  `MethodNotAllowed`) or its message names worm, retention or object lock. That is how the bundled MinIO was
  measured, and nothing about it changed.
* **`s3`, for any other store.** AWS answers a delete of a locked version with `AccessDenied` "Access Denied",
  the same answer as a policy denial, and CloudServer and Ceph RGW answer `AccessDenied` too. So this profile
  never reads a message: a refusal whose code could be a lock is resolved by reading the version's retention and
  legal hold back, and it is a lock only when one is really there. A purge on such a store records
  `LOCKED_UNTIL_RETENTION` and keeps the row due; a refusal with no lock behind it stays a failure.

State alone cannot tell a lock from a policy that denies delete on a locked object, so on the `s3` profile the
register runs a **permission control** before it credits a refused delete: a delete naming no version of
`.noctornal-delete-control`, a key nothing holds, which on a versioned bucket adds a delete marker, and then the
removal of that marker by its version id. Both succeeding shows this credential may delete versions in the
bucket. A credential that may not is a denied proof (the preservation account's shape, so that check moves to
the evidence credential on the same store, as before). A store that adds no marker for an absent key, the
bundled MinIO among them, cannot run the control and fails closed on this profile: run it on `minio`. A
credential that may delete objects but not versions leaves one marker on that key per probe.

---

## 3. Pointing a deployment at a store

In `secrets.env` (commented and unset in `secrets.env.example`):

```
NOCTORNAL_OBJECT_STORE=s3
OBJECT_STORE_ENDPOINT=objects.store.example:443     # host:port, no scheme
OBJECT_STORE_ACCESS_KEY=...                          # the API's account: evidence, raw, collected markup
OBJECT_STORE_SECRET_KEY=...
OBJECT_STORE_SECURE=true                             # strict: exactly "true"
OBJECT_STORE_REGION=eu-west-2                        # saves the client asking where a bucket is
OBJECT_STORE_ADDRESSING=auto                         # auto, path or virtual
SAMPLE_ACCESS_KEY=... / SAMPLE_SECRET_KEY=...        # the samples bucket's own account
PRESERVE_ACCESS_KEY=... / PRESERVE_SECRET_KEY=...    # the preservation bucket's own account
```

The `MINIO_*` names stay accepted, for every deployment, installer and test that sets them; each
`OBJECT_STORE_*` name is the same setting under a neutral name and wins when both are set. Production refuses
to start when a neutral name and its alias are set to different values (two stores named, one used), and when
`NOCTORNAL_OBJECT_STORE` is neither `minio` nor `s3`. `SAMPLE_*` and `PRESERVE_*` fall back as they always did:
`SAMPLE_*`, then `OBJECT_STORE_*`, then `MINIO_*`, and `PRESERVE_*` before all of them; `SAMPLE_SECURE` and
`PRESERVE_SECURE` never fall back to the evidence store's. For a virtual-hosted-only vendor set
`OBJECT_STORE_ADDRESSING=virtual` and use a wildcard certificate; neither is testable here, so check what
`scripts/object_store_check.py` prints.

**Replace the bundled store's lines.** `infra/production/secrets.env.example` sets `MINIO_ENDPOINT=minio:9000`, `MINIO_SECURE`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `SAMPLE_ENDPOINT` and `SAMPLE_SECURE` for the bundled MinIO. Delete them, or change each to the new store, when you set the `OBJECT_STORE_*` names. Left as they are, `MINIO_ENDPOINT` makes production refuse to start (it differs from `OBJECT_STORE_ENDPOINT`), and `SAMPLE_ENDPOINT` is read before `OBJECT_STORE_ENDPOINT` for the samples bucket, so that bucket would point at a service that is no longer there and `object-store-init` would report the `sample` row red.

**The buckets.** Make them with an administrator's credential, never the API's. From a development checkout:

```
OBJECT_STORE_ADMIN_ACCESS_KEY=... OBJECT_STORE_ADMIN_SECRET_KEY=... \
  python scripts/object_store_provision.py --apply
```

On the production stack the pair goes in `infra/production/object-store-admin.env` (mode 0600, read by
`object-store-init` alone, ignored by git and the image build) and the same script runs in that service;
`infra/production/README.md`, Your own object store, has the command.

| Bucket (variable, default) | Object lock |
|---|---|
| `EVIDENCE_BUCKET`, `noctornal-evidence` | on, with a COMPLIANCE default of 365 days |
| `PRESERVE_BUCKET`, `noctornal-preserved` | on, no default retention (a sample stays held only while its hold is on) |
| `INGEST_BUCKET`, `noctornal-raw` | off |
| `COLLECT_RAW_BUCKET`, `noctornal-collect-raw` | off |
| `SAMPLE_BUCKET`, `noctornal-samples` | off |

The script never changes an existing bucket's lock and creates no account or policy. Without `--apply` it
checks, read only, and exits 1 on anything red; its table is the bucket's own account of itself and is advisory.

**The production stack.** `infra/production/compose.external-store.yml` is an override that takes `minio` and
`minio-init` out of the stack and puts `object-store-init` (the check above, as a one-shot) in minio-init's
place, so the API stays down while a bucket is missing or wrongly locked:

```
sudo docker compose -p noctornal-prod -f infra/production/compose.yml \
  -f infra/production/compose.external-store.yml up -d
```

Name both files on every command. It needs Compose 2.24 or later (`!reset`); `docker compose config` on Compose
2.40 renders api and sample-origin with every dependency but minio-init, and object-store-init in its place.

**The route.** The application network is internal. A store is reachable from the stack only when it is
attached to that network (a Ceph RGW container in this compose project, say); a store on another host has no
route, and giving it one is the later step docs/17 F41 records.

**Backups.** The `mc mirror` commands in `infra/production/README.md` are the bundled MinIO's. On another store
use its replication. On any store a mirror keeps bytes and not version ids, so objects restored from one are put
back with `scripts/restore_object_versions.py`, which records the version the store gave each (decision 240, the
restore runbook in `infra/production/README.md`, docs/08).

---

## 4. The three accounts' policies

Never grant `s3:BypassGovernanceRetention`. `BUCKET` is the bucket's name.

The API's account, on the evidence, raw and collected-markup buckets:

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion",
    "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:GetObjectRetention",
    "s3:GetObjectLegalHold"], "Resource": ["arn:aws:s3:::BUCKET/*"]},
  {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation",
    "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration"], "Resource": ["arn:aws:s3:::BUCKET"]}]}
```

The samples account (the policy `minio-init` mints), plus `s3:ListBucketVersions` and `s3:DeleteObjectVersion`
if the samples bucket is versioned:

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::BUCKET/*"]},
  {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::BUCKET"]}]}
```

The preservation account (the policy `minio-init` mints): it writes, reads and sets a hold, sets a hold only ON
so it cannot lift one, and deletes nothing:

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectLegalHold"],
    "Resource": ["arn:aws:s3:::BUCKET/*"]},
  {"Effect": "Allow", "Action": ["s3:PutObjectLegalHold"], "Resource": ["arn:aws:s3:::BUCKET/*"],
    "Condition": {"StringEquals": {"s3:object-lock-legal-hold": ["ON"]}}},
  {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketObjectLockConfiguration"],
    "Resource": ["arn:aws:s3:::BUCKET"]}]}
```

**The preservation bucket's proof needs a second account.** The preservation account deletes nothing, by
design, so its own refusal of a delete says nothing about the lock (it is `AccessDenied` whatever the store
does). `preservation_bucket_object_lock` therefore makes its delete with the API's account when that account is
a different one on the same endpoint. For that proof to pass, the API's account (or another credential on the
same endpoint) needs on the preservation bucket `s3:PutObject`, `s3:GetObject`, `s3:GetObjectVersion`,
`s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutObjectRetention`, `s3:GetObjectRetention`, `s3:ListBucket` and
`s3:ListBucketVersions`: the first policy above, applied to that bucket as well. Without such a credential the
row stays red with "no other credential this process holds addresses that store", and the lock has to be proven
out of band and recorded (docs/16 C2). A locked or held version stays undeletable to that account too; the
grant is what lets the proof see the store refuse.

---

## 5. Proving it

1. `python scripts/object_store_provision.py`: every bucket there, locked where it must be and not where it
   must not.

   Then `python scripts/object_store_check.py`, read only: it prints the profile, host, TLS flag, region and
   addressing each role resolved to (never a key), each bucket's own account of itself, and the actions each
   account needs. With `--prove` it also runs the register's two proofs, `evidence_bucket_object_lock` and
   `preservation_bucket_object_lock`, which write only the one-day canaries the register writes anyway. It exits
   1 on a red bucket or a failed proof.
2. The conformance suite, on a scratch store or in scratch buckets, never the evidence store itself:

   ```
   OBJECT_STORE_CONFORMANCE_ENDPOINT=host:port OBJECT_STORE_CONFORMANCE_ACCESS_KEY=... \
   OBJECT_STORE_CONFORMANCE_SECRET_KEY=... OBJECT_STORE_CONFORMANCE_PROFILE=s3 \
   OBJECT_STORE_CONFORMANCE_STORE=<name> OBJECT_STORE_CONFORMANCE_LOCK_SECONDS=60 \
   pytest apps/api/store_conformance -q -rs
   ```

   It lives outside `apps/api/tests`, so the CI gate that fails on any skip never sees it, and with no
   endpoint it fails saying nothing was run. It makes two buckets of its own and refuses the endpoint the
   deployment names unless `OBJECT_STORE_CONFORMANCE_ON_LIVE_STORE=1`. Every COMPLIANCE object it writes is
   undeletable for `LOCK_SECONDS`, and the register's canary for a day, so the locked scratch bucket is left
   behind and named in `store-measurements.json`; on a vendor store that may carry a minimum-retention charge,
   and a vendor that refuses short locks needs `LOCK_SECONDS` at its minimum. A known bug is declared in
   `apps/api/store_conformance/known_gaps/<name>.txt`, one check per line with its upstream link, and runs as a
   strict xfail, so a fix turns the run red until the line goes. A store that fails a required lock check is a
   finding for docs/17, never a reason to weaken the check. `tests/test_store_conformance_selftest.py` runs
   the same checks against an in-process store and against stores broken on purpose, so the suite cannot pass
   everything unnoticed.
3. The register: `evidence_bucket_object_lock` and `preservation_bucket_object_lock` must both say
   "write-once PROVEN", naming the profile and the store (`store: s3 at host:port`). "these credentials may not
   delete a version" means the account cannot make the proof; "left no delete marker" means the store cannot
   run the `s3` profile's control; "SUCCEEDED" means the store accepts a lock and does not enforce it, and must
   be replaced.

---

## 6. Custody: a store somebody else operates

The application encrypts nothing at the object level: exhibits and samples are plaintext to whoever runs the
store, and to anyone with its administrative or storage access. A store outside the deployment is therefore a
custody decision before it is a setting (docs/16 C2), and AMBER_STRICT and RED never leave the boundary
(invariant 8).

The endpoint is read for what it names, never resolved: a single-label name (a compose service), `localhost`,
or a loopback, private or link-local address is inside; anything else is outside. Then:

* the readiness row `object_store_custody_declared` is red until `NOCTORNAL_OBJECT_STORE_CUSTODY` names who
  operates the store, the jurisdiction and the legal-process contact; and
* an AMBER_STRICT or RED exhibit or sample is refused, with nothing stored, until
  `NOCTORNAL_OBJECT_STORE_COUNSEL_DECLARATION` records counsel's written decision that this store may hold
  them. That decision is counsel's, not the operator's; the setting records it and cannot verify it. A sample
  is refused when either the samples store or the preservation store is outside, because a rejected sample
  moves to the second.

A private name with dots (`s3.internal.example`) reads as outside: the declaration is one line, and the other
direction lets a vendor's store in unremarked. Each new exhibit's lodging custody row records the store's
profile and host (`store_profile`, `store_host`), so a disclosure can say which store held it; rows already
written are not touched.

Questions to answer in writing before the declaration: who can reach the bytes (the vendor, its support, its
break-glass and account recovery); which jurisdiction and which legal process can compel or alter them, and
whether the vendor tells the agency; whether anything the vendor does can shorten, release or delete a
COMPLIANCE-locked object (the register cannot see that); what happens to locked objects on suspension,
non-payment or contract end; who holds the keys if the store encrypts at rest; whether the vendor's access logs
are available to the Security Officer; where the bytes and their replicas sit; how the agency leaves, given
that a cross-vendor copy assigns new version ids and the custody rows name the old ones; the egress route and
its cost; the time source; and whether the courts the agency appears in accept the register's refused delete as
evidence of write-once for this store. On a self-hosted store the same holds for whoever holds the volume:
they can delete under the lock.

---

## 7. Time

The API's clock computes when a lock ends and the store's clock enforces it. Both must be disciplined (NTP);
skew between them lengthens or shortens a lock by its size.

## 8. Stores to test

Each of these may be tested; none is promised: Ceph RGW (including Rook-Ceph on Kubernetes, where a store is an
endpoint, a Secret and a CA bundle), NetApp StorageGRID, Dell ECS, Wasabi, Backblaze B2, AWS S3, and a
community MinIO fork. Garage implements no object lock; SeaweedFS has let a locked version be deleted (docs/17
F24) and stays out until the suite passes on it.

## 9. Not done here

The production compose still bundles MinIO and makes its accounts with `mc`, the documented backups are `mc
mirror`, the conformance suite has no CI leg, an off-host store has no route (F41), and the client library is
minio-py (pinned in `constraints.txt`; a bump, or a swap to boto3, is one file and is permitted only by a
conformance run on every supported store). Those are the later steps, recorded in docs/17.
