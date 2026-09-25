"""Shared fixtures for the static-triage and YARA suites (F11, F12,
2026-09-24). Not a test module: the suites import it by name.

Nothing here is malware. The PE images are built byte by byte from the
format's own structures, carry one import and a Rich header the builder
chose, and do nothing if run: enough for pefile to parse and hash, which
is all static triage asks of them. No binary is checked in.
"""
from __future__ import annotations

import hashlib
import os
import struct
from datetime import date
from uuid import uuid4

# ---------------------------------------------------------------------------
# Synthetic PE images
# ---------------------------------------------------------------------------

_DANS = 0x536E6144


def rich_header(key: int, entries: list[tuple[int, int]]) -> bytes:
    """A Rich header: 'DanS' and three zero dwords, then (compid, count)
    pairs, all XORed with `key`, then 'Rich' and the key."""
    clear = [_DANS, 0, 0, 0]
    for compid, count in entries:
        clear += [compid, count]
    body = b"".join(struct.pack("<I", v ^ key) for v in clear)
    return body + b"Rich" + struct.pack("<I", key)


def pe_image(*, dll: bytes = b"KERNEL32.dll", function: bytes = b"ExitProcess",
             rich: bool = True, is_dll: bool = False, pad_to: int = 0) -> bytes:
    """A 32-bit PE with one section holding one import, and (optionally)
    a Rich header between the DOS stub and the PE header."""
    e_lfanew = 0xC0
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    stub = bytearray(dos)
    if rich:
        stub += rich_header(0x1234ABCD, [(0x00FF0000 | 30319, 7),
                                         (0x01040000 | 30729, 2)])
    stub += b"\x00" * (e_lfanew - len(stub))
    sect_rva, sect_raw, sect_size = 0x1000, 0x200, 0x200
    # The import section: descriptor, null descriptor, INT, IAT, name, hint.
    idata = bytearray(sect_size)
    int_rva = sect_rva + 0x40
    iat_rva = sect_rva + 0x50
    name_rva = sect_rva + 0x60
    hint_rva = sect_rva + 0x80
    struct.pack_into("<IIIII", idata, 0, int_rva, 0, 0, name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x40, hint_rva, 0)
    struct.pack_into("<II", idata, 0x50, hint_rva, 0)
    idata[0x60:0x60 + len(dll) + 1] = dll + b"\x00"
    idata[0x80:0x82] = b"\x00\x00"
    idata[0x82:0x82 + len(function) + 1] = function + b"\x00"
    file_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0,
                              0x2102 if is_dll else 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, sect_rva)          # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)          # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)            # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)             # FileAlignment
    struct.pack_into("<H", opt, 40, 4)                 # MajorOSVersion
    struct.pack_into("<H", opt, 48, 4)                 # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x2000)            # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)             # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)                 # Subsystem
    struct.pack_into("<I", opt, 92, 16)                # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 96 + 8, sect_rva, 40)  # the import directory
    section = struct.pack("<8sIIIIIIHHI", b".idata\x00\x00", sect_size,
                          sect_rva, sect_size, sect_raw, 0, 0, 0, 0,
                          0xC0000040)
    header = bytes(stub) + b"PE\x00\x00" + file_header + bytes(opt) + section
    image = header + b"\x00" * (sect_raw - len(header)) + bytes(idata)
    if pad_to > len(image):
        image += b"\x00" * (pad_to - len(image))
    return image


def imphash_of(dll: str, function: str) -> str:
    """What pefile's imphash is for one import: md5 of 'dll.function',
    lower case, the DLL's extension dropped."""
    lib = dll.lower().rsplit(".", 1)[0]
    return hashlib.md5(f"{lib}.{function.lower()}".encode()).hexdigest()


def rich_hash() -> str:
    """md5 of the clear Rich header data the builder writes."""
    clear = [_DANS, 0, 0, 0, 0x00FF0000 | 30319, 7, 0x01040000 | 30729, 2]
    key = 0x1234ABCD
    raw = b"".join(struct.pack("<I", v ^ key) for v in clear)
    keyb = struct.pack("<I", key)
    return hashlib.md5(bytes(b ^ keyb[i % 4] for i, b in enumerate(raw))).hexdigest()


def varied(seed: int, size: int) -> bytes:
    """Bytes with enough variety for ssdeep and TLSH, reproducibly."""
    import random
    return random.Random(seed).randbytes(size)


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

class MemoryStore:
    """Stands in for the sample bucket."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = bytes(data)

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


def remove_case_samples(c, case_id) -> None:
    """Remove one case's Lab samples and what hangs off them, as the test
    superuser, for a suite that keeps its case but not its samples."""
    ssub = "(SELECT id FROM lab.sample WHERE case_id = %(case)s)"
    p = {"case": case_id}
    with c.transaction():
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}", p)
        for table in ("sample_access", "detonation"):
            c.execute(f"ALTER TABLE lab.{table} DISABLE TRIGGER USER")
            c.execute(f"DELETE FROM lab.{table} WHERE sample_id IN {ssub}", p)
            c.execute(f"ALTER TABLE lab.{table} ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE sample_id IN {ssub}", p)
        c.execute(f"DELETE FROM lab.static_run WHERE sample_id IN {ssub}", p)
        c.execute("DELETE FROM lab.sample WHERE case_id = %(case)s", p)


def teardown(c, prefix: str) -> None:
    """Remove everything a suite with `prefix` made, as the test
    superuser, leaving no SYSTEM or SCANNED custody, no started run, no
    machine row and no rule set behind: 0078, 0079 and 0080 refuse their
    downgrades on those, and the 0058 round trip must not meet one."""
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{prefix}%@noctornal.test')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    rsub = ("(SELECT id FROM lab.yara_ruleset WHERE created_by IN "
            f"{sub} OR key LIKE '{prefix.rstrip('-')}%')")
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        # 0103 guards lab.detonation against DELETE.
        c.execute("ALTER TABLE lab.detonation DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.detonation WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.detonation ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE yara_ruleset_version_id "
                  f"IN (SELECT id FROM lab.yara_ruleset_version WHERE ruleset_id "
                  f"IN {rsub})")
        c.execute(f"DELETE FROM lab.static_run WHERE sample_id IN {ssub} "
                  f"OR requested_by IN {sub}")
        # Reads this suite's people caused on samples that are not its own
        # (a retrohunt in their view): custody is otherwise never deleted,
        # and only a test's own rows are.
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE actor_id IN {sub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE analyst_id IN {sub}")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        for table in ("yara_compiled_rejected", "yara_compiled",
                      "yara_compile_job", "yara_activation",
                      "yara_ruleset_version", "yara_ruleset"):
            c.execute(f"ALTER TABLE lab.{table} DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.yara_compiled_rejected WHERE compiled_id IN "
                  f"(SELECT c.id FROM lab.yara_compiled c JOIN "
                  f"lab.yara_ruleset_version v ON v.id = c.version_id "
                  f"WHERE v.ruleset_id IN {rsub})")
        vsub = f"(SELECT id FROM lab.yara_ruleset_version WHERE ruleset_id IN {rsub})"
        c.execute(f"DELETE FROM lab.yara_compiled WHERE version_id IN {vsub}")
        c.execute(f"DELETE FROM lab.yara_compile_job WHERE version_id IN {vsub}")
        c.execute(f"DELETE FROM lab.yara_activation WHERE ruleset_id IN {rsub}")
        c.execute(f"DELETE FROM lab.yara_ruleset_version WHERE ruleset_id IN {rsub}")
        c.execute(f"DELETE FROM lab.yara_ruleset WHERE id IN {rsub}")
        for table in ("yara_compiled_rejected", "yara_compiled",
                      "yara_compile_job", "yara_activation",
                      "yara_ruleset_version", "yara_ruleset"):
            c.execute(f"ALTER TABLE lab.{table} ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{prefix}%@noctornal.test'")


def left_behind(c, prefix: str) -> dict:
    """What a teardown must leave at zero."""
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{prefix}%@noctornal.test')"
    return {
        "users": c.execute(f"SELECT count(*) FROM {sub} x").fetchone()[0],
        "rulesets": c.execute(
            "SELECT count(*) FROM lab.yara_ruleset WHERE key LIKE %s",
            (prefix.rstrip("-") + "%",)).fetchone()[0],
    }


def make_user(c, prefix: str, *, roles=(), clearance="RED", compartments=(),
              name="Lab"):
    from noctornal_api.stores import PgUserStore
    email = f"{prefix}{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(c).create_user(email, name, "x" * 20)
    for key in compartments:
        c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                  "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    c.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
              "WHERE id = %s", (clearance, list(compartments), uid))
    for role in roles:
        c.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                  (uid, role))
    return uid


def make_case(c, owner, *, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    for key in compartments:
        c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                  "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    return CaseService(c).create(
        code=f"OP-STAT-{uuid4().hex[:6]}", title="Static triage",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


def token(c, uid, *, fresh=True) -> str:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, raw = SessionService(PgSessionStore(c)).create(uuid4(), uid,
                                                      mfa_satisfied=True)
    if not fresh:
        c.execute("UPDATE iam.session SET mfa_satisfied_at = now() - "
                  "interval '1 hour' WHERE user_id = %s", (uid,))
    return raw


def auth(raw: str) -> dict:
    return {"Authorization": f"Bearer {raw}"}


def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def declare_policy(monkeypatch) -> None:
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")


def drain(conn, store, *, run_id=None, prefix=None, settings=None):
    """Claim and run, in this process and with the real child, one run
    (`run_id`) or every queued run of the samples a suite's own users
    submitted (`prefix`). Never the rest of the queue: another suite's
    samples, or the demo estate's, are not this test's to decrypt, and a
    store double does not hold their bytes. Returns the final statuses."""
    from noctornal_api import lab_triage
    settings = settings or lab_triage.settings_or_default()
    if run_id is not None:
        claimed, _skipped = lab_triage.claim(conn, settings, run_id=run_id)
        if claimed is None:
            return []
        return [lab_triage.run_claimed(conn, store, claimed, settings)]
    assert prefix, "say whose samples to drain"
    out = []
    tried = set()
    while True:
        row = conn.execute(
            """SELECT r.id FROM lab.static_run r
                 JOIN lab.sample s ON s.id = r.sample_id
                 JOIN iam.app_user u ON u.id = s.submitted_by
                WHERE r.status = 'QUEUED' AND u.email LIKE %s
                  AND NOT (r.id = ANY(%s::uuid[]))
                ORDER BY r.priority, r.queued_at, r.id LIMIT 1""",
            (prefix + "%", [str(t) for t in tried])).fetchone()
        if row is None:
            return out
        tried.add(row[0])
        claimed, _skipped = lab_triage.claim(conn, settings, run_id=row[0])
        if claimed is not None:
            out.append(lab_triage.run_claimed(conn, store, claimed, settings))


__all__ = ["MemoryStore", "auth", "client", "declare_policy", "drain",
           "imphash_of", "left_behind", "make_case", "make_user", "pe_image",
           "rich_hash", "teardown", "token", "varied"]

# The test runner's KEK, as conftest sets it, for suites that import this
# before conftest has run.
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
