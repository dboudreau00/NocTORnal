"""The static-triage child: what it can see, what it can do, and how it
fails (F11 F and G, 2026-09-24).

Every parser in the child reads attacker-supplied bytes, so each step runs
in a process that bounds itself before it reads a payload byte, is fed
over stdin only, reports failures by exception class and never by
message, and is killed when it overruns its wall clock or its output cap.

Pure: no database. The children are real processes.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

from lab_static_fixtures import imphash_of, pe_image, rich_hash, varied

from noctornal_api import lab_static, lab_triage


@pytest.fixture
def settings():
    return lab_triage.settings_or_default()


def test_the_child_sees_no_secret(monkeypatch, settings):
    """The parent's environment is full of secrets; the child's holds a
    PATH, a locale, two flags and where the code is."""
    for name in ("NOCTORNAL_TOTP_KEK", "DATABASE_URL", "SAMPLE_SECRET_KEY",
                 "MINIO_SECRET_KEY", "REDIS_URL", "SMTP_PASSWORD",
                 "PRESERVE_SECRET_KEY"):
        monkeypatch.setenv(name, "a-secret-the-child-must-not-see")
    out = lab_triage.selftest(settings)
    keys = set(out["environment_keys"])
    assert keys <= {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE",
                    "PYTHONNOUSERSITE", "PYTHONPATH", "SYSTEMROOT", "WINDIR"}
    assert not any(k.startswith(("NOCTORNAL_", "DATABASE", "MINIO_", "SAMPLE_",
                                 "PRESERVE_", "REDIS", "SMTP_")) for k in keys)


def test_the_selftest_reports_what_the_child_can_run(settings):
    out = lab_triage.selftest(settings)
    caps = out["capabilities"]
    assert caps["tlsh"].startswith("noctornal-tlsh")
    assert caps["ssdeep"].startswith("noctornal-ssdeep")
    assert caps["limits"] == lab_static.limits_kind()
    assert "exposure" in out


@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="RLIMIT_FSIZE is enforced on Linux; on Windows the "
                           "child has no rlimits and says so")
def test_the_child_cannot_write_a_file(tmp_path, settings):
    script = tmp_path / "write.py"
    target = tmp_path / "out.bin"
    script.write_text(
        "import sys\nsys.path.insert(0, %r)\n"
        "from noctornal_api import lab_static\n"
        "lab_static.apply_limits(1 << 30, 10)\n"
        # Unbuffered, so the write is a system call here and its EFBIG is
        # raised here, not swallowed at a garbage-collected close.
        "try:\n    open(%r, 'wb', buffering=0).write(b'x' * 10)\n"
        "    print('WROTE')\n"
        "except OSError as e:\n    print('REFUSED', e.errno)\n"
        % (lab_triage._package_root(), str(target)))
    import subprocess
    out = subprocess.run([sys.executable, str(script)], capture_output=True,
                         text=True, env=lab_triage.child_env(), timeout=30)
    assert "WROTE" not in out.stdout
    assert not target.exists() or target.stat().st_size == 0


def test_limits_are_reported_per_platform():
    assert lab_static.limits_kind("linux") == "rlimit"
    assert lab_static.limits_kind("darwin") == "no_writes_cpu_wall"
    assert lab_static.limits_kind("win32") == "wall_clock_only"
    assert "memory not limited" in lab_static.LIMITS_WORDS["no_writes_cpu_wall"]
    assert lab_static.LIMITS_WORDS["wall_clock_only"] == "wall-clock only"


def test_a_child_that_runs_too_long_is_killed_and_the_step_fails(tmp_path):
    script = tmp_path / "sleep.py"
    script.write_text("import time, sys\nsys.stdin.buffer.readline()\n"
                      "time.sleep(60)\n")
    result = lab_triage.run_child({"mode": "pe"}, (b"MZ",), wall_s=1.5,
                                  argv=[sys.executable, str(script)])
    assert not result.ok and result.failure == "timeout"


def test_output_over_the_cap_kills_the_child_as_it_crosses(tmp_path):
    script = tmp_path / "flood.py"
    script.write_text("import sys\nsys.stdin.buffer.readline()\n"
                      "while True:\n    sys.stdout.buffer.write(b'x' * 65536)\n")
    result = lab_triage.run_child({"mode": "pe"}, (), wall_s=30,
                                  stdout_cap=1 << 20,
                                  argv=[sys.executable, str(script)])
    assert not result.ok and result.failure == "output_too_large"
    assert len(result.output) <= 1 << 20


def test_a_non_pe_records_imphash_as_not_applicable_not_null(settings):
    part = lab_triage._step_child("pe", varied(1, 4000), settings,
                                  lab_triage.STEP_GAPS["pe"])
    assert part["gaps"]["imphash"] == {"status": "not_applicable",
                                       "reason": "not a PE image"}
    assert part["gaps"]["rich_header_hash"]["status"] == "not_applicable"


def test_rich_header_is_parsed_explicitly_under_fast_load(settings):
    """After fast_load pefile's get_rich_header_hash() says '' for every
    file; the step parses the header itself."""
    import pefile
    image = pe_image()
    assert pefile.PE(data=image, fast_load=True).get_rich_header_hash() == ""
    part = lab_triage._step_child("pe", image, settings,
                                  lab_triage.STEP_GAPS["pe"])
    assert part["values"]["rich_header_hash"] == rich_hash()
    assert part["values"]["imphash"] == imphash_of("KERNEL32.dll", "ExitProcess")
    assert part["gaps"] == {"imphash": None, "rich_header_hash": None}
    assert part["facts"] == {"machine": 0x14C, "is_dll": False,
                             "is_dotnet": False}


def test_a_pe_without_rich_header_says_so(settings):
    part = lab_triage._step_child("pe", pe_image(rich=False), settings,
                                  lab_triage.STEP_GAPS["pe"])
    assert part["gaps"]["rich_header_hash"]["status"] == "not_applicable"
    assert "no Rich header" in part["gaps"]["rich_header_hash"]["reason"]
    assert part["values"]["imphash"]


def test_a_dotnet_stub_is_flagged_by_its_common_imphash(settings):
    from noctornal_api.fuzzyhash import COMMON_IMPHASHES
    part = lab_triage._step_child(
        "pe", pe_image(dll=b"mscoree.dll", function=b"_CorExeMain"), settings,
        lab_triage.STEP_GAPS["pe"])
    assert part["values"]["imphash"] in COMMON_IMPHASHES
    assert part["facts"]["is_dotnet"] is True


def test_parser_errors_never_quote_the_sample(settings):
    """A hostile import name reaches no output, and a failure is its class
    and a fixed sentence."""
    marker = b"EVILMARKER_" + b"\xfe\xff" * 4
    image = pe_image(function=marker)
    raw = lab_triage.run_child(
        {"mode": "pe", "sample_len": len(image), "fuzzy_max_bytes": 1 << 20,
         "limits": {"memory_bytes": settings.memory_bytes, "cpu_s": 30}},
        (image,), wall_s=40)
    assert raw.ok
    assert b"EVILMARKER" not in raw.output
    truncated = image[:0x140]
    raw = lab_triage.run_child(
        {"mode": "pe", "sample_len": len(truncated), "fuzzy_max_bytes": 1 << 20,
         "limits": {"memory_bytes": settings.memory_bytes, "cpu_s": 30}},
        (truncated,), wall_s=40)
    out = json.loads(raw.output)
    for step in out["steps"].values():
        # A value is a digest; anything else is a status, a code and a
        # class name, never words the parser wrote.
        if step["status"] == "done":
            assert set(step) == {"status", "value"}
            int(step["value"], 16)
        else:
            assert set(step) <= {"status", "code", "error"}


def test_truncated_and_corrupted_pe_headers_fail_the_step_by_class_and_the_fuzzy_step_still_reports(settings):
    bad = b"MZ" + b"\x00" * 58 + (0xFFFFFF).to_bytes(4, "little") + varied(2, 8000)
    pe = lab_triage._step_child("pe", bad, settings, lab_triage.STEP_GAPS["pe"])
    assert pe["gaps"]["imphash"]["status"] == "failed"
    assert "(PEFormatError)" in pe["gaps"]["imphash"]["reason"]
    fz = lab_triage._step_child("fuzzy", bad, settings,
                                lab_triage.STEP_GAPS["fuzzy"])
    assert fz["values"]["ssdeep"] and fz["values"]["tlsh"]


def test_fuzzy_above_the_cap_is_skipped_naming_the_setting(settings):
    small = lab_triage.AnalysisSettings(settings.memory_bytes, 1 << 20, 1000,
                                        settings.timeout_s, 1)
    fz = lab_triage._step_child("fuzzy", varied(3, 5000), small,
                                lab_triage.STEP_GAPS["fuzzy"])
    assert fz["gaps"]["ssdeep"]["status"] == "skipped"
    assert "NOCTORNAL_SAMPLE_FUZZY_MAX_BYTES" in fz["gaps"]["ssdeep"]["reason"]


def test_a_child_that_lies_is_not_believed(tmp_path, settings, monkeypatch):
    """A compromised child's words never reach the card: values must be
    digests, reasons come from the parent's table."""
    script = tmp_path / "liar.py"
    versions = json.dumps(lab_triage._parent_versions())
    script.write_text(
        "import sys, json\nsys.stdin.buffer.readline()\nsys.stdin.buffer.read()\n"
        "print(json.dumps({'ok': True, 'versions': json.loads(%r), 'steps': {"
        "'imphash': {'status': 'done', 'value': '<script>x</script>'},"
        "'rich_header_hash': {'status': 'not_applicable', 'code': 'pwned',"
        " 'reason': 'click here'}}}))\n" % versions)
    monkeypatch.setattr(lab_triage, "CHILD_ARGV", [sys.executable, str(script)])
    part = lab_triage._step_child("pe", b"MZ" + bytes(100), settings,
                                  lab_triage.STEP_GAPS["pe"])
    assert part["values"]["imphash"] is None
    assert part["gaps"]["imphash"]["status"] == "failed"
    assert part["gaps"]["rich_header_hash"]["reason"] != "click here"


def test_a_32_mib_zero_padded_pe_finishes_both_steps_inside_the_default_timeout(settings):
    image = pe_image(pad_to=32 << 20)
    for mode in ("pe", "fuzzy"):
        part = lab_triage._step_child(mode, image, settings,
                                      lab_triage.STEP_GAPS[mode])
        assert part.get("failure") is None, (mode, part)
        assert part["timing_ms"] < settings.timeout_s * 1000


def test_the_child_is_started_without_preexec_fn():
    src = (lab_triage.__file__)
    text = open(src, encoding="utf-8").read()
    assert "preexec_fn" not in text.split('"""', 2)[2].replace(
        "Never `preexec_fn`", "")
    assert os.name in ("nt", "posix")


def test_the_settings_have_one_reader_and_production_refuses_a_problem():
    """F11 B: memory, the analysis and fuzzy maxima, the per-child timeout
    and the deployment-wide concurrency, read once; a production boot
    refuses a problem by the variable's name, never its value."""
    from noctornal_api.config import verify_environment
    s, problem = lab_triage.analysis_settings({})
    assert problem is None
    assert (s.memory_bytes, s.timeout_s, s.concurrency) == (2 << 30, 300, 1)
    assert s.max_bytes == min(256 << 20, ((2 << 30) - (512 << 20)) // 3)
    assert s.fuzzy_max_bytes == 32 << 20
    _s, problem = lab_triage.analysis_settings(
        {lab_triage.MAX_BYTES_ENV: "1GiB"})
    assert "could not hold a sample this large" in problem
    _s, problem = lab_triage.analysis_settings(
        {lab_triage.FUZZY_MAX_ENV: "600MiB", lab_triage.MAX_BYTES_ENV: "100MiB"})
    assert lab_triage.FUZZY_MAX_ENV in problem
    _s, problem = lab_triage.analysis_settings({lab_triage.CONCURRENCY_ENV: "9"})
    assert lab_triage.CONCURRENCY_ENV in problem
    refusals = verify_environment({"NOCTORNAL_ENV": "production",
                                   lab_triage.TIMEOUT_ENV: "7",
                                   "NOCTORNAL_YARA_SCAN_TIMEOUT_S": "1"})
    mine = [r for r in refusals if lab_triage.TIMEOUT_ENV in r
            or "NOCTORNAL_YARA_SCAN_TIMEOUT_S" in r]
    assert len(mine) == 2
    assert not any(" 7 " in r or " 1 " in r for r in mine)
    assert verify_environment({lab_triage.TIMEOUT_ENV: "7"}) == []


# --- the build key's CPU fingerprint ------------------------------------------

_X86 = ("processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "flags\t\t: fpu pni ssse3 cx16 sse4_1 sse4_2 popcnt avx avx2 fma "
        "bmi1 bmi2 abm constant_tsc {extra}\nbugs\t\t: spectre_v1\n")


def _fp(extra="", **kw):
    return lab_static.fingerprint_basis(
        "linux", kw.pop("machine", "x86_64"),
        cpuinfo=kw.pop("cpuinfo", _X86.format(extra=extra)), **kw)


@pytest.mark.parametrize("flag", ["avx512vbmi", "avx512_bitalg", "avx512f",
                                  "avx512vl", "avx512dq", "avx512bw"])
def test_hosts_differing_in_a_feature_wasmtime_checks_get_different_keys(flag):
    """The verifier of 2026-09-24: hosts differing only in AVX-512 VBMI or
    BITALG, CMPXCHG16B, or an aarch64 feature shared a build key, and each
    refused the other's build in turn."""
    assert _fp() != _fp(flag)


def test_linux_spellings_are_the_ones_read():
    """SSE3 is `pni`, LZCNT rides on `abm` and CMPXCHG16B is `cx16` in
    /proc/cpuinfo; the names Cranelift uses never appear there."""
    base = _X86.format(extra="")
    for linux in ("pni", "abm", "cx16"):
        without = base.replace(f" {linux} ", " ")
        assert _fp(cpuinfo=without) != _fp(cpuinfo=base), linux
    assert _fp("sse3 lzcnt cmpxchg16b") == _fp()


def test_flags_wasmtime_ignores_do_not_split_the_key():
    assert _fp("hypervisor tsc_known_freq arch_perfmon") == _fp()
    shuffled = _X86.format(extra="").replace("pni ssse3", "ssse3 pni")
    assert _fp(cpuinfo=shuffled) == _fp()


def test_aarch64_features_and_other_architectures():
    arm = "Features\t: fp asimd evtstrm aes crc32 {x}\n"
    base = _fp(machine="aarch64", cpuinfo=arm.format(x=""))
    for feature in ("atomics", "paca", "fphp", "bti"):
        assert _fp(machine="aarch64",
                   cpuinfo=arm.format(x=feature)) != base, feature
    # macOS and Windows call the same machine arm64.
    assert _fp(machine="arm64", cpuinfo=arm.format(x="")) == base
    # An architecture without a list keeps every flag it reports.
    riscv = "isa\t\t: rv64imafdc {x}\n"
    assert (_fp(machine="riscv64", cpuinfo=riscv.format(x="zba"))
            != _fp(machine="riscv64", cpuinfo=riscv.format(x="")))


def test_windows_feature_bits_are_part_of_the_key():
    a = lab_static.fingerprint_basis("win32", "AMD64", windows=(13, 14, 40),
                                     processor="Intel64 Family 6")
    b = lab_static.fingerprint_basis("win32", "AMD64", windows=(13, 14),
                                     processor="Intel64 Family 6")
    assert a != b and a.startswith("win32|x86_64|")


def test_the_host_fingerprint_is_short_and_stable():
    first = lab_static.host_fingerprint()
    assert len(first) == 16 and first == lab_static.host_fingerprint()
