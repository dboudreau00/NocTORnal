"""The static-triage child process: one bounded step over one sample's
bytes (F11 and F12, 2026-09-24).

Run as `python -m noctornal_api.lab_static` by `lab_triage`, never
imported for its steps by anything that holds a database connection,
a key or a request. Pure in this sense: no database, no
environment reads beyond what the parent hands it, no files.

## Why a child at all, and one per step

Every parser here reads attacker-supplied bytes. pefile is pure Python
and memory-safe but has had CPU and memory blow-ups on crafted files;
yara-x runs precompiled native code and parses PE, ELF and .NET with its
own modules. So each step runs in a process of its own that bounds itself
BEFORE it reads a payload byte: no file writes, a CPU limit, an address
space limit where the platform enforces one, a few file descriptors and no
core dump. The parent adds a wall-clock limit that kills the process group
and a cap on what it will read back. One slow or crashing step fails
alone; the others still report.

## What crosses, and how

stdin carries one header line (UTF-8 JSON, at most `HEADER_CAP` bytes),
then the sample, then the rule blob for the YARA modes. Never a temporary
file, an argument, an environment variable or a log line. stdout carries
one JSON document for every mode but `yara_compile`, which frames its
report and its blob (`frame_compile`). stderr is drained by the parent
into its own log, never into the UI, the audit chain or the run row:
a parser's message can quote hostile bytes.

Every step reports an exception by its CLASS with a fixed sentence and
never by its message, for the same reason.

## What the child can still reach

The environment it is started with holds no credential (`child_env` in
`lab_triage`), but on Linux a process can read `/proc/<pid>/environ` of
any dumpable process running as the same user, which includes its
parent, the other API workers and a container's PID 1, and it shares the
container's network. So a parser exploit in the child is a compromise of
the process that started it. The selftest reports both facts
(`exposure`), readiness shows them, and docs/16 records the residual; a
separate container with no secrets and no network is the fix, and is a
deployment change this build does not make.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import struct
import sys
import time

#: The wire protocol between the parent and this module.
PROTOCOL = 1
#: The longest header line the child reads.
HEADER_CAP = 64 * 1024
#: How many file descriptors the child may hold: stdin, stdout, stderr,
#: and what the interpreter and yara-x open for themselves.
NOFILE = 64
MODES = ("selftest", "pe", "fuzzy", "yara_scan", "yara_compile")

#: Fixed sentences for what can go wrong inside a step. A parser's own
#: message can quote the sample, so none is ever passed on.
FAILED = {
    "MemoryError": "the step ran out of memory under the child's limit",
    "RecursionError": "the parser recursed too deeply on this input",
}
FAILED_OTHER = "the parser refused this input"

#: Why a step produced no value, by code. The child reports the CODE and
#: the parent looks the sentence up here, so whatever a compromised child
#: prints, the words stored on a sample and shown in the console are
#: these (a parser exploit must not be able to write the card).
REASONS = {
    "not_pe": "not a PE image",
    "no_imports": "the PE has no import table",
    "no_rich": ("no Rich header (not linked by the Microsoft toolchain, or "
                "stripped)"),
    "fuzzy_cap": ("larger than NOCTORNAL_SAMPLE_FUZZY_MAX_BYTES; fuzzy "
                  "hashes were not computed"),
    "ssdeep_degenerate": "too little byte variety for ssdeep",
    "tlsh_short": ("too short or too little byte variety for TLSH (it needs "
                   "at least 50 bytes spread over more than half its "
                   "buckets)"),
}


def failure_reason(error_class: str | None) -> str:
    """The sentence for a failed step, from the exception CLASS alone."""
    name = error_class if isinstance(error_class, str) and \
        error_class.isidentifier() and len(error_class) <= 64 else "Error"
    return FAILED.get(name, FAILED_OTHER) + f" ({name})"

#: The imports every .NET binary shares, by pefile's lower-cased DLL name.
_DOTNET_LOADER = b"mscoree.dll"


# ---------------------------------------------------------------------------
# Limits, applied by the child to itself
# ---------------------------------------------------------------------------

def limits_kind(plat: str | None = None) -> str:
    """What the child can bound on this platform, in the words the run
    row, the card and readiness use.

    Linux enforces all five limits. macOS accepts RLIMIT_AS and does not
    enforce it, so it is not claimed there. Windows has no
    rlimits: the parent's wall clock is the only bound."""
    plat = plat or sys.platform
    if plat.startswith("linux"):
        return "rlimit"
    if plat == "darwin":
        return "no_writes_cpu_wall"
    return "wall_clock_only"


#: What each kind means, for a reader.
LIMITS_WORDS = {
    "rlimit": "no file writes; memory, CPU and wall-clock limits",
    "no_writes_cpu_wall": ("no file writes; CPU and wall-clock limits; "
                           "memory not limited on this platform"),
    "wall_clock_only": "wall-clock only",
}


def apply_limits(memory_bytes: int, cpu_s: int) -> str:
    """Bound this process before a payload byte is read. Returns the kind
    actually applied."""
    kind = limits_kind()
    if kind == "wall_clock_only":
        return kind
    import resource
    wanted = [(resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_CPU, cpu_s),
              (resource.RLIMIT_NOFILE, NOFILE), (resource.RLIMIT_CORE, 0)]
    if kind == "rlimit":
        wanted.append((resource.RLIMIT_AS, memory_bytes))
    for which, value in wanted:
        soft, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY and value > hard:
            value = hard
        resource.setrlimit(which, (value, value))
    return kind


# ---------------------------------------------------------------------------
# What can run here
# ---------------------------------------------------------------------------

def _version(dist: str) -> str | None:
    try:
        import importlib.metadata
        return importlib.metadata.version(dist)
    except Exception:  # noqa: BLE001 - absent is an answer
        return None


#: The CPU features wasmtime's Cranelift checks when it loads precompiled
#: code, as Linux names them in /proc/cpuinfo (2026-09-24). x86_64: `pni`
#: is SSE3, `abm` carries LZCNT and `cx16` is CMPXCHG16B, which Linux
#: spells differently from Cranelift; the verifier of 2026-09-24 found
#: `sse3` and `lzcnt` (names Linux never prints),
#: `cmpxchg16b`, `avx512vbmi` and `avx512_bitalg` missing, so hosts that
#: differed only there shared a key and each refused the other's build in
#: turn. aarch64: `atomics` is LSE, `paca` pointer authentication, `fphp`
#: half precision and `bti` branch target identification. Extra flags only
#: make a key more specific, which costs a compile, never a refused load.
CPU_FEATURES = {
    "x86_64": ("pni", "ssse3", "cx16", "sse4_1", "sse4_2", "popcnt", "avx",
               "avx2", "fma", "bmi1", "bmi2", "abm", "avx512f", "avx512vl",
               "avx512dq", "avx512bw", "avx512vbmi", "avx512_bitalg"),
    "aarch64": ("atomics", "paca", "pacg", "fphp", "asimdhp", "bti"),
}
#: The same machine names, as other systems report them.
_MACHINE = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}
#: Windows' IsProcessorFeaturePresent numbers for the x86_64 features it
#: can report: SSE3, CMPXCHG16B, SSSE3, SSE4.1, SSE4.2, AVX, AVX2, AVX-512F.
_WINDOWS_FEATURES = (13, 14, 36, 37, 38, 39, 40, 41)


def fingerprint_basis(system: str, machine: str, *, cpuinfo: str | None = None,
                      windows: tuple[int, ...] | None = None,
                      processor: str = "") -> str:
    """What a host's build key hashes: the platform and the CPU features
    that decide whether a precompiled build loads. Pure, so every source
    (the /proc/cpuinfo text, Windows' feature bits, a processor string)
    can be tested without the host."""
    arch = _MACHINE.get(machine.lower(), machine.lower())
    features: list[str] = []
    if cpuinfo is not None:
        have: set[str] = set()
        for line in cpuinfo.splitlines():
            label, _, rest = line.partition(":")
            if label.strip().lower() in ("flags", "features", "isa"):
                have |= set(rest.split())
        wanted = CPU_FEATURES.get(arch)
        # An architecture without a list keeps every flag it reports.
        features = ([f for f in wanted if f in have] if wanted
                    else sorted(have))
    elif windows is not None:
        features = [f"pf{n}" for n in windows] + [processor or "unknown"]
    else:
        features = [processor or "unknown"]
    return f"{system}|{arch}|{','.join(features)}"


def _windows_features() -> tuple[int, ...] | None:
    try:
        import ctypes
        present = ctypes.windll.kernel32.IsProcessorFeaturePresent  # type: ignore[attr-defined]
    except (ImportError, AttributeError, OSError):
        return None
    return tuple(n for n in _WINDOWS_FEATURES if present(n))


_FINGERPRINT: str | None = None


def host_fingerprint() -> str:
    """A short digest of what a compiled YARA build depends on beyond the
    platform name: the CPU features wasmtime checks when it loads
    precompiled code (a build made with AVX2 is refused on a host without
    it). Linux reads the flags the kernel reports, Windows asks the kernel
    for its feature bits, and elsewhere the processor description stands
    in. Computed once per
    process (the CPU does not change under it), in the parent as in the
    child, so both key builds alike."""
    global _FINGERPRINT
    if _FINGERPRINT is None:
        cpuinfo = windows = None
        try:
            with open("/proc/cpuinfo", encoding="ascii", errors="replace") as f:
                cpuinfo = f.read(1 << 20)
        except OSError:
            if sys.platform == "win32":
                windows = _windows_features()
        basis = fingerprint_basis(sys.platform, platform.machine(),
                                  cpuinfo=cpuinfo, windows=windows,
                                  processor=platform.processor())
        _FINGERPRINT = hashlib.sha256(basis.encode()).hexdigest()[:16]
    return _FINGERPRINT


def capabilities() -> dict:
    """The one reader of what can run in this child."""
    from noctornal_api import fuzzyhash
    return {
        "protocol": PROTOCOL,
        "pefile": _version("pefile"),
        "tlsh": fuzzyhash.TLSH_IMPLEMENTATION,
        "ssdeep": fuzzyhash.SSDEEP_IMPLEMENTATION,
        "yara_x": _version("yara-x"),
        "limits": limits_kind(),
        "platform": f"{sys.platform}-{platform.machine().lower()}",
    }


def _exposure(probe: dict | None) -> dict:
    """What a compromised child could reach: whether it can
    read PID 1's environment, and whether it can open a TCP connection to
    the database host the parent names. Neither reads anything past the
    first byte, and neither is ever reported beyond a yes or no."""
    out: dict = {"proc_environ_readable": None, "database_reachable": None}
    if os.path.exists("/proc/1/environ"):
        try:
            with open("/proc/1/environ", "rb") as f:
                f.read(1)
            out["proc_environ_readable"] = True
        except OSError:
            out["proc_environ_readable"] = False
    host = (probe or {}).get("host")
    port = (probe or {}).get("port")
    if host and isinstance(port, int):
        try:
            with socket.create_connection((host, port), timeout=2):
                out["database_reachable"] = True
        except OSError:
            out["database_reachable"] = False
    return out


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def _failure(exc: BaseException) -> dict:
    return {"status": "failed", "code": "error", "error": type(exc).__name__}


def _na(code: str) -> dict:
    return {"status": "not_applicable", "code": code}


def pe_step(data: bytes) -> dict:
    """imphash, the Rich header hash and three facts about the image.

    Only for data that starts with `MZ`. The Rich header is parsed
    EXPLICITLY: after `fast_load` pefile's `get_rich_header_hash()`
    returns '' for every file (measured on python.exe, notepad.exe and
    kernel32.dll), which would have recorded "no Rich header" for all of
    them."""
    steps: dict = {}
    facts: dict = {}
    if not data.startswith(b"MZ"):
        return {"steps": {"imphash": _na("not_pe"),
                          "rich_header_hash": _na("not_pe")}, "pe": None}
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
    except (Exception, MemoryError, RecursionError) as exc:
        bad = _failure(exc)
        return {"steps": {"imphash": dict(bad), "rich_header_hash": dict(bad)},
                "pe": None}
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imphash = pe.get_imphash()
        steps["imphash"] = ({"status": "done", "value": imphash} if imphash
                            else _na("no_imports"))
        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
        facts["is_dotnet"] = (len(imports) == 1 and bytes(
            imports[0].dll or b"").lower() == _DOTNET_LOADER)
    except (Exception, MemoryError, RecursionError) as exc:
        steps["imphash"] = _failure(exc)
    try:
        rich = pe.parse_rich_header()
        clear = rich.get("clear_data") if rich else None
        steps["rich_header_hash"] = (
            {"status": "done", "value": hashlib.md5(clear).hexdigest()}
            if clear else _na("no_rich"))
    except (Exception, MemoryError, RecursionError) as exc:
        steps["rich_header_hash"] = _failure(exc)
    try:
        facts["machine"] = int(pe.FILE_HEADER.Machine)
        facts["is_dll"] = bool(pe.is_dll())
    except (Exception, MemoryError, RecursionError):
        pass
    return {"steps": steps, "pe": facts or None}


def fuzzy_step(data: bytes, fuzzy_max_bytes: int) -> dict:
    """ssdeep and TLSH, each on its own, under the fuzzy cap."""
    from noctornal_api import fuzzyhash
    if len(data) > fuzzy_max_bytes:
        skip = {"status": "skipped", "code": "fuzzy_cap"}
        return {"steps": {"ssdeep": dict(skip), "tlsh": dict(skip)}}
    steps: dict = {}
    try:
        digest = fuzzyhash.ssdeep_digest(data)
        steps["ssdeep"] = (_na("ssdeep_degenerate")
                           if fuzzyhash.ssdeep_is_degenerate(digest)
                           else {"status": "done", "value": digest})
    except (Exception, MemoryError, RecursionError) as exc:
        steps["ssdeep"] = _failure(exc)
    try:
        digest = fuzzyhash.tlsh_digest(data)
        steps["tlsh"] = (_na("tlsh_short") if digest is None
                         else {"status": "done", "value": digest})
    except (Exception, MemoryError, RecursionError) as exc:
        steps["tlsh"] = _failure(exc)
    return {"steps": steps}


# -- YARA ------------------------------------------------------------------

#: What a scan reports per version, bounded (F12 F).
MAX_RULES_REPORTED = 200
MAX_OFFSETS = 8
META_TEXT = 512
MAX_MATCHES_PER_PATTERN = 1000


def _meta_value(value):
    """Rule metadata as JSON: strings cut at META_TEXT, numbers and
    booleans as they are, bytes as escaped text."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        value = value.decode("ascii", "backslashreplace")
    return str(value)[:META_TEXT]


def yara_scan_step(data: bytes, rules_blob: bytes, timeout_s: int) -> dict:
    """Load a compiled build and scan. Returns per matching rule its
    namespace, identifier, tags, metadata and, per pattern, the hit count
    and the first offsets. NO MATCHED BYTES: they would carry the
    sample's content into a finding (F12)."""
    try:
        import yara_x
    except Exception as exc:  # noqa: BLE001
        return {"error": "engine_absent", "error_class": type(exc).__name__}
    try:
        rules = yara_x.Rules.deserialize_from(_Reader(rules_blob))
    except (Exception, MemoryError, RecursionError) as exc:
        return {"error": "rules_rejected", "error_class": type(exc).__name__}
    try:
        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(timeout_s)
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
        # A rule's console.log must never reach the output channel.
        scanner.console_log(lambda _msg: None)
        results = scanner.scan(data)
    except (Exception, MemoryError, RecursionError) as exc:
        name = type(exc).__name__
        kind = "timeout" if "Timeout" in name else "engine_error"
        return {"error": kind, "error_class": name}
    matched = []
    for rule in results.matching_rules:
        if len(matched) >= MAX_RULES_REPORTED:
            break
        patterns = []
        for pattern in rule.patterns:
            hits = list(pattern.matches)
            if not hits:
                continue
            patterns.append({"identifier": str(pattern.identifier)[:META_TEXT],
                             "hits": len(hits),
                             "offsets": [int(m.offset) for m in hits[:MAX_OFFSETS]]})
        matched.append({
            "namespace": str(rule.namespace)[:META_TEXT],
            "identifier": str(rule.identifier)[:META_TEXT],
            "tags": [str(t)[:META_TEXT] for t in rule.tags][:50],
            "metadata": {str(k)[:META_TEXT]: _meta_value(v)
                         for k, v in list(rule.metadata)[:50]},
            "patterns": patterns[:50],
        })
    total = len(results.matching_rules)
    return {"matched": total, "truncated": total > len(matched),
            "rules": matched}


class _Reader:
    """A file-like view of a blob, for `Rules.deserialize_from`."""

    def __init__(self, blob: bytes):
        self._blob = blob
        self._at = 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = len(self._blob) - self._at
        out = self._blob[self._at:self._at + n]
        self._at += len(out)
        return out


class _Writer:
    def __init__(self):
        self.parts: list[bytes] = []

    def write(self, b) -> int:
        self.parts.append(bytes(b))
        return len(b)

    def flush(self) -> None:
        pass


def _compile_errors(compiler) -> list[dict]:
    """Where each error is, never its text: yara-x's text quotes the
    offending rule lines, and a rule's text carries malicious byte
    patterns (docs/18 D3)."""
    out = []
    try:
        errors = compiler.errors()
    except Exception:  # noqa: BLE001
        return out
    for err in errors[:50]:
        labels = err.get("labels") or []
        span = labels[0].get("span") if labels and isinstance(labels[0], dict) else None
        out.append({"code": str(err.get("code", ""))[:16],
                    "title": str(err.get("title", ""))[:200],
                    "line": err.get("line"), "column": err.get("column"),
                    "span": span if isinstance(span, dict) else None})
    return out


def yara_compile_step(source_json: bytes) -> tuple[dict, bytes]:
    """Two passes, because yara-x keeps the valid rules of a source whose
    `add_source` raised (probed 2026-09-24: always-true rules either side
    of a broken one in a 'failed' file matched an unrelated buffer).

    Pass 1 compiles each file alone in a fresh Compiler; a file with any
    error is 'failed' and left out. Pass 2 compiles only the files pass 1
    accepted, one namespace per path, into the Compiler whose build is
    serialised. A cross-file reference fails pass 1, as an include does
    (includes are disabled)."""
    import yara_x
    files = json.loads(source_json.decode("utf-8"))["files"]
    report: dict = {"files": [], "rule_count": 0, "warning_count": 0}
    accepted = []
    for f in files:
        compiler = yara_x.Compiler(relaxed_re_syntax=True,
                                   includes_enabled=False)
        compiler.new_namespace(f["path"])
        try:
            compiler.add_source(f["text"])
            errors = _compile_errors(compiler)
        except yara_x.CompileError:
            errors = _compile_errors(compiler) or [
                {"code": "", "title": "the file does not compile",
                 "line": None, "column": None, "span": None}]
        if errors:
            report["files"].append({"path": f["path"], "status": "failed",
                                    "errors": errors})
        else:
            accepted.append(f)
            report["files"].append({"path": f["path"], "status": "compiled"})
    if not accepted:
        report["status"] = "FAILED"
        return report, b""
    compiler = yara_x.Compiler(relaxed_re_syntax=True, includes_enabled=False)
    try:
        for f in accepted:
            compiler.new_namespace(f["path"])
            compiler.add_source(f["text"])
    except yara_x.CompileError:
        # Every file compiled alone; together they did not (two files
        # defining one global). Nothing is built from a half.
        report["status"] = "FAILED"
        report["combined_errors"] = _compile_errors(compiler)
        return report, b""
    try:
        report["warning_count"] = len(compiler.warnings())
    except Exception:  # noqa: BLE001
        report["warning_count"] = 0
    rules = compiler.build()
    report["rule_count"] = sum(1 for _ in rules)
    out = _Writer()
    rules.serialize_into(out)
    blob = b"".join(out.parts)
    failed = any(x["status"] == "failed" for x in report["files"])
    if not report["rule_count"]:
        report["status"] = "FAILED"
        return report, b""
    report["status"] = "PARTIAL" if failed else "COMPILED"
    return report, blob


def frame_compile(report: dict, blob: bytes) -> bytes:
    """An 8-byte big-endian length, the report, then the blob."""
    body = json.dumps(report, separators=(",", ":")).encode()
    return struct.pack(">Q", len(body)) + body + blob


def unframe_compile(raw: bytes) -> tuple[dict, bytes]:
    """The parent's half of `frame_compile`. Raises ValueError on a frame
    that is not one."""
    if len(raw) < 8:
        raise ValueError("short frame")
    (n,) = struct.unpack(">Q", raw[:8])
    if n > len(raw) - 8 or n > HEADER_CAP * 16:
        raise ValueError("bad frame length")
    return json.loads(raw[8:8 + n].decode("utf-8")), raw[8 + n:]


# ---------------------------------------------------------------------------
# The child's main
# ---------------------------------------------------------------------------

def _read_exact(stream, n: int) -> bytes:
    parts = []
    left = n
    while left:
        chunk = stream.read(min(left, 1 << 20))
        if not chunk:
            raise EOFError("the parent sent fewer bytes than it declared")
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def main() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    line = stdin.readline(HEADER_CAP + 1)
    if len(line) > HEADER_CAP or not line.endswith(b"\n"):
        stdout.write(b'{"ok":false,"error":"bad_header"}')
        return 2
    header = json.loads(line)
    if header.get("protocol") != PROTOCOL or header.get("mode") not in MODES:
        stdout.write(b'{"ok":false,"error":"bad_header"}')
        return 2
    limits = header.get("limits") or {}
    applied = apply_limits(int(limits.get("memory_bytes", 2 << 30)),
                           int(limits.get("cpu_s", 300)))
    mode = header["mode"]
    started = time.monotonic()
    out: dict = {"ok": True, "mode": mode, "limits": applied,
                 "versions": {"pefile": _version("pefile"),
                              "yara_x": _version("yara-x")}}
    if mode == "selftest":
        out["capabilities"] = capabilities()
        out["environment_keys"] = sorted(os.environ)
        out["exposure"] = _exposure(header.get("probe"))
    else:
        data = _read_exact(stdin, int(header.get("sample_len", 0)))
        if mode == "pe":
            out.update(pe_step(data))
        elif mode == "fuzzy":
            out.update(fuzzy_step(data, int(header.get("fuzzy_max_bytes", 0))))
        elif mode == "yara_scan":
            blob = _read_exact(stdin, int(header.get("rules_len", 0)))
            out.update(yara_scan_step(data, blob,
                                      int(header.get("timeout_s", 60))))
        elif mode == "yara_compile":
            try:
                report, blob = yara_compile_step(data)
            except (Exception, MemoryError, RecursionError) as exc:
                report, blob = {"status": "ERROR",
                                "error_class": type(exc).__name__}, b""
            report["timing_ms"] = int((time.monotonic() - started) * 1000)
            report["versions"] = out["versions"]
            stdout.write(frame_compile(report, blob))
            stdout.flush()
            return 0
    out["timing_ms"] = int((time.monotonic() - started) * 1000)
    stdout.write(json.dumps(out, separators=(",", ":")).encode())
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
