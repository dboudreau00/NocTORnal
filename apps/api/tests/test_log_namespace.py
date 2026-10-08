"""docs/17, "Tests and code structure", test isolation (Beta 1.1): one logger
namespace.

Twenty-five modules logged under `noctornal.<name>` and thirteen under
`noctornal_api.<module>` (`getLogger(__name__)`), so a setting made for one
namespace, `logging.getLogger("noctornal").setLevel(...)` or a handler on it,
reached two thirds of the product. Every logger of ours is `noctornal.<name>`
now. The one other name is `telethon`, the library's own logger, which
`telegram_wire.install_log_scrub` configures on purpose and does not own.

Pure: reads the source.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LIBRARY_LOGGERS = frozenset({"telethon"})


def _sources():
    for root in (ROOT / "apps" / "api" / "src", ROOT / "scripts"):
        for path in sorted(root.rglob("*.py")):
            yield path, ast.parse(path.read_text(encoding="utf-8"))


def _logger_calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "getLogger":
                yield node


def _named(node):
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def test_every_logger_is_in_the_noctornal_namespace():
    wrong = []
    for path, tree in _sources():
        for call in _logger_calls(tree):
            name = _named(call)
            if name is None or not (name == "noctornal" or name.startswith("noctornal.")
                                    or name in LIBRARY_LOGGERS):
                shown = name if name is not None else ast.unparse(call.args[0]) if call.args else "()"
                wrong.append(f"{path.relative_to(ROOT).as_posix()}:{call.lineno} {shown}")
    assert wrong == [], (
        "these log outside the noctornal. namespace (getLogger(__name__) names "
        "the module noctornal_api.<module>): " + "; ".join(wrong))


def test_a_module_logs_under_one_name():
    """The same module under two names splits its records for whoever filters
    on one of them."""
    split = []
    for path, tree in _sources():
        names = {n for n in (_named(c) for c in _logger_calls(tree)) if n} - LIBRARY_LOGGERS
        if len(names) > 1:
            split.append(f"{path.relative_to(ROOT).as_posix()}: {sorted(names)}")
    assert split == [], "; ".join(split)


def test_the_scrubbed_telethon_records_are_logged_under_the_namespace(caplog):
    """`install_log_scrub` re-logs a library record under our own name,
    which was `noctornal_api.telegram_wire` while the module's logger was
    `noctornal.telegram_wire`'s sibling."""
    import logging

    from noctornal_api import telegram_wire

    telegram_wire.install_log_scrub()
    caplog.set_level(logging.WARNING)
    logging.getLogger("telethon.network").warning("a record with a persona.name in it")
    scrubbed = [r for r in caplog.records if r.name.startswith("noctornal")]
    assert [r.name for r in scrubbed] == ["noctornal.telegram_wire"]
    assert telegram_wire.log.name == "noctornal.telegram_wire"
