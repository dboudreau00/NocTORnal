"""The object store seam's boundary, held by reading the tree.

- One module imports the client library (`objectstore/_minio_sdk.py`), and one test (`test_objectstore_adapter.py`)
  besides, so replacing the library is one file and nothing reads its types.
- No product module lifts a legal hold on a stored object: lifting a hold on a preserved sample is an operator's
  act under counsel's instruction, outside the product (`samples.PreservationStorage`). Only the seam itself, the
  conformance suite and the tests' clean-up may.
- The neutral store names are kept from the processes that must not hold them: the egress proxy refuses the
  neutral secret as it refuses the MinIO one, and an analysis child is started with no store variable at all.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
TESTS = ROOT / "apps" / "api" / "tests"

#: The only files that may import minio, and why.
MINIO_IMPORTERS = {
    "apps/api/src/noctornal_api/objectstore/_minio_sdk.py": "the one adapter",
    "apps/api/tests/test_objectstore_adapter.py": "the adapter's own test, which builds the SDK's errors",
}


def _python_files():
    for base in (ROOT / "apps", ROOT / "scripts", ROOT / "packages"):
        for path in base.rglob("*.py"):
            if ".venv" in path.parts or "node_modules" in path.parts:
                continue
            yield path


def _imports_minio(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
                a.name == "minio" or a.name.startswith("minio.") for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module and (
                node.module == "minio" or node.module.startswith("minio.")):
            return True
    return False


def test_the_minio_sdk_is_imported_by_one_module():
    found = set()
    for path in _python_files():
        if _imports_minio(ast.parse(path.read_text(encoding="utf-8"))):
            found.add(path.relative_to(ROOT).as_posix())
    assert found == set(MINIO_IMPORTERS), found


def test_no_product_module_lifts_a_legal_hold():
    """A store's `set_legal_hold` and the SDK's hold calls appear in no product module and no script outside
    the seam. (`RetentionService.set_legal_hold` is the database's hold on an exhibit row, a different thing,
    and its receiver is never a store.)"""
    offenders = []
    for path in _python_files():
        rel = path.relative_to(ROOT).as_posix()
        if (rel.startswith("apps/api/tests/") or rel.startswith("apps/api/store_conformance/")
                or "/objectstore/" in rel):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            name = node.func.attr
            receiver = ast.unparse(node.func.value).lower()
            if name in ("enable_object_legal_hold", "disable_object_legal_hold") or (
                    name == "set_legal_hold" and "store" in receiver):
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == [], offenders


def test_object_store_secret_is_forbidden_in_the_egress_proxy_env():
    from noctornal_api import egress_proxy
    assert {"OBJECT_STORE_SECRET_KEY", "MINIO_SECRET_KEY", "SAMPLE_SECRET_KEY"} <= set(
        egress_proxy.FORBIDDEN_ENV)
    from test_egress_refusals import _proxy_env
    env = _proxy_env(OBJECT_STORE_SECRET_KEY="not-a-real-store-secret")
    problems = egress_proxy.verify_proxy_environment(env)
    assert any("OBJECT_STORE_SECRET_KEY" in p for p in problems), problems
    assert not any("not-a-real-store-secret" in p for p in problems)


def test_a_child_environment_holds_no_object_store_name(monkeypatch):
    from noctornal_api import analysis_runner
    for name in ("OBJECT_STORE_ENDPOINT", "OBJECT_STORE_ACCESS_KEY", "OBJECT_STORE_SECRET_KEY",
                 "NOCTORNAL_OBJECT_STORE"):
        monkeypatch.setenv(name, "set-in-the-parent")
    child = analysis_runner.child_env()
    assert not [k for k in child if k.startswith(("OBJECT_STORE_", "NOCTORNAL_"))], child
