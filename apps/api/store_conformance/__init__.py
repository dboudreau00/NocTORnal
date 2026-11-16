"""The object store conformance suite: what a store must do for this product to keep evidence on it (docs/22).

Run against a live endpoint, by environment variable, OUTSIDE the CI test path (`apps/api/tests` is the only
directory the CI Tests step and `testpaths` name), so the CI gate that fails on any skip never sees a suite that
has no store to run against:

    OBJECT_STORE_CONFORMANCE_ENDPOINT=host:port OBJECT_STORE_CONFORMANCE_ACCESS_KEY=... \\
    OBJECT_STORE_CONFORMANCE_SECRET_KEY=... OBJECT_STORE_CONFORMANCE_PROFILE=s3 \\
    pytest apps/api/store_conformance -q

The checks themselves are in `checks.py`, plain functions over a `Ctx`, so `tests/test_store_conformance_selftest.py`
runs the same functions against an in-process store that behaves and against stores broken on purpose, which is
what stops the suite turning into a rubber stamp.
"""
