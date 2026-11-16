"""The object store seam: one way to speak S3 to whichever store a deployment runs.

Every bucket the product writes (evidence, the raw ingest batches, collected markup, samples and the
preservation bucket) is addressed through the one settings reader (`settings.py`), and what a store
says is told in this package's own words (`errors.py`, `types.py`), so a caller never needs the
client library's types to read an answer. `store.open_store` builds the store a role's settings name
over one adapter, `_minio_sdk.py`, which is the only module that imports the client library, handed a
pool from `pools.py` that gives up in seconds. docs/22 is the operator's page.
"""
