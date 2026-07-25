# noctornal-api

The FastAPI service. Phase 1 surface: authentication, cases, graph writes,
selectors, evidence, search — every case-scoped request through the
five-part access gate, every graph write carrying an assertion.

## Run it

The compose stack must be up (`cd infra && docker compose up -d`) and the
migrations applied (`alembic upgrade head` from the repo root).

```bash
export DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal"
export NOCTORNAL_TOTP_KEK="$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
export MINIO_ENDPOINT=localhost:9000 MINIO_ACCESS_KEY=noctornal MINIO_SECRET_KEY=dev_only_change_me
uvicorn noctornal_api.http.app:app --reload
```

PowerShell uses `$env:NAME = "value"`. Interactive docs:
<http://localhost:8000/api/v1/docs>.

**Keep the KEK.** It seals TOTP secrets; losing it means every user must
re-enrol. There is deliberately no default.

## Layout

```
security/    passwords (Argon2id), totp (RFC 6238 + replay), sessions,
             tokens, envelope (AES-GCM), access (the five-part gate)
stores.py    Postgres implementations of the store protocols + the
             access-context resolver
graph.py     GraphWriteService — the ONLY sanctioned node/edge write path
selectors.py selector storage, normalised via the ontology package
evidence.py  WORM ingest, dual-hash, custody
cases.py     case CRUD, lifecycle, assignment
curation.py  tags, node sets, search
http/        app factory, deps (auth + gate), routers
```

## The three rules a new endpoint must follow

1. **Case-scoped endpoints depend on `require("<permission>")`** (or call
   `authorize_object` when the object is an element whose classification
   can be stricter than its case). Never re-implement an access decision —
   there is exactly one `evaluate()`.
2. **Graph writes go through `GraphWriteService`**, so the assertion lands
   in the same transaction. The database rejects an assertion-less node or
   edge at commit anyway (invariant 1), but going around the service means
   discovering that as a 500 instead of a clean 400.
3. **An endpoint that costs real money gets a limit.** Add it to the
   catalogue in `ratelimit.py` and hang `Depends(rate_limit("<name>"))` on
   the route. "Costs real money" means CPU (analytics), storage that cannot
   be reclaimed (WORM ingest), something leaving the boundary (export), or
   an analyst's attention (capture floods the triage queue). Everything is
   already under a blanket per-credential ceiling applied in middleware, so
   this is about the specific cost, not about basic protection.

## Rate limiting

`ratelimit.py` holds the algorithm and the catalogue; `ratelimit_redis.py`
holds the one Lua script; `http/limits.py` wires both into requests. The
full reasoning is decision 43. Four things worth knowing before touching it:

- **`REDIS_URL` unset ⇒ per-process metering**, with a loud warning at
  startup. Correct for a single-process dev instance, wrong for a
  deployment with more than one worker.
- **A backend outage means different things to different limits.** The
  cost-bearing ones return 503 rather than run unmetered; the blanket
  ceiling fails open so that a Redis restart is not an outage. A test
  asserts the blanket ceiling is the *only* fail-open entry.
- **Login is metered twice** — a generous limit on attempts (so a NAT'd
  organisation can sign on) and a tight one on *failures* (which only a
  guesser produces).
- **`NOCTORNAL_RATELIMIT=off`** disables everything. It exists for tests
  that deliberately hammer an endpoint. It logs a warning on every start.

## Tests

```bash
python -m pytest apps/api/tests -q
```

Unit tests always run. Anything touching Postgres is gated on
`DATABASE_URL`, and the evidence legs additionally on `MINIO_ENDPOINT`, so
the suite degrades to unit-only without the stack. `test_http_e2e.py` is
the wiring proof: the analyst journey plus the 401/403/404/400 paths,
including step-up re-challenge and the invariant-8 export refusal.

## Not yet done

- **CSRF** — cookie auth is set but there is no double-submit token yet, so
  browser clients should use the Bearer token until it lands (docs/05).
- **Egress gate** — `export` enforces the AMBER_STRICT/RED floor, but the
  destination-aware gate is Phase 5 (docs/07).
- Node/edge **read** endpoints, assertion listing, and the neighbourhood /
  subgraph queries the sociogram needs are Phase 2.
