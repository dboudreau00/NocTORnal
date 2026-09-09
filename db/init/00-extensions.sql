-- The ONLY thing initdb does. CREATE EXTENSION needs superuser, which the
-- application/migration role must never be — so extensions live here and
-- everything else (schemas, tables, triggers, seed) comes from Alembic:
--   alembic upgrade head
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "vector";      -- pgvector, for semantic search
-- No pg_uuidv7: ids are uuid4() app-side and gen_random_uuid() in SQL (the
-- 2026-07 sketch preferred v7; the build did not take it).
