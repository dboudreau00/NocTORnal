-- The ONLY thing initdb does. CREATE EXTENSION needs superuser, which the
-- application/migration role must never be — so extensions live here and
-- everything else (schemas, tables, triggers, seed) comes from Alembic:
--   alembic upgrade head
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "vector";      -- pgvector, for semantic search
-- CREATE EXTENSION IF NOT EXISTS "pg_uuidv7"; -- preferred; else uuid v4 app-side
