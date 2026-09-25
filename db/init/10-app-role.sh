#!/bin/sh
# The least-privilege runtime role, born at initdb because this is the only
# moment in the whole deployment that anything runs as a superuser.
#
# db/README.md's rule for 00-extensions.sql applies here for the same reason:
# CREATE ROLE needs superuser or CREATEROLE, and the role that owns the schema
# and runs Alembic must never be either. So `noctornal_app` is CREATED here and
# every privilege it holds is GRANTed by migration 0060 -- not because that is
# tidier, but because at this point in initdb the database has no schemas at
# all. Alembic has not run and cannot: the server answering right now is the
# entrypoint's temporary single-user instance on a unix socket. `GRANT USAGE ON
# SCHEMA core` here would be a well-formed statement that fails, and with
# ON_ERROR_STOP it would abandon a half-built cluster (see the recovery note in
# infra/docker-compose.yml: `docker compose down -v`).
#
# A shell script rather than .sql because the password arrives as an
# environment variable and psql -f cannot read the environment. It is passed as
# a psql VARIABLE (`--set` + `:'apppw'`), never pasted into SQL text assembled
# here: psql renders the variable as a correctly escaped literal, so a password
# containing a quote or a backslash is a password, not a syntax error or an
# injection.
#
# NOT executable, deliberately. The postgres entrypoint runs an executable
# `*.sh` and SOURCES a non-executable one, and this repository is authored on
# Windows, where git records every file 100644 -- a script that only worked
# with the execute bit set would work on the author's machine and nowhere else.
# Being sourced is also why nothing below calls `exit`: that would kill the
# entrypoint's own shell mid-init, leaving a cluster with no schema and a
# container that reports success. It is why `set -u` is not used either --
# nounset would persist into the rest of the entrypoint, which is written
# without it and reads plenty of unset variables. `set -e` below persists in
# exactly the same way and is still correct, which looks inconsistent until
# you check: postgres's docker-entrypoint.sh opens with `set -Eeo pipefail`,
# so errexit is already on and re-stating it changes nothing there while
# keeping this file honest if somebody runs it by hand.
#
# Doing nothing is a supported outcome. Without NOCTORNAL_APP_DB_PASSWORD there
# is no app role, the deployment connects as the owner, and every existing dev
# stack behaves exactly as it did before this file existed. That is the case on
# every developer machine and in CI, and it must stay silent-but-stated rather
# than fatal.

set -e

_NOC_DB="${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"
_NOC_SUPERUSER="${POSTGRES_USER:-postgres}"

if [ -z "${NOCTORNAL_APP_DB_PASSWORD:-}" ]; then
	echo "10-app-role: NOCTORNAL_APP_DB_PASSWORD is not set, so no least-privilege"
	echo "10-app-role: role was created. This deployment will connect as the owner"
	echo "10-app-role: ${_NOC_SUPERUSER}, which is what a development stack does."
	echo "10-app-role: Set the variable (infra/production/secrets.env) and initialise"
	echo "10-app-role: a FRESH volume to get one -- initdb scripts never re-run."
else
	echo "10-app-role: creating the least-privilege role noctornal_app."

	psql -v ON_ERROR_STOP=1 --no-psqlrc \
		--username "${_NOC_SUPERUSER}" \
		--dbname "${_NOC_DB}" \
		--set=dbname="${_NOC_DB}" \
		--set=apppw="${NOCTORNAL_APP_DB_PASSWORD}" <<-'EOSQL'
		-- The password is about to travel through a statement. Postgres logs
		-- statement text when log_statement is ddl/all, and logs it anyway if
		-- the statement outruns log_min_duration_statement (the dev stack sets
		-- that to 250ms and a production one may be stricter). Both are
		-- superuser GUCs and we are the superuser exactly once -- here -- so
		-- pin them for this session and let the value stay out of the log.
		SET log_statement = 'none';
		SET log_min_duration_statement = -1;

		-- Idempotent: an operator re-running this by hand against a live
		-- cluster resets the password and changes nothing else. CREATE ROLE
		-- has no IF NOT EXISTS, hence the DO block.
		--
		-- NOINHERIT does not stop `SET ROLE` -- nothing but not being a member
		-- does that -- but it does mean a future `GRANT noctornal TO
		-- noctornal_app`, typed to fix some permission complaint, would not
		-- silently hand this role the owner's rights on every connection. The
		-- escalation would then need a deliberate SET ROLE somebody can find.
		DO $$
		BEGIN
		  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app') THEN
		    CREATE ROLE noctornal_app
		      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
		      NOREPLICATION NOBYPASSRLS;
		  END IF;
		END
		$$;

		-- Interpolated by psql as a literal, at the top level of the file:
		-- psql does NOT substitute inside a dollar-quoted body, so this cannot
		-- move into the DO block above.
		ALTER ROLE noctornal_app WITH PASSWORD :'apppw';

		-- CONNECT is granted to PUBLIC by default, so on a stock cluster this
		-- is a statement of intent rather than a change: it becomes the thing
		-- that keeps the API connecting the moment an operator runs
		-- `REVOKE CONNECT ON DATABASE ... FROM PUBLIC`. That revoke is not done
		-- here, because this file cannot know what else an operator has
		-- pointed at this database (a metrics exporter, a backup role), and
		-- locking out an unknown consumer at initdb is a failure nobody can
		-- diagnose from the API's logs.
		--
		-- Every SCHEMA-level and TABLE-level grant is in migration 0060. None
		-- of those objects exist yet.
		GRANT CONNECT ON DATABASE :"dbname" TO noctornal_app;

		-- S1 (2026-09-25): the request role's own settings, which only
		-- a superuser may pin. Row-level security binds each request's
		-- connection with a proof that travels as a bind parameter, and a
		-- statement slower than log_min_duration_statement is logged WITH its
		-- parameters by default: keep them out of the log. And a row-security
		-- refusal is recognised by its message (http/errors.py), so the
		-- message language is pinned for this role.
		ALTER ROLE noctornal_app SET log_parameter_max_length = 0;
		ALTER ROLE noctornal_app SET log_parameter_max_length_on_error = 0;
		ALTER ROLE noctornal_app SET lc_messages = 'C';
	EOSQL

	echo "10-app-role: created. It holds nothing until 0060 grants it -- run"
	echo "10-app-role: 'alembic upgrade head' as the OWNER (${_NOC_SUPERUSER})."
fi

# The system role (S1, 2026-09-25). Row-level security filters every
# request to the rows its user may read, and some work must see every row:
# retention, legal holds, lock extension, merges, the withheld counts,
# sign-in (the IAM plane is read-only to noctornal_app) and every script.
# That work connects as noctornal_worker: BYPASSRLS, which only a superuser
# may grant, and this is the one moment anything here runs as one. It owns
# nothing and is a member of nothing; migration 0108 grants it exactly what
# the request role held before 0109. Its password is NOT in secrets.env:
# postgres-init.env gives it to this service alone, and the sample origin
# is started without the DSN. Absent, nothing is created and that is said.
if [ -z "${NOCTORNAL_WORKER_DB_PASSWORD:-}" ]; then
	echo "10-app-role: NOCTORNAL_WORKER_DB_PASSWORD is not set, so no system"
	echo "10-app-role: role was created. A development stack connects as the"
	echo "10-app-role: owner and needs none; a production one does"
	echo "10-app-role: (infra/production/postgres-init.env), or run"
	echo "10-app-role: python scripts/runtime_roles.py ensure --production later."
else
	echo "10-app-role: creating the system role noctornal_worker."

	psql -v ON_ERROR_STOP=1 --no-psqlrc \
		--username "${_NOC_SUPERUSER}" \
		--dbname "${_NOC_DB}" \
		--set=dbname="${_NOC_DB}" \
		--set=workerpw="${NOCTORNAL_WORKER_DB_PASSWORD}" <<-'EOSQL'
		SET log_statement = 'none';
		SET log_min_duration_statement = -1;

		DO $$
		BEGIN
		  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_worker') THEN
		    CREATE ROLE noctornal_worker
		      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
		      NOREPLICATION BYPASSRLS;
		  END IF;
		END
		$$;

		ALTER ROLE noctornal_worker WITH PASSWORD :'workerpw';
		GRANT CONNECT ON DATABASE :"dbname" TO noctornal_worker;
	EOSQL

	echo "10-app-role: created. Migration 0108 grants it; set"
	echo "10-app-role: NOCTORNAL_WORKER_DATABASE_URL on every service but the"
	echo "10-app-role: sample origin."
fi

unset _NOC_DB _NOC_SUPERUSER
