#!/bin/sh
# The egress proxy's own database role (S2-3, egress-proxy, 2026-09-24),
# born at initdb for the reason 10-app-role.sh gives: this is the only
# moment in the deployment that anything runs as a superuser. Migration 0086
# grants it exactly egress_ledger.EGRESS_GRANTS: the egress configuration, the
# collection columns the proxy decides on, and INSERT on the connection
# ledger. It can append what left the building and cannot rewrite it.
#
# The same shape as 10-app-role.sh, for the same reasons (read that file's
# header): a sourced, NOT executable script, because the postgres entrypoint
# sources a non-executable *.sh and a repository authored on Windows records
# every file 100644; no `exit` and no `set -u`, because being sourced means
# both would reach the entrypoint's own shell; the password passed as a psql
# variable and never pasted into SQL; statement logging off for the session
# that carries it. The same connection defaults as 10-app-role.sh too, so
# CI's step (PGHOST, PGPASSWORD, POSTGRES_USER, POSTGRES_DB) runs it as it
# runs the other.
#
# The password is NOCTORNAL_EGRESS_DB_PASSWORD, which lives in
# infra/production/postgres-init.env (read by the postgres service alone)
# and inside NOCTORNAL_EGRESS_DATABASE_URL in egress-proxy.env. It is never
# in secrets.env, which every application service and caddy receive.
#
# Doing nothing is a supported outcome: without the variable there is no
# egress role, and a development stack runs the proxy (when it runs one at
# all) as the owner.

set -e

_NOC_DB="${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"
_NOC_SUPERUSER="${POSTGRES_USER:-postgres}"

if [ -z "${NOCTORNAL_EGRESS_DB_PASSWORD:-}" ]; then
	echo "20-egress-role: NOCTORNAL_EGRESS_DB_PASSWORD is not set, so no egress proxy"
	echo "20-egress-role: role was created. Set it (infra/production/postgres-init.env)"
	echo "20-egress-role: and initialise a FRESH volume, or create the role by hand"
	echo "20-egress-role: (python scripts/egress_setup.py role-sql)."
else
	echo "20-egress-role: creating the egress proxy role noctornal_egress."

	psql -v ON_ERROR_STOP=1 --no-psqlrc \
		--username "${_NOC_SUPERUSER}" \
		--dbname "${_NOC_DB}" \
		--set=dbname="${_NOC_DB}" \
		--set=egresspw="${NOCTORNAL_EGRESS_DB_PASSWORD}" <<-'EOSQL'
		-- The password travels through the statement below: keep it out of
		-- the server log for this session (see 10-app-role.sh).
		SET log_statement = 'none';
		SET log_min_duration_statement = -1;

		DO $$
		BEGIN
		  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_egress') THEN
		    CREATE ROLE noctornal_egress
		      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
		      NOREPLICATION NOBYPASSRLS;
		  END IF;
		END
		$$;

		ALTER ROLE noctornal_egress WITH PASSWORD :'egresspw';

		-- Every schema, table and column grant is migration 0086's; none of
		-- those objects exist yet.
		GRANT CONNECT ON DATABASE :"dbname" TO noctornal_egress;
	EOSQL

	echo "20-egress-role: created. It holds nothing until 0086 grants it; run"
	echo "20-egress-role: 'alembic upgrade head' as the OWNER (${_NOC_SUPERUSER})."
fi

unset _NOC_DB _NOC_SUPERUSER
