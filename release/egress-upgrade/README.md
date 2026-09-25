# Upgrading an existing deployment to the egress proxy

From this release the production deployment's application network is
internal: the API, the cron loop and the sample origin have no route to the
internet, and everything that leaves goes through the egress proxy, which
decides each connection by route and records it
(`infra/production/README.md`, Egress). An existing deployment keeps its
data. It needs keys, three small files, one database role and its routes,
in this order.

## 0. Check Docker Compose

```sh
docker compose version --short
```

It must be **2.24 or later**. The production compose file lists the new env
files as optional (`required: false`), which older Compose versions refuse
outright, including for `ps` and `logs`.

## 1. Generate the keys

```sh
python scripts/egress_setup.py keygen
```

It prints a seal key pair, a client key and a fingerprint key, once, each
labelled with the file it belongs in. Nothing is written anywhere.

## 2. Write the three files

```sh
cp infra/production/egress-proxy.env.example  infra/production/egress-proxy.env
cp infra/production/egress-client.env.example infra/production/egress-client.env
cp infra/production/postgres-init.env.example infra/production/postgres-init.env
chmod 600 infra/production/egress-*.env infra/production/postgres-init.env
```

Fill them from step 1. Choose a password for the egress role and write it in
`postgres-init.env` and inside `NOCTORNAL_EGRESS_DATABASE_URL`. None of this
goes in `secrets.env`.

## 3. Create the role on the existing volume

`db/init/20-egress-role.sh` runs only on an empty volume, so an existing one
needs the role created by hand, as a superuser:

```sh
python scripts/egress_setup.py role-sql
docker compose -p noctornal-prod -f infra/production/compose.yml exec postgres \
  psql -U noctornal -d noctornal
```

Paste the statements it printed. `\password noctornal_egress` asks for the
password without it ever sitting in a statement or a log. The grants are
the migration's, so run the upgrade (next step) after the role exists; if
you created the role after migrating, the grant lines in the same output
apply them.

## 4. Preflight, then start

```sh
python scripts/egress_setup.py preflight
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

Preflight checks that all three files exist, that every key is well formed,
that the two copies of the client and fingerprint keys agree, and that the
seal key's public half matches. It writes nothing.

## 5. Adopt the current configuration

```sh
python scripts/egress_setup.py adopt
```

It signs you in (password and a current authenticator code; the account
needs `egress.manage`), proposes what this deployment needs to keep working
through the proxy, and creates it only when you type `yes`:

* a passive default profile named `passive`, which reads feeds from this
  host's own address as they have always been read: any public host, on the
  ports your feeds use plus 80 and 443, carrying feeds labelled up to the
  highest label among them (AMBER at least);
* an `smtp` route for `SMTP_HOST`, and a `webhook` route for
  `NOCTORNAL_WEBHOOK_URL`, each allowing exactly that host and port. A relay
  that answers on a private address is proposed as `name@network`, and you
  confirm the network.

Until adopt has run, feeds and deliveries are refused for want of a route,
and the readiness row `egress_routes_cover_sources` says which uses have
none.

## 6. Confirm the boundary

Open Administration, Readiness. `egress_boundary` passes only when the proxy
accepted this process's key and refused a private destination, and this
process has no default route of its own. Then make the host check in
`infra/production/README.md`, Egress, which the register cannot make for
you.
