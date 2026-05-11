-- Vigil dev-postgres init script.
--
-- Mounted into /docker-entrypoint-initdb.d/ by deploy/docker-compose.yml.
-- Runs once, when the Postgres data dir is first initialised.
--
-- Why this exists: the manager's runtime DB role `edr` must NOT be a
-- Postgres superuser. The M16.a audit_log hardening (REVOKE
-- UPDATE/DELETE/TRUNCATE) is invisible to a superuser — they bypass
-- all GRANT/REVOKE checks. Previously the compose set
-- `POSTGRES_USER: edr` which made `edr` the bootstrap superuser; the
-- bootstrap user cannot be demoted (`ALTER ROLE … NOSUPERUSER` refuses
-- with "The bootstrap user must have the SUPERUSER attribute"). The
-- only way out is to bootstrap as a different user (`postgres`) and
-- create `edr` separately as non-superuser. That's what this script
-- does.
--
-- After this runs:
--   * `postgres`           superuser, owns nothing important
--   * `edr`                non-superuser, CREATEROLE, owns the `edr`
--                          database; manager connects as this user
--   * audit_log ownership  still held by `edr` after Alembic creates
--                          the table; the M16.a (fixed) migration
--                          transfers it to `vigil_audit_writer`

CREATE ROLE edr LOGIN PASSWORD 'vigil_dev_password' NOSUPERUSER CREATEROLE NOCREATEDB INHERIT;

-- The `edr` database was created by POSTGRES_DB and is owned by
-- `postgres`. Transfer ownership so the manager can create / alter
-- tables in it without superuser. `postgres` is a member of every
-- role (it's the cluster superuser) so this ALTER works.
ALTER DATABASE edr OWNER TO edr;
GRANT CONNECT ON DATABASE edr TO edr;
