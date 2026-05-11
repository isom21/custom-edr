-- Vigil dev-postgres init script.
--
-- Mounted into /docker-entrypoint-initdb.d/ by deploy/docker-compose.yml.
-- Runs once, when the Postgres data dir is first initialised.
--
-- Why this exists: the manager's runtime DB role `vigil_manager` must
-- NOT be a Postgres superuser. The M16.a audit_log hardening (REVOKE
-- UPDATE/DELETE/TRUNCATE) is invisible to a superuser — they bypass
-- all GRANT/REVOKE checks. The bootstrap superuser (the one created
-- by initdb) can't be demoted (`ALTER ROLE … NOSUPERUSER` refuses
-- with "The bootstrap user must have the SUPERUSER attribute"). The
-- only way out is to bootstrap as a different user (`postgres`) and
-- create the runtime role separately as non-superuser. That's what
-- this script does.
--
-- After this runs:
--   * `postgres`           superuser, owns nothing important
--   * `vigil_manager`      non-superuser, CREATEROLE, owns the `vigil`
--                          database; manager connects as this user
--   * audit_log ownership  still held by `vigil_manager` after Alembic
--                          creates the table; the M16.a (fixed)
--                          migration transfers it to `vigil_audit_writer`

CREATE ROLE vigil_manager LOGIN PASSWORD 'vigil_dev_password' NOSUPERUSER CREATEROLE NOCREATEDB INHERIT;

-- The `vigil` database was created by POSTGRES_DB and is owned by
-- `postgres`. Transfer ownership so the manager can create / alter
-- tables in it without superuser. `postgres` is a member of every
-- role (it's the cluster superuser) so this ALTER works.
ALTER DATABASE vigil OWNER TO vigil_manager;
GRANT CONNECT ON DATABASE vigil TO vigil_manager;
