-- migrations/audit_log_immutability.sql
--
-- Run ONCE on a PostgreSQL deployment to enforce audit-log immutability at the
-- database level, independent of the application layer.
--
-- What this does:
--   1. Creates a dedicated role `medledger_app` that can INSERT but not
--      UPDATE or DELETE audit_logs rows.
--   2. Enables Row-Level Security on audit_logs.
--   3. Revokes UPDATE/DELETE from the application role.
--   4. Grants only SELECT + INSERT to the application role.
--
-- The application connects as `medledger_app`.  A separate `medledger_admin`
-- role (used only for migrations/break-glass) can still UPDATE/DELETE if
-- needed for legal compliance (e.g. GDPR right-to-erasure — discuss with
-- counsel before ever running DELETE on audit rows).
--
-- Usage:
--   psql -U postgres -d medledger -f migrations/audit_log_immutability.sql

-- ── 1. Create application role (skip if it already exists) ───────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'medledger_app') THEN
        CREATE ROLE medledger_app LOGIN PASSWORD 'CHANGE_THIS_IN_VAULT';
    END IF;
END
$$;

-- ── 2. Grant schema + table access ───────────────────────────────────────────
GRANT CONNECT ON DATABASE medledger TO medledger_app;
GRANT USAGE ON SCHEMA public TO medledger_app;

-- All tables: SELECT + INSERT only (UPDATE/DELETE never granted)
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO medledger_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO medledger_app;

-- ── 3. Hard-revoke UPDATE and DELETE on audit_logs ───────────────────────────
-- Even if a future GRANT ALL is run by mistake, explicit REVOKEs take precedence.
REVOKE UPDATE, DELETE ON audit_logs FROM medledger_app;
REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;

-- ── 4. Enable Row-Level Security (belt-and-suspenders) ───────────────────────
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

-- Allow the app role to see and insert its own rows
CREATE POLICY audit_insert_policy ON audit_logs
    FOR INSERT TO medledger_app
    WITH CHECK (true);

CREATE POLICY audit_select_policy ON audit_logs
    FOR SELECT TO medledger_app
    USING (true);

-- No UPDATE or DELETE policy is created, so both are denied by default.

-- ── 5. Prevent table-structure changes by the app role ───────────────────────
REVOKE ALL ON audit_logs FROM medledger_app;
GRANT SELECT, INSERT ON audit_logs TO medledger_app;

-- ── Verification ─────────────────────────────────────────────────────────────
-- After running, verify:
--   \dp audit_logs           → should show no UPDATE/DELETE for medledger_app
--   \d audit_logs            → RLS should be enabled
