-- Drop dependent views first
DROP VIEW IF EXISTS v_user_share_stats;
DROP VIEW IF EXISTS v_active_shares;
DROP VIEW IF EXISTS v_vault_stats;

-- Now alter the column
ALTER TABLE users ALTER COLUMN user_id_hex TYPE VARCHAR(64);

-- Recreate the views (copy from V1 schema)
CREATE OR REPLACE VIEW v_active_shares AS
SELECT
    s.share_id,
    s.short_code,
    u1.username as owner_username,
    u2.username as grantee_username,
    s.filename,
    s.mime_type,
    s.size_bytes,
    s.created_at,
    s.expires_at,
    s.delete_on_download,
    s.status
FROM active_shares s
JOIN users u1 ON s.owner_user_id_hex = u1.user_id_hex
JOIN users u2 ON s.grantee_user_id_hex = u2.user_id_hex
WHERE s.status = 'active';

CREATE OR REPLACE VIEW v_user_share_stats AS
SELECT
    u.user_id_hex,
    u.username,
    COUNT(DISTINCT s_owned.share_id) as shares_created,
    COUNT(DISTINCT s_received.share_id) as shares_received,
    COALESCE(SUM(s_owned.size_bytes), 0) as total_bytes_shared,
    MAX(s_owned.created_at) as last_share_created
FROM users u
LEFT JOIN active_shares s_owned ON u.user_id_hex = s_owned.owner_user_id_hex AND s_owned.status = 'active'
LEFT JOIN active_shares s_received ON u.user_id_hex = s_received.grantee_user_id_hex AND s_received.status = 'active'
WHERE u.account_deleted = FALSE
GROUP BY u.user_id_hex, u.username;

CREATE OR REPLACE VIEW v_vault_stats AS
SELECT
    u.username,
    u.user_id_hex,
    COUNT(v.record_id) as total_files,
    COALESCE(SUM(v.size_bytes), 0) as total_bytes,
    COUNT(DISTINCT g.grant_id) as total_grants_given,
    MAX(v.created_at) as last_upload
FROM users u
LEFT JOIN vault_records v ON u.user_id_hex = v.owner_user_id_hex
LEFT JOIN grants g ON v.record_id = g.record_id AND g.revoked = FALSE
WHERE u.account_deleted = FALSE
GROUP BY u.user_id_hex, u.username;
