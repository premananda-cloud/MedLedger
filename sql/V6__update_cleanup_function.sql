-- Add pending_registrations cleanup to the existing cleanup function
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
BEGIN
    -- Expire old shares
    PERFORM expire_old_shares();

    -- Delete old pending registrations (NEW)
    DELETE FROM pending_registrations
    WHERE expires_at < CURRENT_TIMESTAMP;

    -- Delete old audit logs (after 7 years)
    DELETE FROM audit_log
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '7 years';

    -- Delete old rate limit entries
    DELETE FROM rate_limit
    WHERE last_attempt < CURRENT_TIMESTAMP - INTERVAL '24 hours';

    -- Delete expired token revocations
    DELETE FROM token_revocations
    WHERE expires_at < CURRENT_TIMESTAMP;

    -- Delete expired refresh tokens
    DELETE FROM refresh_tokens
    WHERE expires_at < CURRENT_TIMESTAMP OR revoked_at IS NOT NULL;

    -- Delete expired PoW challenges
    DELETE FROM pow_challenges
    WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;
