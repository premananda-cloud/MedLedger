-- Fix generate_user_id_hex trigger to accept base64url (frontend format)
-- Frontend sends base64url without padding; PostgreSQL decode() wants standard base64 with padding

CREATE OR REPLACE FUNCTION generate_user_id_hex()
RETURNS TRIGGER AS $$
DECLARE
    b64_key TEXT;
BEGIN
    IF NEW.signing_public_key IS NOT NULL AND NEW.user_id_hex IS NULL THEN
        -- Convert base64url to standard base64 for PostgreSQL decode()
        b64_key := replace(replace(NEW.signing_public_key, '-', '+'), '_', '/');
        -- Add padding if missing (base64 length must be multiple of 4)
        b64_key := b64_key || substring('===', 1, (4 - length(b64_key) % 4) % 4);
        
        NEW.user_id_hex := encode(
            sha256(decode(b64_key, 'base64')::bytea),
            'hex'
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
