-- AUTH: what the app submitted via /register. Pubkey IS the user id.
-- Re-registration = new row; current auth = max(created_at) per address.
CREATE TABLE IF NOT EXISTS registrations (
    burn_address bytea   NOT NULL CHECK (octet_length(burn_address) = 20),
    created_at   bigint  NOT NULL CHECK (created_at > 0),
    pubkey_x     bytea   NOT NULL CHECK (octet_length(pubkey_x) = 32),
    pubkey_y     bytea   NOT NULL CHECK (octet_length(pubkey_y) = 32),
    sig_r_x      bytea   NOT NULL CHECK (octet_length(sig_r_x) = 32),
    sig_r_y      bytea   NOT NULL CHECK (octet_length(sig_r_y) = 32),
    sig_z        bytea   NOT NULL CHECK (octet_length(sig_z) = 32),
    salt         bytea   NOT NULL CHECK (octet_length(salt) = 32),
    recipient    bytea   NOT NULL CHECK (octet_length(recipient) = 32),
    user_id      text    NOT NULL,
    PRIMARY KEY (burn_address, created_at)
);

CREATE INDEX idx_reg_user_id ON registrations(user_id);

-- Append-only guard (fires even for service_role/superuser).
CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is not allowed on %.% (append-only)',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_registrations_append_only
    BEFORE UPDATE OR DELETE ON registrations
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
