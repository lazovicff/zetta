-- AUTH: what the app submitted via /register. Pubkey IS the user id.
-- Re-registration = new row; current auth = max(created_at) per address.
CREATE TABLE IF NOT EXISTS registrations (
    burn_address BLOB NOT NULL CHECK (length(burn_address) = 20),
    created_at   INTEGER NOT NULL CHECK (created_at > 0),
    pubkey_x     BLOB NOT NULL CHECK (length(pubkey_x) = 32),
    pubkey_y     BLOB NOT NULL CHECK (length(pubkey_y) = 32),
    sig_r_x      BLOB NOT NULL CHECK (length(sig_r_x) = 32),
    sig_r_y      BLOB NOT NULL CHECK (length(sig_r_y) = 32),
    sig_z        BLOB NOT NULL CHECK (length(sig_z) = 32),
    recipient    BLOB NOT NULL CHECK (length(recipient) = 32),
    expiry       INTEGER NOT NULL CHECK (expiry >= 0),   -- global burn index; u64-range forever
    PRIMARY KEY (burn_address, created_at)
) STRICT;

CREATE INDEX idx_reg_current ON registrations(burn_address, created_at DESC);

-- SPEND: one row per issued card. One-way, so order == spend.
CREATE TABLE IF NOT EXISTS card_orders (
    id           INTEGER PRIMARY KEY,
    pubkey_x     BLOB NOT NULL CHECK (length(pubkey_x) = 32),
    amount       BLOB NOT NULL CHECK (length(amount) = 32),
    provider     TEXT NOT NULL,
    provider_ref TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'succeeded', 'failed')),
    error        TEXT,                       -- provider failure reason, if any
    created_at   INTEGER NOT NULL CHECK (created_at > 0),
    resolved_at  INTEGER
) STRICT;


CREATE INDEX idx_card_orders_pubkey ON card_orders(pubkey_x);
