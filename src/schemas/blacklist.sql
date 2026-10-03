-- COMPLIANCE: deposits FROM these sender addresses are never credited.
-- Transfers still enter the hash chain / tree (the on-chain root requires them);
-- only the off-chain ledger credit is withheld. Mutable on purpose (no
-- append-only trigger) — operators must be able to remove entries.
CREATE TABLE IF NOT EXISTS blacklist (
    address    bytea  NOT NULL CHECK (octet_length(address) = 20),
    created_at bigint NOT NULL DEFAULT (extract(epoch from now())::bigint),
    reason     text,
    PRIMARY KEY (address)
);
