//! Durable append-only log: registrations + card orders (PostgreSQL).
//! Tables are created externally. Deposits are NOT stored here —
//! they are chain facts, rebuilt by replay.

use alloy::primitives::U256;
use ark_bn254::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use sqlx::{PgPool, Row};

use crate::ids::user_id;

pub fn fr_to_blob<F: PrimeField>(x: F) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

pub fn blob_to_fr<F: PrimeField>(b: &[u8]) -> F {
    F::from_be_bytes_mod_order(b)
}

pub fn fr_to_u256(x: Fr) -> U256 {
    U256::from_be_slice(&fr_to_blob(x))
}

pub fn blob_to_u256(b: &[u8]) -> U256 {
    U256::from_be_slice(b)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Global advisory-lock key serializing spends (replaces SQLite's BEGIN IMMEDIATE).
const SPEND_LOCK_KEY: i64 = 0x5A45_5454_41; // "ZETTA"

#[derive(Clone, Debug)]
pub struct Registration {
    pub address: [u8; 20],
    pub created_at: i64,
    pub pubkey_x: Fr,
    pub pubkey_y: Fr,
    pub sig_r_x: Fr,
    pub sig_r_y: Fr,
    pub sig_z: Fq,
    pub salt: Fr,
    pub recipient: Fr,
    pub user_id: String,
}

#[derive(Clone)]
pub struct Db(PgPool);

const REG_COLS: &str = "burn_address, created_at, pubkey_x, pubkey_y, sig_r_x, sig_r_y, sig_z, salt, recipient, user_id";

fn row_to_registration(row: &sqlx::postgres::PgRow) -> Result<Registration, sqlx::Error> {
    let addr: Vec<u8> = row.try_get("burn_address")?;
    let address: [u8; 20] = addr
        .try_into()
        .map_err(|_| sqlx::Error::Decode("bad address length".into()))?;
    Ok(Registration {
        address,
        created_at: row.try_get("created_at")?,
        pubkey_x: blob_to_fr(&row.try_get::<Vec<u8>, _>("pubkey_x")?),
        pubkey_y: blob_to_fr(&row.try_get::<Vec<u8>, _>("pubkey_y")?),
        sig_r_x: blob_to_fr(&row.try_get::<Vec<u8>, _>("sig_r_x")?),
        sig_r_y: blob_to_fr(&row.try_get::<Vec<u8>, _>("sig_r_y")?),
        sig_z: blob_to_fr(&row.try_get::<Vec<u8>, _>("sig_z")?),
        salt: blob_to_fr(&row.try_get::<Vec<u8>, _>("salt")?),
        recipient: blob_to_fr(&row.try_get::<Vec<u8>, _>("recipient")?),
        user_id: row.try_get("user_id")?,
    })
}

impl Db {
    pub async fn open(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = PgPool::connect(url).await?;
        Ok(Self(pool))
    }

    pub async fn insert_registration(
        &self,
        r: &Registration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(&format!(
            "INSERT INTO registrations ({REG_COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        ))
        .bind(r.address.as_slice())
        .bind(r.created_at)
        .bind(fr_to_blob(r.pubkey_x))
        .bind(fr_to_blob(r.pubkey_y))
        .bind(fr_to_blob(r.sig_r_x))
        .bind(fr_to_blob(r.sig_r_y))
        .bind(fr_to_blob(r.sig_z))
        .bind(fr_to_blob(r.salt))
        .bind(fr_to_blob(r.recipient))
        .bind(&r.user_id)
        .execute(&self.0)
        .await?;
        Ok(())
    }

    /// Latest row per address — for boot-time hydration.
    pub async fn latest_registrations(
        &self,
    ) -> Result<Vec<Registration>, Box<dyn std::error::Error>> {
        let rows = sqlx::query(&format!(
            "SELECT {REG_COLS} FROM registrations r
             WHERE created_at = (
                 SELECT MAX(created_at) FROM registrations WHERE burn_address = r.burn_address
             )"
        ))
        .fetch_all(&self.0)
        .await?;
        let regs = rows
            .iter()
            .map(row_to_registration)
            .collect::<Result<Vec<Registration>, sqlx::Error>>()?;
        Ok(regs)
    }

    pub async fn latest_registration_by_pubkey(
        &self,
        pubkey_x: Fr,
    ) -> Result<Option<Registration>, Box<dyn std::error::Error>> {
        let row = sqlx::query(&format!(
            "SELECT {REG_COLS} FROM registrations
             WHERE pubkey_x = $1 ORDER BY created_at DESC LIMIT 1"
        ))
        .bind(fr_to_blob(pubkey_x))
        .fetch_optional(&self.0)
        .await?;
        row.as_ref()
            .map(row_to_registration)
            .transpose()
            .map_err(Into::into)
    }

    pub async fn latest_registration_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<Registration>, Box<dyn std::error::Error>> {
        let row = sqlx::query(&format!(
            "SELECT {REG_COLS} FROM registrations
             WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1"
        ))
        .bind(user_id)
        .fetch_optional(&self.0)
        .await?;
        row.as_ref()
            .map(row_to_registration)
            .transpose()
            .map_err(Into::into)
    }

    pub async fn total_spent(&self, pubkey_x: Fr) -> Result<U256, Box<dyn std::error::Error>> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (provider_ref) amount, status
             FROM card_orders
             WHERE pubkey_x = $1
             ORDER BY provider_ref, id DESC",
        )
        .bind(fr_to_blob(pubkey_x))
        .fetch_all(&self.0)
        .await?;
        let mut total = U256::ZERO;
        for r in &rows {
            let status: String = r.try_get("status")?;
            if status != "failed" {
                let amount: Vec<u8> = r.try_get("amount")?;
                total += blob_to_u256(&amount);
            }
        }
        Ok(total)
    }

    /// Atomically check lifetime balance and record a spend.
    /// `available` = lifetime deposits for this pubkey (chain-derived, passed in).
    /// Returns the new lifetime spend total.
    pub async fn try_spend(
        &self,
        pubkey_x: Fr,
        amount: U256,
        available: U256,
        provider: &str,
        provider_ref: &str,
    ) -> Result<U256, String> {
        // A global advisory xact lock replaces SQLite's BEGIN IMMEDIATE: no two
        // orders can pass the balance check concurrently.
        let mut tx = self.0.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(SPEND_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        let rows = sqlx::query(
            "SELECT DISTINCT ON (provider_ref) amount, status
             FROM card_orders
             WHERE pubkey_x = $1
             ORDER BY provider_ref, id DESC",
        )
        .bind(fr_to_blob(pubkey_x))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        let mut spent = U256::ZERO;
        for r in &rows {
            let status: String = r.try_get("status").map_err(|e| e.to_string())?;
            if status != "failed" {
                let amount: Vec<u8> = r.try_get("amount").map_err(|e| e.to_string())?;
                spent += blob_to_u256(&amount);
            }
        }

        let new_spent = spent + amount;
        if new_spent > available {
            return Err(format!(
                "insufficient balance: available {available}, spent {spent}, requested {amount}"
            ));
        }

        let amount_bytes: [u8; 32] = amount.to_be_bytes();
        sqlx::query(
            "INSERT INTO card_orders (pubkey_x, user_id, amount, provider, provider_ref, status, created_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', $6)",
        )
        .bind(fr_to_blob(pubkey_x))
        .bind(user_id(pubkey_x))
        .bind(amount_bytes.as_slice())
        .bind(provider)
        .bind(provider_ref)
        .bind(unix_now())
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(new_spent)
    }

    /// Append a 'succeeded'/'failed' transition to an order still in 'pending'.
    pub async fn settle_order(
        &self,
        provider_ref: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), String> {
        let res = sqlx::query(
            "INSERT INTO card_orders (pubkey_x, user_id, amount, provider, provider_ref, status, error, created_at, resolved_at)
             SELECT pubkey_x, user_id, amount, provider, provider_ref, $1, $2, created_at, $3
             FROM card_orders
             WHERE provider_ref = $4
               AND id = (SELECT MAX(id) FROM card_orders WHERE provider_ref = $4)
               AND status = 'pending'",
        )
        .bind(status)
        .bind(error)
        .bind(unix_now())
        .bind(provider_ref)
        .execute(&self.0)
        .await
        .map_err(|e| e.to_string())?;
        if res.rows_affected() != 1 {
            return Err(format!("order {provider_ref} not pending (or missing)"));
        }
        Ok(())
    }
}
