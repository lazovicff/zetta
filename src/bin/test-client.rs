//! Load-test client: generates grumpkin keypairs, registers burn addresses,
//! deposits small amounts, and polls per-key balances from the server.

use std::time::Duration;

use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use ark_bn254::{Fq, Fr};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_grumpkin::{Affine as G2Affine, Projective as G2};
use clap::Parser;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};

use zetta::burn::trim_to_160;
use zetta::zkp::poseidon3;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 value) external returns (bool);
    }
}

#[derive(Parser)]
#[command(name = "test-client")]
struct Args {
    /// Server base URL.
    #[arg(long, default_value = "http://localhost:3000")]
    server_url: String,

    /// Chain RPC URL.
    #[arg(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Chain id, used to locate the deploy broadcast file (from .env `CHAIN_ID`).
    #[arg(long, env = "CHAIN_ID", default_value = "31337")]
    chain_id: u64,

    /// Private key holding deposit funds (from .env `CLIENT_PRIVATE_KEY`).
    #[arg(
        long,
        env = "CLIENT_PRIVATE_KEY",
        default_value = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    )]
    private_key: String,

    /// Number of signing keys to create.
    #[arg(long, default_value = "2")]
    num_keys: usize,

    /// Burn addresses to register per key, per round.
    #[arg(long, default_value = "2")]
    addresses_per_key: usize,

    /// Seconds between rounds.
    #[arg(long, default_value = "5")]
    interval_secs: u64,

    /// Minimum deposit amount (raw token units).
    #[arg(long, default_value = "1")]
    min_deposit: u128,

    /// Maximum deposit amount (raw token units).
    #[arg(long, default_value = "100")]
    max_deposit: u128,
}

#[derive(Serialize)]
struct RegisterRequest {
    address: String,
    pubkey: (String, String),
    sig_r: (String, String),
    sig_z: String,
    salt: String,
}

#[derive(Deserialize)]
struct RecipientResponse {
    recipient: String,
}

#[derive(Deserialize)]
struct BalanceResponse {
    #[allow(dead_code)]
    pubkey_x: String,
    #[allow(dead_code)]
    deposited: String,
    #[allow(dead_code)]
    spent: String,
    balance: String,
}

struct SigningKey {
    secret: Fq,
    pubkey: G2Affine,
}

fn parse_fr(s: &str) -> Fr {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).expect("invalid decimal");
    Fr::from_be_bytes_mod_order(&n.to_bytes_be())
}

fn generate_key(rng: &mut impl RngCore) -> SigningKey {
    let secret = Fq::rand(rng);
    let pubkey = (G2::generator() * secret).into_affine();
    SigningKey { secret, pubkey }
}

/// Schnorr signature matching the server's verification in `register_inner`:
///   R = k·G,  e = poseidon3(R.x, P.x, recipient),  z = k + e·x  (over Fq).
fn schnorr_sign(
    secret: Fq,
    pubkey: G2Affine,
    recipient: Fr,
    rng: &mut impl RngCore,
) -> (G2Affine, Fq) {
    let k = Fq::rand(rng);
    let sig_r = (G2::generator() * k).into_affine();
    let e_fr = poseidon3(sig_r.x, pubkey.x, recipient).expect("poseidon3");
    let e = Fq::from_be_bytes_mod_order(&e_fr.into_bigint().to_bytes_be());
    let sig_z = k + e * secret;
    (sig_r, sig_z)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let args = Args::parse();

    let signer: PrivateKeySigner = args.private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(args.rpc_url.parse()?);
    let token = IERC20::new(
        zetta::config::deployed_address(args.chain_id, "zERC20")?,
        &provider,
    );

    let client = reqwest::Client::new();

    // Recipient is constant per (chain_id, exchange_addr, tweak), and it is required
    // to derive burn addresses and signatures — so retry until the server is reachable
    // instead of exiting.
    let recipient: Fr = loop {
        match client
            .get(format!("{}/recipient", args.server_url))
            .send()
            .await
        {
            Ok(resp) => match resp.json::<RecipientResponse>().await {
                Ok(r) => break parse_fr(&r.recipient),
                Err(e) => {
                    eprintln!(
                        "recipient decode failed ({e}); retrying in {}s",
                        args.interval_secs
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "server unreachable while fetching recipient ({e}); retrying in {}s",
                    args.interval_secs
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(args.interval_secs)).await;
    };

    let mut rng = OsRng;
    let keys: Vec<SigningKey> = (0..args.num_keys).map(|_| generate_key(&mut rng)).collect();
    println!("generated {} keys", keys.len());

    loop {
        // 1. register burn addresses + deposit (deposit ONLY after a successful register)
        for key in &keys {
            for _ in 0..args.addresses_per_key {
                let salt = Fr::rand(&mut rng);
                let burn = poseidon3(recipient, key.pubkey.x, salt).expect("poseidon3");
                let addr = trim_to_160(burn);
                let addr_hex = format!("0x{}", hex::encode(addr));

                let (sig_r, sig_z) = schnorr_sign(key.secret, key.pubkey, recipient, &mut rng);

                let req = RegisterRequest {
                    address: addr_hex.clone(),
                    pubkey: (key.pubkey.x.to_string(), key.pubkey.y.to_string()),
                    sig_r: (sig_r.x.to_string(), sig_r.y.to_string()),
                    sig_z: sig_z.to_string(),
                    salt: salt.to_string(),
                };

                // A connection failure here means the server is down: skip the deposit
                // entirely (we must not deposit without a successful registration).
                let resp = match client
                    .post(format!("{}/register", args.server_url))
                    .json(&req)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "server unreachable while registering {addr_hex} ({e}); skipping deposit"
                        );
                        continue;
                    }
                };

                if resp.status().is_success() {
                    let amount: u128 = rng.gen_range(args.min_deposit..=args.max_deposit);
                    match token
                        .transfer(Address::from(addr), U256::from(amount))
                        .send()
                        .await
                    {
                        Ok(pending) => match pending.register().await {
                            Ok(_) => println!("registered + deposited {amount} to {addr_hex}"),
                            Err(e) => eprintln!("deposit tx not confirmed for {addr_hex}: {e}"),
                        },
                        Err(e) => eprintln!("deposit tx failed for {addr_hex}: {e}"),
                    }
                } else {
                    eprintln!(
                        "register failed for {addr_hex}: {}",
                        resp.text().await.unwrap_or_default()
                    );
                }
            }
        }

        // 2. report balances (best-effort; never exit on failure)
        for (i, key) in keys.iter().enumerate() {
            let result = client
                .get(format!(
                    "{}/balance/{}",
                    args.server_url,
                    key.pubkey.x.to_string()
                ))
                .send()
                .await
                .and_then(|r| r.error_for_status());

            match result {
                Ok(resp) => match resp.json::<BalanceResponse>().await {
                    Ok(b) => println!("key {i} balance = {} wei", b.balance),
                    Err(e) => eprintln!("balance decode failed for key {i}: {e}"),
                },
                Err(e) => eprintln!("balance request failed for key {i}: {e}"),
            }
        }

        tokio::time::sleep(Duration::from_secs(args.interval_secs)).await;
    }
}
