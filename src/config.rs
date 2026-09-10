use alloy::primitives::Address;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;

pub struct Config {
    pub rpc_url: String,
    pub token: Address,
    pub verifier: Address,
    pub private_key: String,
    pub secrets: Vec<Fr>,
    pub tweak: [u8; 32],
    pub poll_interval_secs: u64,
    pub port: u16,
    pub chain_id: u64,
    pub last_block: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv::dotenv().ok();
        let chain_id: u64 = std::env::var("CHAIN_ID")?.parse()?;
        let last_block = load_deployment_block(chain_id)?;
        Ok(Self {
            rpc_url: std::env::var("RPC_URL")?,
            token: std::env::var("TOKEN")?.parse()?,
            verifier: std::env::var("VERIFIER")?.parse()?,
            private_key: std::env::var("PRIVATE_KEY")?,
            secrets: parse_secrets(&std::env::var("SECRETS")?)?,
            tweak: parse_tweak(&std::env::var("TWEAK")?)?,
            poll_interval_secs: std::env::var("POLL_INTERVAL_SECS")?.parse()?,
            port: std::env::var("PORT")?.parse()?,
            chain_id,
            last_block,
        })
    }
}

fn parse_secrets(s: &str) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| {
            let n = BigUint::parse_bytes(x.as_bytes(), 10).ok_or("invalid secret decimal")?;
            Ok(Fr::from_be_bytes_mod_order(&n.to_bytes_be()))
        })
        .collect()
}

fn parse_tweak(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_deployment_block(chain_id: u64) -> Result<u64, Box<dyn std::error::Error>> {
    let path = format!("broadcast/Deploy.s.sol/{chain_id}/run-latest.json");
    let content = std::fs::read_to_string(&path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;
    let block = json["transactions"]
        .as_array()
        .ok_or("no transactions in broadcast")?
        .iter()
        .find(|tx| tx["contractName"] == "zERC20")
        .and_then(|tx| tx["blockNumber"].as_u64())
        .ok_or("no zERC20 deployment in broadcast")?;
    Ok(block)
}
