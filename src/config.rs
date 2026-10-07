use alloy::primitives::Address;

pub struct Config {
    pub rpc_url: String,
    pub database_url: String,
    /// Card provider base URL (mock-laso in dev, https://laso.finance in prod).
    pub laso_url: String,
    pub token: Address,
    pub verifier: Address,
    pub vault: Address,
    pub tweak: [u8; 32],
    pub poll_interval_secs: u64,
    pub port: u16,
    pub chain_id: u64,
    pub last_block: u64,
    // Privy wallet credentials
    pub privy_app_id: String,
    pub privy_app_secret: String,
    pub privy_wallet_id: String,
    pub wallet_address: Address,
    /// Max unique registered pubkeys; new users are rejected at/above this.
    pub max_users: i64,
    /// Max non-failed card orders per user within `card_limit_window_days`.
    pub max_cards_per_user: i64,
    /// Rolling window (days) for the per-user card-issuance limit.
    pub card_limit_window_days: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv::dotenv().ok();
        let chain_id: u64 = std::env::var("CHAIN_ID")?.parse()?;
        Ok(Self {
            rpc_url: std::env::var("RPC_URL")?,
            database_url: std::env::var("DATABASE_URL")?,
            laso_url: std::env::var("LASO_URL")?,
            token: deployed_address(chain_id, "zERC20")?,
            verifier: deployed_address(chain_id, "Verifier")?,
            vault: deployed_address(chain_id, "USDCVault")?,
            privy_app_id: std::env::var("PRIVY_APP_ID")?,
            privy_app_secret: std::env::var("PRIVY_APP_SECRET")?,
            privy_wallet_id: std::env::var("PRIVY_WALLET_ID")?,
            wallet_address: std::env::var("PRIVY_WALLET_ADDRESS")?.parse()?,
            tweak: parse_tweak(&std::env::var("TWEAK")?)?,
            poll_interval_secs: std::env::var("POLL_INTERVAL_SECS")?.parse()?,
            port: std::env::var("PORT")?.parse()?,
            chain_id,
            last_block: deployment_block(chain_id, "zERC20")?,
            max_users: std::env::var("MAX_USERS")?.parse()?,
            max_cards_per_user: std::env::var("MAX_CARDS_PER_USER")?.parse()?,
            card_limit_window_days: std::env::var("CARD_LIMIT_WINDOW_DAYS")?.parse()?,
        })
    }
}

/// TWEAK is a decimal integer ("0", "1", ...), encoded big-endian into 32 bytes.
fn parse_tweak(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let n = alloy::primitives::U256::from_str_radix(s.trim(), 10)?;
    Ok(n.to_be_bytes::<32>())
}

fn load_broadcast(chain_id: u64) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = format!("broadcast/Deploy.s.sol/{chain_id}/run-latest.json");
    Ok(serde_json::from_str(&std::fs::read_to_string(&path)?)?)
}

/// Address of a CREATE'd contract from `forge script --broadcast`.
pub fn deployed_address(
    chain_id: u64,
    contract_name: &str,
) -> Result<Address, Box<dyn std::error::Error>> {
    let json = load_broadcast(chain_id)?;
    let addr = json["transactions"]
        .as_array()
        .ok_or("no transactions in broadcast")?
        .iter()
        .find(|tx| tx["transactionType"] == "CREATE" && tx["contractName"] == contract_name)
        .and_then(|tx| tx["contractAddress"].as_str())
        .ok_or_else(|| format!("no {contract_name} deployment in broadcast"))?;
    Ok(addr.parse()?)
}

/// Block number of the deployment tx for a contract.
pub fn deployment_block(
    chain_id: u64,
    contract_name: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let json = load_broadcast(chain_id)?;
    let hash = json["transactions"]
        .as_array()
        .ok_or("no transactions in broadcast")?
        .iter()
        .find(|tx| tx["transactionType"] == "CREATE" && tx["contractName"] == contract_name)
        .and_then(|tx| tx["hash"].as_str())
        .ok_or_else(|| format!("no {contract_name} deployment in broadcast"))?;
    let block_hex = json["receipts"]
        .as_array()
        .ok_or("no receipts in broadcast")?
        .iter()
        .find(|r| r["transactionHash"].as_str() == Some(hash))
        .and_then(|r| r["blockNumber"].as_str())
        .ok_or("no receipt for deployment")?;
    Ok(u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?)
}
