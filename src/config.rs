use alloy::primitives::Address;

pub struct Config {
    pub rpc_url: String,
    pub database_url: String,
    pub token: Address,
    pub verifier: Address,
    pub private_key: String,
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
        Ok(Self {
            rpc_url: std::env::var("RPC_URL")?,
            database_url: std::env::var("DATABASE_URL")?,
            token: deployed_address(chain_id, "zERC20")?,
            verifier: deployed_address(chain_id, "Verifier")?,
            private_key: std::env::var("PRIVATE_KEY")?,
            tweak: parse_tweak(&std::env::var("TWEAK")?)?,
            poll_interval_secs: std::env::var("POLL_INTERVAL_SECS")?.parse()?,
            port: std::env::var("PORT")?.parse()?,
            chain_id,
            last_block: deployment_block(chain_id, "zERC20")?,
        })
    }
}

fn parse_tweak(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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
