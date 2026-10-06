//! Deploy the zUSDC stack via the Privy operator wallet:
//!   PoseidonT4 (library) -> zERC20 -> USDCVault -> decider verifiers -> Verifier,
//! then setVerifiers / setMinter / setVerifier, then write the forge-compatible
//! broadcast JSON that Config reads. Run `forge build` first.
//!
//! Env: PRIVY_APP_ID · PRIVY_APP_SECRET · PRIVY_WALLET_ID · PRIVY_WALLET_ADDRESS
//!      RPC_URL · CHAIN_ID (84532 Base Sepolia) · USDC_ADDRESS (per-chain default)

use std::collections::HashMap;
use std::time::Duration;

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use serde_json::{Value, json};
use tracing::info;

use zetta::server::db::fr_to_u256;
use zetta::server::wallet::Wallet;
use zetta::tree::{MerkleTree, TREE_DEPTH};

sol! {
    interface IAdmin {
        function setMinter(address m) external;
        function setVerifier(address v) external;
        function setVerifiers(address root, address withdraw, address singleWithdraw, address singleRoot) external;
    }
}

/// Empty depth-32 Poseidon tree root; recomputed below, this literal only
/// cross-checks the Poseidon parameterization matches Deploy.s.sol.
const EXPECTED_INITIAL_ROOT: &str =
    "7694308195910501081009121293114024464085863242234210875116972222894508088593";

fn env(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(key).map_err(|_| format!("missing env {key}").into())
}

fn usdc_address(chain_id: u64) -> Result<Address, Box<dyn std::error::Error>> {
    if let Ok(a) = std::env::var("USDC_ADDRESS") {
        return Ok(a.parse()?);
    }
    match chain_id {
        84532 => Ok("0x036CbD53842c5426634e7929541eC2318f3dCF7e".parse()?), // Base Sepolia
        8453 => Ok("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".parse()?),  // Base mainnet
        _ => Err("USDC_ADDRESS env required for this chain".into()),
    }
}

fn artifact(name: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let p = format!("contracts/out/{name}.sol/{name}.json");
    Ok(serde_json::from_str(
        &std::fs::read_to_string(&p)
            .map_err(|e| format!("read {p}: {e} — run `forge build` first"))?,
    )?)
}

/// Initcode with library placeholders patched to deployed addresses.
fn bytecode(
    name: &str,
    libs: &HashMap<String, Address>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let a = artifact(name)?;
    let mut code = a["bytecode"]["object"]
        .as_str()
        .ok_or("bytecode.object missing")?
        .trim_start_matches("0x")
        .to_string();
    if let Some(files) = a["bytecode"]["linkReferences"].as_object() {
        for (_file, lib_refs) in files {
            for (lib, ranges) in lib_refs.as_object().ok_or("bad linkReferences")? {
                let addr = libs
                    .get(lib.as_str())
                    .ok_or_else(|| format!("{name} needs library {lib} — deploy it first"))?;
                let addr_hex = hex::encode(addr.into_array());
                for r in ranges.as_array().ok_or("bad link range")? {
                    let start = r["start"].as_u64().ok_or("bad link start")? as usize * 2;
                    let len = r["length"].as_u64().ok_or("bad link len")? as usize * 2;
                    if len != 40 {
                        return Err("unexpected link reference length".into());
                    }
                    code.get_mut(start..start + len)
                        .ok_or("link reference out of bounds")?;
                    code.replace_range(start..start + len, &addr_hex);
                }
            }
        }
    }
    if code.contains('$') {
        return Err(format!("{name}: unresolved link references remain").into());
    }
    Ok(hex::decode(code)?)
}

async fn wait_receipt(
    provider: &impl Provider,
    hash: B256,
) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
    for _ in 0..90 {
        if let Some(rc) = provider.get_transaction_receipt(hash).await? {
            return Ok(rc);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(format!("tx {hash} not mined after 180s").into())
}

async fn deploy(
    wallet: &Wallet,
    provider: &impl Provider,
    name: &str,
    libs: &HashMap<String, Address>,
    ctor_args: Vec<u8>,
    txs: &mut Vec<Value>,
    receipts: &mut Vec<Value>,
) -> Result<Address, Box<dyn std::error::Error>> {
    let mut initcode = bytecode(name, libs)?;
    initcode.extend_from_slice(&ctor_args);
    let hash = wallet.deploy_tx(Bytes::from(initcode)).await?;
    let rc = wait_receipt(provider, hash).await?;
    let addr = rc
        .contract_address
        .ok_or("receipt without contract address")?;
    if !rc.status() {
        return Err(format!("{name} deployment reverted in {hash}").into());
    }
    info!(stage = "deploy", contract = name, address = %addr, "deployed");
    txs.push(json!({
        "transactionType": "CREATE",
        "contractName": name,
        "contractAddress": format!("{addr}"),
        "hash": format!("{hash}"),
    }));
    receipts.push(json!({
        "transactionHash": format!("{hash}"),
        "blockNumber": format!("{:#x}", rc.block_number.ok_or("receipt without block")?),
    }));
    Ok(addr)
}

async fn call(
    wallet: &Wallet,
    provider: &impl Provider,
    label: &str,
    to: Address,
    data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash = wallet.send_tx(to, Bytes::from(data)).await?;
    let rc = wait_receipt(provider, hash).await?;
    if !rc.status() {
        return Err(format!("{label} reverted in {hash}").into());
    }
    info!(stage = "wire", call = label, tx = %hash, "confirmed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    dotenv::dotenv().ok();

    let chain_id: u64 = env("CHAIN_ID")?.parse()?;
    let provider = ProviderBuilder::new().connect_http(env("RPC_URL")?.parse()?);
    if provider.get_chain_id().await? != chain_id {
        return Err("CHAIN_ID does not match RPC_URL network".into());
    }
    let wallet = Wallet::new(
        &env("PRIVY_APP_ID")?,
        &env("PRIVY_APP_SECRET")?,
        &env("PRIVY_WALLET_ID")?,
        env("PRIVY_WALLET_ADDRESS")?.parse()?,
        chain_id,
    )?;
    info!(stage = "boot", chain = chain_id, operator = %wallet.address(), "deploying");

    let initial_root = fr_to_u256(MerkleTree::new(TREE_DEPTH).root());
    if initial_root != EXPECTED_INITIAL_ROOT.parse::<U256>()? {
        return Err("empty-tree root mismatch — Poseidon params drifted".into());
    }

    let mut txs = Vec::new();
    let mut receipts = Vec::new();
    let mut libs = HashMap::new();

    // 1. Poseidon library (zERC20 links against its public hash()).
    let poseidon_t4 = deploy(
        &wallet,
        &provider,
        "PoseidonT4",
        &libs,
        vec![],
        &mut txs,
        &mut receipts,
    )
    .await?;
    libs.insert("PoseidonT4".to_string(), poseidon_t4);

    // 2. Token. Deployer is owner; minter/verifier bootstrap to deployer.
    let token = deploy(
        &wallet,
        &provider,
        "zERC20",
        &libs,
        ("Zetta USDC".to_string(), "zUSDC".to_string()).abi_encode_params(),
        &mut txs,
        &mut receipts,
    )
    .await?;

    // 3. USDC vault.
    let usdc = usdc_address(chain_id)?;
    let vault = deploy(
        &wallet,
        &provider,
        "USDCVault",
        &libs,
        (usdc, token).abi_encode_params(),
        &mut txs,
        &mut receipts,
    )
    .await?;

    // 4. Decider verifiers (stateless, no ctor args).
    let root_v = deploy(
        &wallet,
        &provider,
        "RootTransitionVerifier",
        &libs,
        vec![],
        &mut txs,
        &mut receipts,
    )
    .await?;
    let withdraw_v = deploy(
        &wallet,
        &provider,
        "WithdrawVerifier",
        &libs,
        vec![],
        &mut txs,
        &mut receipts,
    )
    .await?;
    let single_withdraw_v = deploy(
        &wallet,
        &provider,
        "SingleWithdrawVerifier",
        &libs,
        vec![],
        &mut txs,
        &mut receipts,
    )
    .await?;
    let single_root_v = deploy(
        &wallet,
        &provider,
        "SingleRootTransitionVerifier",
        &libs,
        vec![],
        &mut txs,
        &mut receipts,
    )
    .await?;

    // 5. Verifier (genesis: empty tree, no prev in current contract).
    let verifier = deploy(
        &wallet,
        &provider,
        "Verifier",
        &libs,
        (token, initial_root).abi_encode_params(),
        &mut txs,
        &mut receipts,
    )
    .await?;

    // 6. Wire roles.
    call(
        &wallet,
        &provider,
        "Verifier.setVerifiers",
        verifier,
        IAdmin::setVerifiersCall {
            root: root_v,
            withdraw: withdraw_v,
            singleWithdraw: single_withdraw_v,
            singleRoot: single_root_v,
        }
        .abi_encode(),
    )
    .await?;
    call(
        &wallet,
        &provider,
        "zERC20.setMinter",
        token,
        IAdmin::setMinterCall { m: vault }.abi_encode(),
    )
    .await?;
    call(
        &wallet,
        &provider,
        "zERC20.setVerifier",
        token,
        IAdmin::setVerifierCall { v: verifier }.abi_encode(),
    )
    .await?;

    // 7. Forge-compatible broadcast output for Config.
    let dir = format!("broadcast/Deploy.s.sol/{chain_id}");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        format!("{dir}/run-latest.json"),
        serde_json::to_string_pretty(&json!({ "transactions": txs, "receipts": receipts }))?,
    )?;

    info!(
        stage = "done",
        usdc = %usdc, token = %token, vault = %vault, verifier = %verifier,
        "deployment complete"
    );
    info!(
        stage = "done",
        "next: fund the operator wallet with USDC, then transfer token/verifier ownership to the multisig (transferOwnership → acceptOwnership)"
    );
    Ok(())
}
