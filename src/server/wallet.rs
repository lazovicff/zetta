//! Operator wallet: a Privy server wallet. Key material lives in Privy's TEE;
//! this process only holds API credentials. Signs (SIWE, EIP-3009 digests) and
//! broadcasts contract calls via the wallet RPC — Privy fills nonce/gas and
//! sends through its relay, so this cannot point at localhost (anvil); use a
//! testnet in dev.
//!
//! Written against privy-rs 0.1.0-alpha.6 — the generated API churns between
//! alphas, keep the pin exact in Cargo.toml: privy-rs = "=0.1.0-alpha.6".

use alloy::primitives::{Address, B256, Bytes};
use privy_rs::generated::types::{
    Hex, Quantity, UnsignedStandardEthereumTransaction, WalletRpcResponse,
};
use privy_rs::{AuthorizationContext, PrivyClient};

#[derive(Clone)]
pub struct Wallet {
    client: std::sync::Arc<PrivyClient>,
    wallet_id: String,
    address: Address,
    chain_id: u64,
    caip2: String,
}

impl Wallet {
    pub fn new(
        app_id: &str,
        app_secret: &str,
        wallet_id: &str,
        address: Address,
        chain_id: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            client: std::sync::Arc::new(PrivyClient::new(
                app_id.to_string(),
                app_secret.to_string(),
            )?),
            wallet_id: wallet_id.to_string(),
            address,
            chain_id,
            caip2: format!("eip155:{chain_id}"),
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// EIP-191 personal_sign → 0x-prefixed 65-byte hex sig (same shape as alloy's Display).
    pub async fn sign_message(&self, msg: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = AuthorizationContext::new();
        let r = self
            .client
            .wallets()
            .ethereum()
            .sign_message(&self.wallet_id, std::str::from_utf8(msg)?, &ctx, None)
            .await?
            .into_inner();
        match r {
            WalletRpcResponse::EthereumPersonalSignRpcResponse(resp) => {
                Ok(String::from(resp.data.signature))
            }
            other => Err(format!("unexpected rpc response: {other:?}").into()),
        }
    }

    /// Raw secp256k1 sign over a 32-byte digest (EIP-3009 x402 path in laso.rs).
    pub async fn sign_hash(&self, digest: &B256) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = AuthorizationContext::new();
        let r = self
            .client
            .wallets()
            .ethereum()
            .sign_secp256k1(&self.wallet_id, &digest.to_string(), &ctx, None)
            .await?
            .into_inner();
        match r {
            WalletRpcResponse::EthereumSecp256k1SignRpcResponse(resp) => {
                Ok(String::from(resp.data.signature))
            }
            other => Err(format!("unexpected rpc response: {other:?}").into()),
        }
    }

    /// Broadcast a contract call; returns the tx hash once relayed.
    pub async fn send_tx(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<B256, Box<dyn std::error::Error>> {
        let ctx = AuthorizationContext::new();
        let tx = UnsignedStandardEthereumTransaction {
            to: Some(to.to_string()),
            data: Some(Hex::try_from(format!("0x{}", hex::encode(&data)))?),
            chain_id: Some(Quantity::Integer(self.chain_id as i64)),
            ..Default::default()
        };
        let r = self
            .client
            .wallets()
            .ethereum()
            .send_transaction(&self.wallet_id, &self.caip2, tx.into(), &ctx, None)
            .await?
            .into_inner();
        match r {
            WalletRpcResponse::EthereumSendTransactionRpcResponse(resp) => {
                Ok(String::from(resp.data.hash).parse()?)
            }
            other => Err(format!("unexpected rpc response: {other:?}").into()),
        }
    }

    /// Broadcast a contract-creation tx; returns the tx hash once relayed.
    pub async fn deploy_tx(&self, initcode: Bytes) -> Result<B256, Box<dyn std::error::Error>> {
        let ctx = AuthorizationContext::new();
        let tx = UnsignedStandardEthereumTransaction {
            to: None, // contract creation
            data: Some(Hex::try_from(format!("0x{}", hex::encode(&initcode)))?),
            chain_id: Some(Quantity::Integer(self.chain_id as i64)),
            ..Default::default()
        };
        let r = self
            .client
            .wallets()
            .ethereum()
            .send_transaction(&self.wallet_id, &self.caip2, tx.into(), &ctx, None)
            .await?
            .into_inner();
        match r {
            WalletRpcResponse::EthereumSendTransactionRpcResponse(resp) => {
                Ok(String::from(resp.data.hash).parse()?)
            }
            other => Err(format!("unexpected rpc response: {other:?}").into()),
        }
    }
}
