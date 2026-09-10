//! Watch Transfer events, maintain hash chain + tree (Phase E).

use crate::burn::{address_to_fr, poseidon2};
use crate::tree::{HashChain, MerkleTree};
use alloy::sol_types::SolEvent;
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    transports::ws::WsConnect,
};
use ark_ff::PrimeField;
use futures_util::StreamExt;

sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
}

pub struct Indexer {
    pub tree: MerkleTree,
    pub chain: HashChain,
}

impl Indexer {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(32),
            chain: HashChain::new(),
        }
    }

    /// Apply one transfer (from != 0x0) to the tree + hash chain.
    pub fn apply(&mut self, to: Address, value: U256) {
        let to_bytes: [u8; 20] = to.into_array();
        let value_fr = u256_to_fr(value);
        let leaf = poseidon2(address_to_fr(to_bytes), value_fr).expect("poseidon");
        self.tree.insert(leaf);
        self.chain.apply(to_bytes, value_fr);
    }
}

fn u256_to_fr(v: U256) -> ark_bn254::Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    ark_bn254::Fr::from_be_bytes_mod_order(&bytes)
}

pub async fn run(ws_url: &str, token: Address) -> Result<(), Box<dyn std::error::Error>> {
    let ws = WsConnect::new(ws_url);
    let provider = ProviderBuilder::new().connect_ws(ws).await?;

    let filter = Filter::new()
        .address(token)
        .event_signature(Transfer::SIGNATURE_HASH);
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    let mut indexer = Indexer::new();

    while let Some(log) = stream.next().await {
        let decoded = log.log_decode::<Transfer>()?;
        let d = decoded.data();
        if d.from.is_zero() {
            continue; // mint — excluded from tree
        }
        indexer.apply(d.to, d.value);
        println!(
            "index={} root={} hashChain={}",
            indexer.chain.index(),
            indexer.tree.root(),
            indexer.chain.state()
        );
    }
    Ok(())
}
