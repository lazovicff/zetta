use std::collections::HashMap;

use ark_bn254::Fr;

use crate::burn::{recipient, trim_to_160};
use crate::config::Config;
use crate::tree::{HashChain, MerkleTree, TREE_DEPTH};
use crate::zkp::{RootTransitionWitness, poseidon2};

pub struct State {
    pub tree: MerkleTree,                 // current tree (being built)
    pub finalized_trees: Vec<MerkleTree>, // finalized trees (for Merkle proofs)
    pub chain: HashChain,                 // global hash chain
    pub chain_id: u64,
    pub exchange_addr: [u8; 20],
    pub tweak: [u8; 32],
    pub secrets: Vec<Fr>,
    pub burn_addresses: Vec<[u8; 20]>,
    pub secret_by_addr: HashMap<[u8; 20], Fr>,
    pub next_index: usize,
    /// burn_address -> (value, rootIndex, treeIndex)
    pub deposits: HashMap<[u8; 20], (Fr, usize, usize)>,
    pub pending: Option<(Vec<Fr>, Vec<RootTransitionWitness>)>,
}

impl State {
    pub fn new(
        config: &Config,
        chain_id: u64,
        exchange_addr: [u8; 20],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let recipient = recipient(chain_id, exchange_addr, config.tweak);
        let mut burn_addresses = Vec::with_capacity(config.secrets.len());
        let mut secret_by_addr = HashMap::new();
        for &secret in &config.secrets {
            let burn = poseidon2(recipient, secret)?;
            let addr = trim_to_160(burn);
            burn_addresses.push(addr);
            secret_by_addr.insert(addr, secret);
        }
        Ok(Self {
            tree: MerkleTree::new(TREE_DEPTH),
            finalized_trees: Vec::new(),
            chain: HashChain::new(),
            chain_id,
            exchange_addr,
            tweak: config.tweak,
            secrets: config.secrets.clone(),
            burn_addresses,
            secret_by_addr,
            next_index: 0,
            deposits: HashMap::new(),
            pending: None,
        })
    }

    /// Rotate to a fresh tweak and regenerate burn addresses (same secrets).
    pub fn rotate_tweak(&mut self, new_tweak: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        self.tweak = new_tweak;
        let recipient = recipient(self.chain_id, self.exchange_addr, self.tweak);
        self.burn_addresses.clear();
        self.secret_by_addr.clear();
        for &secret in &self.secrets {
            let burn = poseidon2(recipient, secret)?;
            let addr = trim_to_160(burn);
            self.burn_addresses.push(addr);
            self.secret_by_addr.insert(addr, secret);
        }
        self.next_index = 0;
        self.deposits.clear();
        Ok(())
    }
}
