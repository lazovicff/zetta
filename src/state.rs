use std::collections::HashMap;

use ark_bn254::{Fq, Fr};
use ark_grumpkin::Projective as G2;

use crate::config::Config;
use crate::tree::{HashChain, MerkleTree, TREE_DEPTH};
use crate::zkp::RootTransitionWitness;

pub struct State {
    pub tree: MerkleTree,
    pub finalized_trees: Vec<MerkleTree>,
    pub chain: HashChain,
    pub chain_id: u64,
    pub exchange_addr: [u8; 20],
    pub tweak: [u8; 32],
    /// Registered burn-address pubkeys (P = x·G).
    pub pubkey_by_addr: HashMap<[u8; 20], G2>,
    /// Schnorr authorization for the current recipient: (R, z) per burn address.
    pub sig_by_addr: HashMap<[u8; 20], (G2, Fq)>,
    pub deposits: HashMap<[u8; 20], (Fr, usize, usize)>,
    pub pending: Option<(Vec<Fr>, Vec<RootTransitionWitness>)>,
}

impl State {
    pub fn new(
        config: &Config,
        chain_id: u64,
        exchange_addr: [u8; 20],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            tree: MerkleTree::new(TREE_DEPTH),
            finalized_trees: Vec::new(),
            chain: HashChain::new(),
            chain_id,
            exchange_addr,
            tweak: config.tweak,
            pubkey_by_addr: HashMap::new(),
            sig_by_addr: HashMap::new(),
            deposits: HashMap::new(),
            pending: None,
        })
    }
}
