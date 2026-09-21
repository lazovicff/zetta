use std::collections::{HashMap, VecDeque};

use alloy::primitives::U256;
use ark_bn254::{Fq, Fr};
use ark_grumpkin::Projective as G2;

use crate::config::Config;
use crate::tree::{HashChain, MerkleTree, TREE_DEPTH};

pub struct State {
    /// Single depth-32 ever-growing tree.
    pub tree: MerkleTree,
    pub chain: HashChain,
    /// Transfers fetched from chain, not yet inserted into the tree.
    /// Popped in FIFO order during commit.
    pub uncommitted_leaves: VecDeque<([u8; 20], Fr)>,
    /// Number of leaves proven on-chain via updateRoot.
    pub committed_index: u64,
    pub chain_id: u64,
    pub exchange_addr: [u8; 20],
    pub tweak: [u8; 32],
    /// Registered burn-address pubkeys (P = x·G).
    pub pubkey_by_addr: HashMap<[u8; 20], G2>,
    /// Schnorr authorization per burn address: (R, z).
    pub sig_by_addr: HashMap<[u8; 20], (G2, Fq)>,
    /// Burn-address derivation salt: burn = poseidon3(recipient, P.x, salt).
    pub salt_by_addr: HashMap<[u8; 20], Fr>,
    /// All deposits per burn address: (value, tree_index) per deposit.
    pub deposits: HashMap<[u8; 20], Vec<(Fr, usize)>>,
    /// Lifetime deposited value per address. Chain-derived; never trimmed.
    pub credits: HashMap<[u8; 20], U256>,
    /// Card issuance fee in basis points of `amount`.
    pub card_fee_bps: u64,
    /// Withdraw fee in basis points, taken out of the requested amount.
    pub withdraw_fee_bps: u64,
}

impl State {
    pub fn new(
        config: &Config,
        chain_id: u64,
        exchange_addr: [u8; 20],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            tree: MerkleTree::new(TREE_DEPTH),
            chain: HashChain::new(),
            uncommitted_leaves: VecDeque::new(),
            committed_index: 0,
            chain_id,
            exchange_addr,
            tweak: config.tweak,
            pubkey_by_addr: HashMap::new(),
            sig_by_addr: HashMap::new(),
            salt_by_addr: HashMap::new(),
            deposits: HashMap::new(),
            credits: HashMap::new(),
            card_fee_bps: config.card_fee_bps,
            withdraw_fee_bps: config.withdraw_fee_bps,
        })
    }
}
