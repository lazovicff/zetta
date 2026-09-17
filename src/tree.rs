//! Poseidon Merkle tree + on-chain hash-chain mirror (Phase B).

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::zkp::{poseidon2, poseidon3};

pub const TREE_DEPTH: usize = 18;
pub const TREE_CAPACITY: usize = 1 << TREE_DEPTH; // 262144

/// Append-only Poseidon binary Merkle tree.
pub struct MerkleTree {
    depth: usize,
    leaves: Vec<Fr>,
    zero_hashes: Vec<Fr>,     // zero_hashes[h] = empty subtree of height h
    filled_subtrees: Vec<Fr>, // filled_subtrees[h] = rightmost complete subtree of height h
    root: Fr,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zero_hashes = Vec::with_capacity(depth + 1);
        let mut z = poseidon2(Fr::zero(), Fr::zero()).expect("poseidon");
        zero_hashes.push(z);
        for _ in 0..depth {
            z = poseidon2(z, z).expect("poseidon");
            zero_hashes.push(z);
        }
        let root = zero_hashes[depth];
        Self {
            depth,
            leaves: Vec::new(),
            zero_hashes,
            filled_subtrees: vec![Fr::zero(); depth],
            root,
        }
    }

    pub fn root(&self) -> Fr {
        self.root
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Append a leaf; returns the new root. O(depth) — updates only the path
    /// from the inserted leaf to the root.
    pub fn insert(&mut self, leaf: Fr) -> Fr {
        let index = self.leaves.len();
        self.leaves.push(leaf);

        let mut current = leaf;
        let mut idx = index;
        for h in 0..self.depth {
            if idx & 1 == 0 {
                // Left child: right sibling is empty; record this node as the
                // level's filled left subtree for a future right child.
                self.filled_subtrees[h] = current;
                current = poseidon2(current, self.zero_hashes[h]).expect("poseidon");
            } else {
                // Right child: combine with the stored left sibling.
                current = poseidon2(self.filled_subtrees[h], current).expect("poseidon");
            }
            idx >>= 1;
        }
        self.root = current;
        self.root
    }

    /// Siblings from leaf level up to root (length == depth).
    pub fn proof(&self, index: usize) -> Vec<Fr> {
        assert!(index < self.leaves.len(), "index out of range");
        let mut proof = Vec::with_capacity(self.depth);
        let mut idx = index;
        let mut level = self.leaves.clone();
        let mut h = 0;
        while h < self.depth {
            let sibling = if (idx ^ 1) < level.len() {
                level[idx ^ 1]
            } else {
                self.zero_hashes[h]
            };
            proof.push(sibling);
            idx >>= 1;
            level = next_level(&level, self.zero_hashes[h]);
            h += 1;
        }
        proof
    }

    /// Siblings for the (empty) leaf at `index`, where `index == self.len()`.
    pub fn proof_for_empty(&self, index: usize) -> Vec<Fr> {
        assert_eq!(
            index,
            self.leaves.len(),
            "index must be the next empty slot"
        );
        let mut proof = Vec::with_capacity(self.depth);
        let mut idx = index;
        let mut level = self.leaves.clone();
        let mut h = 0;
        while h < self.depth {
            let sibling = if (idx ^ 1) < level.len() {
                level[idx ^ 1]
            } else {
                self.zero_hashes[h]
            };
            proof.push(sibling);
            idx >>= 1;
            level = next_level(&level, self.zero_hashes[h]);
            h += 1;
        }
        proof
    }
}

fn next_level(level: &[Fr], zero: Fr) -> Vec<Fr> {
    let mut next = Vec::with_capacity((level.len() + 1) / 2);
    for i in (0..level.len()).step_by(2) {
        let left = level[i];
        let right = if i + 1 < level.len() {
            level[i + 1]
        } else {
            zero
        };
        next.push(poseidon2(left, right).expect("poseidon"));
    }
    next
}

/// One hash-chain step: `poseidon3(prev, address_to_fr(to), value)`.
pub fn hash_chain_step(prev: Fr, to: [u8; 20], value: Fr) -> Fr {
    poseidon3(prev, crate::burn::address_to_fr(to), value).expect("poseidon")
}

/// Off-chain mirror of the on-chain `burnHashChain`.
#[derive(Default)]
pub struct HashChain {
    state: Fr,
    index: u64,
}

impl HashChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> Fr {
        self.state
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    /// Apply one transfer; returns the new state.
    pub fn apply(&mut self, to: [u8; 20], value: Fr) -> Fr {
        self.state = hash_chain_step(self.state, to, value);
        self.index += 1;
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify a Merkle proof for `leaf` at `index` against `root`.
    pub fn verify_proof(leaf: Fr, index: usize, proof: &[Fr], root: Fr) -> bool {
        let mut h = leaf;
        let mut idx = index;
        for &sibling in proof {
            h = if idx & 1 == 0 {
                poseidon2(h, sibling).expect("poseidon")
            } else {
                poseidon2(sibling, h).expect("poseidon")
            };
            idx >>= 1;
        }
        h == root
    }

    #[test]
    fn empty_tree_root_is_zero_hash() {
        let tree = MerkleTree::new(32);
        let mut z = poseidon2(Fr::zero(), Fr::zero()).unwrap();
        for _ in 0..32 {
            z = poseidon2(z, z).unwrap();
        }
        assert_eq!(tree.root(), z);
    }

    #[test]
    fn insert_and_verify_proofs() {
        let mut tree = MerkleTree::new(32);
        let leaves: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 1)).collect();
        for &l in &leaves {
            tree.insert(l);
        }
        let root = tree.root();
        for (i, &l) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert_eq!(proof.len(), 32);
            assert!(verify_proof(l, i, &proof, root));
        }
        // tampered leaf fails
        assert!(!verify_proof(Fr::from(999u64), 0, &tree.proof(0), root));
    }

    #[test]
    fn hash_chain_deterministic_and_in_range() {
        let mut chain = HashChain::new();
        let s0 = chain.apply([0x11u8; 20], Fr::from(100u64));
        let s1 = chain.apply([0x22u8; 20], Fr::from(200u64));
        assert_eq!(chain.index(), 2);
        // deterministic
        let mut chain2 = HashChain::new();
        chain2.apply([0x11u8; 20], Fr::from(100u64));
        chain2.apply([0x22u8; 20], Fr::from(200u64));
        assert_eq!(chain2.state(), chain.state());
        // different input -> different state
        assert_ne!(s0, s1);
    }

    #[test]
    fn print_constants() {
        let tree = MerkleTree::new(TREE_DEPTH);
        println!("INITIAL_ROOT = {}", tree.root());
        let hc = hash_chain_step(Fr::zero(), [0x01u8; 20], Fr::from(100u64));
        println!("CANONICAL_HASH_CHAIN = {}", hc);
    }
}
