use std::{borrow::Borrow, marker::PhantomData};

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::{Error, frontend::FCircuit};

use crate::{tree::TREE_DEPTH, zkp::poseidon2_var};

pub fn hash_chain_step_var(
    prev: FpVar<Fr>,
    to: FpVar<Fr>,
    value: FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    crate::zkp::poseidon3_var(prev, to, value)
}

/// In-circuit Merkle root: hash `leaf` up `siblings` (depth 32), using `index` bits.
pub fn merkle_root_var(
    index: FpVar<Fr>,
    leaf: FpVar<Fr>,
    siblings: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let (index_bits, _) = index.to_bits_le_with_top_bits_zero(siblings.len())?;
    let mut h = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        let bit = &index_bits[level];
        // bit=0 -> left: poseidon2(h, sibling); bit=1 -> right: poseidon2(sibling, h)
        let a = bit.select(sibling, &h)?;
        let b = bit.select(&h, sibling)?;
        h = poseidon2_var(a, b)?;
    }
    Ok(h)
}

#[derive(Clone, Debug)]
pub struct RootTransitionWitness {
    pub to: Fr,
    pub value: Fr,
    pub merkle_path: [Fr; TREE_DEPTH],
}

impl Default for RootTransitionWitness {
    fn default() -> Self {
        Self {
            to: Fr::zero(),
            value: Fr::zero(),
            merkle_path: [Fr::zero(); TREE_DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct RootTransitionWitnessVar {
    pub to: FpVar<Fr>,
    pub value: FpVar<Fr>,
    pub merkle_path: [FpVar<Fr>; TREE_DEPTH],
}

impl AllocVar<RootTransitionWitness, Fr> for RootTransitionWitnessVar {
    fn new_variable<T: Borrow<RootTransitionWitness>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let w = f()?;
        let w = w.borrow();
        Ok(Self {
            to: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.to), mode)?,
            value: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.value), mode)?,
            merkle_path: <[FpVar<Fr>; TREE_DEPTH] as AllocVar<[Fr; TREE_DEPTH], Fr>>::new_variable(
                cs.clone(),
                || Ok(w.merkle_path),
                mode,
            )?,
        })
    }
}

/// Root-transition step circuit: one step per transfer.
/// State z_i = [index, hashChain, transferRoot].
/// Witness per step = [to, value, merkle_path[0..32]].
#[derive(Clone, Copy, Debug)]
pub struct RootTransitionCircuit {
    _f: PhantomData<Fr>,
}

impl FCircuit<Fr> for RootTransitionCircuit {
    type Params = ();
    type ExternalInputs = RootTransitionWitness;
    type ExternalInputsVar = RootTransitionWitnessVar;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        _: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let index = z_i[0].clone();
        let hash_chain = z_i[1].clone();
        let transfer_root = z_i[2].clone();

        let to = external_inputs.to;
        let value = external_inputs.value;
        let merkle_path = &external_inputs.merkle_path;

        // index' = index + 1
        let index_next = index.clone() + FpVar::<Fr>::one();

        // hashChain' = hash_chain_step(hashChain, to, value)
        let hash_chain_next = hash_chain_step_var(hash_chain, to.clone(), value.clone())?;

        // empty leaf = poseidon2(0, 0)
        let empty_leaf = poseidon2_var(FpVar::<Fr>::zero(), FpVar::<Fr>::zero())?;

        // old root = merkle_root(index, empty_leaf, merkle_path); enforce == transfer_root
        let old_root = merkle_root_var(index.clone(), empty_leaf, merkle_path)?;
        old_root.enforce_equal(&transfer_root)?;

        // new leaf = poseidon2(to, value)
        let new_leaf = poseidon2_var(to, value)?;

        // new root = merkle_root(index, new_leaf, merkle_path)
        let new_root = merkle_root_var(index, new_leaf, merkle_path)?;

        Ok(vec![index_next, hash_chain_next, new_root])
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::One;
    use ark_r1cs_std::GR1CSVar;

    use crate::zkp::poseidon2;

    use super::*;

    #[test]
    fn hash_chain_step_var_matches_native() {
        use crate::burn::address_to_fr;
        use crate::tree::hash_chain_step;
        use ark_relations::gr1cs::ConstraintSystem;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let prev = Fr::from(12345u64);
        let to = [0x11u8; 20];
        let value = Fr::from(100u64);

        let prev_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(prev)).unwrap();
        let to_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(address_to_fr(to))).unwrap();
        let value_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(value)).unwrap();

        let h_var = hash_chain_step_var(prev_var, to_var, value_var).unwrap();
        let h_native = hash_chain_step(prev, to, value);
        assert_eq!(h_var.value().unwrap(), h_native);
    }

    #[test]
    fn merkle_root_var_matches_native() {
        use crate::tree::MerkleTree;
        use ark_relations::gr1cs::ConstraintSystem;

        let mut tree = MerkleTree::new(32);
        let leaves: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 1)).collect();
        for &l in &leaves {
            tree.insert(l);
        }
        let root = tree.root();

        let cs = ConstraintSystem::<Fr>::new_ref();
        for (i, &leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            let index_var =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(i as u64))).unwrap();
            let leaf_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(leaf)).unwrap();
            let siblings_var: Vec<FpVar<Fr>> = proof
                .iter()
                .map(|s| FpVar::<Fr>::new_witness(cs.clone(), || Ok(*s)).unwrap())
                .collect();
            let root_var = merkle_root_var(index_var, leaf_var, &siblings_var).unwrap();
            assert_eq!(root_var.value().unwrap(), root);
        }
    }

    fn compute_root(leaf: Fr, index: usize, siblings: &[Fr]) -> Fr {
        let mut h = leaf;
        let mut idx = index;
        for &sibling in siblings {
            h = if idx & 1 == 0 {
                poseidon2(h, sibling).unwrap()
            } else {
                poseidon2(sibling, h).unwrap()
            };
            idx >>= 1;
        }
        h
    }

    #[test]
    fn root_transition_circuit_matches_native() {
        use crate::burn::address_to_fr;
        use crate::tree::{MerkleTree, hash_chain_step};
        use ark_relations::gr1cs::ConstraintSystem;

        let transfers = [
            ([0x01u8; 20], 100u64),
            ([0x02u8; 20], 200u64),
            ([0x03u8; 20], 300u64),
        ];

        let mut tree = MerkleTree::new(32);
        let mut leaves = Vec::new();
        for (to, val) in transfers {
            let leaf = poseidon2(address_to_fr(to), Fr::from(val)).unwrap();
            leaves.push(leaf);
            tree.insert(leaf);
        }

        let initial_root = MerkleTree::new(32).root();
        let mut index = Fr::zero();
        let mut hash_chain = Fr::zero();
        let mut transfer_root = initial_root;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = RootTransitionCircuit::new(()).unwrap();

        for (i, (to, val)) in transfers.iter().enumerate() {
            let proof = tree.proof(i);
            let leaf = leaves[i];

            let mut merkle_path = [Fr::zero(); TREE_DEPTH];
            merkle_path.copy_from_slice(&proof);
            let witness = RootTransitionWitness {
                to: address_to_fr(*to),
                value: Fr::from(*val),
                merkle_path,
            };

            let index_next = index + Fr::one();
            let hash_chain_next = hash_chain_step(hash_chain, *to, Fr::from(*val));
            let new_root = compute_root(leaf, i, &proof);

            let z_i = vec![index, hash_chain, transfer_root];
            let z_i_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i.clone())).unwrap();
            let witness_var =
                RootTransitionWitnessVar::new_witness(cs.clone(), || Ok(witness)).unwrap();
            let z_next_var = circuit
                .generate_step_constraints(cs.clone(), i, z_i_var, witness_var)
                .unwrap();

            assert_eq!(z_next_var[0].value().unwrap(), index_next);
            assert_eq!(z_next_var[1].value().unwrap(), hash_chain_next);
            assert_eq!(z_next_var[2].value().unwrap(), new_root);

            index = index_next;
            hash_chain = hash_chain_next;
            transfer_root = new_root;
        }
    }
}
