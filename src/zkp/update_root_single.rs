use ark_bn254::Fr;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::tree::TREE_DEPTH;
use crate::zkp::{RootTransitionWitness, hash_chain_step_var, merkle_root_var, poseidon2_var};

/// Single-leaf root transition (no Nova folding).
/// Public inputs: [prevIndex, prevHashChain, prevRoot, newIndex, newHashChain, newRoot].
#[derive(Clone, Debug, Default)]
pub struct SingleRootTransitionCircuit {
    pub z_0: [Fr; 3],
    pub z_1: [Fr; 3],
    pub witness: RootTransitionWitness,
}

impl ConstraintSynthesizer<Fr> for SingleRootTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prev_index = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.z_0[0]))?;
        let prev_chain = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.z_0[1]))?;
        let prev_root = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.z_0[2]))?;
        let new_index = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.z_1[0]))?;
        let new_chain = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.z_1[1]))?;
        let new_root = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.z_1[2]))?;

        let to = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.witness.to))?;
        let value = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.witness.value))?;
        let merkle_path = <[FpVar<Fr>; TREE_DEPTH] as AllocVar<[Fr; TREE_DEPTH], Fr>>::new_witness(
            cs.clone(),
            || Ok(self.witness.merkle_path),
        )?;

        // newIndex == prevIndex + 1
        new_index.enforce_equal(&(prev_index.clone() + FpVar::<Fr>::one()))?;

        // newHashChain == hash_chain_step(prevHashChain, to, value)
        hash_chain_step_var(prev_chain, to.clone(), value.clone())?.enforce_equal(&new_chain)?;

        // prevRoot == merkle_root(prevIndex, poseidon2(0,0), path)  (slot was empty)
        let empty_leaf = poseidon2_var(FpVar::<Fr>::zero(), FpVar::<Fr>::zero())?;
        merkle_root_var(prev_index.clone(), empty_leaf, &merkle_path)?.enforce_equal(&prev_root)?;

        // newRoot == merkle_root(prevIndex, poseidon2(to, value), path)
        let leaf = poseidon2_var(to, value)?;
        merkle_root_var(prev_index, leaf, &merkle_path)?.enforce_equal(&new_root)?;

        Ok(())
    }
}
