use crate::tree::TREE_DEPTH;
use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::{Error, frontend::FCircuit};
use std::borrow::Borrow;

use crate::zkp::{merkle_root_var, poseidon2_var};

#[derive(Clone, Debug)]
pub struct WithdrawParams {
    pub pow_bits: u32,
}

#[derive(Clone, Debug)]
pub struct WithdrawWitness {
    pub secret: Fr,
    pub value: Fr,
    pub index: Fr,
    pub merkle_path: [Fr; TREE_DEPTH],
}

impl Default for WithdrawWitness {
    fn default() -> Self {
        Self {
            secret: Fr::zero(),
            value: Fr::zero(),
            index: Fr::zero(),
            merkle_path: [Fr::zero(); TREE_DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawWitnessVar {
    pub secret: FpVar<Fr>,
    pub value: FpVar<Fr>,
    pub index: FpVar<Fr>,
    pub merkle_path: [FpVar<Fr>; TREE_DEPTH],
}

impl AllocVar<WithdrawWitness, Fr> for WithdrawWitnessVar {
    fn new_variable<T: Borrow<WithdrawWitness>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let w = f()?;
        let w = w.borrow();
        Ok(Self {
            secret: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.secret), mode)?,
            value: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.value), mode)?,
            index: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.index), mode)?,
            merkle_path: <[FpVar<Fr>; TREE_DEPTH] as AllocVar<[Fr; TREE_DEPTH], Fr>>::new_variable(
                cs.clone(),
                || Ok(w.merkle_path),
                mode,
            )?,
        })
    }
}

/// Withdraw step circuit: one step per receipt.
/// State z = [indexWithOffset, totalValue, transferRoot, recipient].
/// transferRoot and recipient are fixed publics (constant across steps).
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    pow_bits: u32,
}

impl FCircuit<Fr> for WithdrawCircuit {
    type Params = WithdrawParams;
    type ExternalInputs = WithdrawWitness;
    type ExternalInputsVar = WithdrawWitnessVar;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            pow_bits: params.pow_bits,
        })
    }

    fn state_len(&self) -> usize {
        4
    }

    fn generate_step_constraints(
        &self,
        _: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let index_with_offset = z_i[0].clone();
        let total_value = z_i[1].clone();
        let transfer_root = z_i[2].clone();
        let recipient = z_i[3].clone();

        let secret = external_inputs.secret;
        let value = external_inputs.value;
        let index = external_inputs.index;
        let merkle_path = &external_inputs.merkle_path;

        // burn = poseidon(recipient, secret)
        let burn = poseidon2_var(recipient.clone(), secret)?;

        // enforce PoW bits [160, 160+n) zero
        let burn_bits = burn.to_bits_le()?;
        for bit in &burn_bits[160..160 + self.pow_bits as usize] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }

        // burn address = lower 160 bits (matches on-chain `to`)
        let burn_addr = Boolean::le_bits_to_fp(&burn_bits[0..160])?;

        // leaf = poseidon(burn_addr, value)
        let leaf = poseidon2_var(burn_addr, value.clone())?;

        // transferRoot == getRoot(index, leaf, merkle_path)
        let root = merkle_root_var(index.clone(), leaf, merkle_path)?;
        root.enforce_equal(&transfer_root)?;

        // index + 1 > indexWithOffset  (strictly increasing)
        let diff = index.clone() - index_with_offset.clone();
        let _ = diff.to_bits_le_with_top_bits_zero(32)?;

        // value < 2^248
        let _ = value.to_bits_le_with_top_bits_zero(248)?;

        // recipient < 2^246
        let _ = recipient.to_bits_le_with_top_bits_zero(246)?;

        // state transition
        let index_with_offset_next = index + FpVar::<Fr>::one();
        let total_value_next = total_value + value;

        Ok(vec![
            index_with_offset_next,
            total_value_next,
            transfer_root,
            recipient,
        ])
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::One;
    use ark_r1cs_std::GR1CSVar;

    use crate::zkp::poseidon2;

    use super::*;

    #[test]
    fn withdraw_circuit_matches_native() {
        use crate::burn::{find_burn_address, recipient};
        use crate::tree::MerkleTree;
        use ark_relations::gr1cs::ConstraintSystem;

        let recipient = recipient(31337, [0x11u8; 20], [0x22u8; 32]);
        let pow_bits = 8u32; // small for test speed
        let (_burn_addr, secret) = find_burn_address(recipient, pow_bits);

        let value = Fr::from(100u64);
        let burn = poseidon2(recipient, secret).unwrap();
        let burn_addr = crate::burn::address_to_fr(crate::burn::trim_to_160(burn));
        let leaf = poseidon2(burn_addr, value).unwrap();

        let mut tree = MerkleTree::new(32);
        tree.insert(leaf);
        let transfer_root = tree.root();
        let proof = tree.proof(0);

        let z_i = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];

        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        let witness = WithdrawWitness {
            secret,
            value,
            index: Fr::zero(),
            merkle_path,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = WithdrawCircuit::new(WithdrawParams { pow_bits }).unwrap();
        let z_i_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i.clone())).unwrap();
        let witness_var = WithdrawWitnessVar::new_witness(cs.clone(), || Ok(witness)).unwrap();
        let z_next_var = circuit
            .generate_step_constraints(cs.clone(), 0, z_i_var, witness_var)
            .unwrap();

        assert_eq!(z_next_var[0].value().unwrap(), Fr::one());
        assert_eq!(z_next_var[1].value().unwrap(), value);
        assert_eq!(z_next_var[2].value().unwrap(), transfer_root);
        assert_eq!(z_next_var[3].value().unwrap(), recipient);
    }
}
