use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_grumpkin::constraints::GVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::tree::TREE_DEPTH;
use crate::zkp::{WithdrawWitness, merkle_root_var, poseidon2_var, poseidon3_var, schnorr_verify};

/// Single-withdrawal Groth16 circuit (no Nova folding).
/// Public inputs: [transferRoot, recipient, indexWithOffset, value].
/// Proves one receipt: Schnorr ownership + Merkle membership + range checks.
#[derive(Clone, Debug)]
pub struct SingleWithdrawCircuit {
    pub transfer_root: Fr,
    pub recipient: Fr,
    pub index_with_offset: Fr,
    pub witness: WithdrawWitness, // value == public input (sum)
}

impl Default for SingleWithdrawCircuit {
    fn default() -> Self {
        Self {
            transfer_root: Fr::zero(),
            recipient: Fr::zero(),
            index_with_offset: Fr::zero(),
            witness: WithdrawWitness::default(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for SingleWithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs (order must match what the contract passes to verifyProof).
        let transfer_root = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.transfer_root))?;
        let recipient = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.recipient))?;
        let index_with_offset = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.index_with_offset))?;
        let value = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.witness.value))?;

        // Witness.
        let w = self.witness;
        let pubkey = GVar::new_witness(cs.clone(), || Ok(w.pubkey))?;
        let sig_r = GVar::new_witness(cs.clone(), || Ok(w.sig_r))?;
        let z_bits = w.sig_z.into_bigint().to_bits_le();
        let mut sig_z_bits = Vec::with_capacity(z_bits.len());
        for bit in z_bits {
            sig_z_bits.push(Boolean::<Fr>::new_witness(cs.clone(), || Ok(bit))?);
        }
        let salt = FpVar::<Fr>::new_witness(cs.clone(), || Ok(w.salt))?;
        let index = FpVar::<Fr>::new_witness(cs.clone(), || Ok(w.index))?;
        let merkle_path = <[FpVar<Fr>; TREE_DEPTH] as AllocVar<[Fr; TREE_DEPTH], Fr>>::new_witness(
            cs.clone(),
            || Ok(w.merkle_path),
        )?;

        // address = low160(poseidon3(recipient, x(P), salt))
        let pk_aff = pubkey.to_affine()?;
        let burn = poseidon3_var(recipient.clone(), pk_aff.x, salt)?;
        let burn_bits = burn.to_bits_le()?;
        let address = Boolean::le_bits_to_fp(&burn_bits[0..160])?;

        // Schnorr verify (proves the user authorized this address).
        schnorr_verify(&pubkey, &sig_r, &sig_z_bits, recipient.clone())?;

        // leaf = poseidon2(address, value)
        let leaf = poseidon2_var(address, value.clone())?;

        // transferRoot == merkle_root(localIndex, leaf, merkle_path)
        let (index_bits, _) = index.to_bits_le_with_top_bits_zero(40)?;
        let local_index = Boolean::le_bits_to_fp(&index_bits[..TREE_DEPTH])?;
        let root = merkle_root_var(local_index, leaf, &merkle_path)?;
        root.enforce_equal(&transfer_root)?;

        // index >= indexWithOffset (both global)
        let diff = index - index_with_offset;
        let _ = diff.to_bits_le_with_top_bits_zero(40)?;

        // value < 2^248, recipient < 2^246
        let _ = value.to_bits_le_with_top_bits_zero(248)?;
        let _ = recipient.to_bits_le_with_top_bits_zero(246)?;

        Ok(())
    }
}
