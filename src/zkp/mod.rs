mod poseidon;
mod update_root;
mod withdraw;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use folding_schemes::commitment::kzg::KZG;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::decider_eth::Decider as DeciderEth;
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, FoldingScheme};

pub use poseidon::*;
pub use update_root::*;
pub use withdraw::*;

use solidity_verifiers::NovaCycleFoldVerifierKey;
use solidity_verifiers::calldata::{
    NovaVerificationMode, prepare_calldata_for_nova_cyclefold_verifier,
};
use solidity_verifiers::verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider;

type RootN = Nova<G1, G2, RootTransitionCircuit, KZG<'static, Bn254>, Pedersen<G2>, false>;
type RootD = DeciderEth<
    G1,
    G2,
    RootTransitionCircuit,
    KZG<'static, Bn254>,
    Pedersen<G2>,
    Groth16<Bn254>,
    RootN,
>;
type WithdrawN = Nova<G1, G2, WithdrawCircuit, KZG<'static, Bn254>, Pedersen<G2>, false>;
type WithdrawD = DeciderEth<
    G1,
    G2,
    WithdrawCircuit,
    KZG<'static, Bn254>,
    Pedersen<G2>,
    Groth16<Bn254>,
    WithdrawN,
>;

macro_rules! cached_params {
    ($prefix:literal, $name:ident, $fc:ty, $n:ty, $d:ty, $fc_params:expr) => {
        pub fn $name() -> Result<
            (
                <$n as FoldingScheme<G1, G2, $fc>>::ProverParam,
                <$n as FoldingScheme<G1, G2, $fc>>::VerifierParam,
                <$d as Decider<G1, G2, $fc, $n>>::ProverParam,
                <$d as Decider<G1, G2, $fc, $n>>::VerifierParam,
            ),
            Box<dyn std::error::Error>,
        > {
            use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

            let dir = std::path::Path::new("artifacts");
            std::fs::create_dir_all(dir)?;

            let pp_path = dir.join(concat!($prefix, "_nova_pp.bin"));
            let vp_path = dir.join(concat!($prefix, "_nova_vp.bin"));
            let dpp_path = dir.join(concat!($prefix, "_decider_pp.bin"));
            let dvp_path = dir.join(concat!($prefix, "_decider_vp.bin"));

            if pp_path.exists() && vp_path.exists() && dpp_path.exists() && dvp_path.exists() {
                let nova_pp =
                    <$n as FoldingScheme<G1, G2, $fc>>::ProverParam::deserialize_uncompressed(
                        &mut std::fs::read(&pp_path)?.as_slice(),
                    )?;
                let nova_vp = <$n as FoldingScheme<G1, G2, $fc>>::vp_deserialize_with_mode(
                    &mut std::fs::read(&vp_path)?.as_slice(),
                    ark_serialize::Compress::No,
                    ark_serialize::Validate::No,
                    $fc_params.clone(),
                )?;
                let decider_pp =
                    <$d as Decider<G1, G2, $fc, $n>>::ProverParam::deserialize_uncompressed(
                        &mut std::fs::read(&dpp_path)?.as_slice(),
                    )?;
                let decider_vp =
                    <$d as Decider<G1, G2, $fc, $n>>::VerifierParam::deserialize_uncompressed(
                        &mut std::fs::read(&dvp_path)?.as_slice(),
                    )?;
                Ok((nova_pp, nova_vp, decider_pp, decider_vp))
            } else {
                let f_circuit = <$fc>::new($fc_params.clone())?;
                let poseidon_config = poseidon_canonical_config::<Fr>();
                let mut rng = ark_std::rand::rngs::OsRng;

                let prep = PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
                let nova_params = <$n as FoldingScheme<G1, G2, $fc>>::preprocess(&mut rng, &prep)?;

                let (decider_pp, decider_vp) = <$d as Decider<G1, G2, $fc, $n>>::preprocess(
                    &mut rng,
                    (nova_params.clone(), f_circuit.state_len()),
                )?;

                let mut buf = vec![];
                nova_params.0.serialize_uncompressed(&mut buf)?;
                std::fs::write(&pp_path, buf)?;
                let mut buf = vec![];
                nova_params.1.serialize_uncompressed(&mut buf)?;
                std::fs::write(&vp_path, buf)?;
                let mut buf = vec![];
                decider_pp.serialize_uncompressed(&mut buf)?;
                std::fs::write(&dpp_path, buf)?;
                let mut buf = vec![];
                decider_vp.serialize_uncompressed(&mut buf)?;
                std::fs::write(&dvp_path, buf)?;

                Ok((nova_params.0, nova_params.1, decider_pp, decider_vp))
            }
        }
    };
}

cached_params!(
    "root",
    load_root_params,
    RootTransitionCircuit,
    RootN,
    RootD,
    ()
);
cached_params!(
    "withdraw",
    load_withdraw_params,
    WithdrawCircuit,
    WithdrawN,
    WithdrawD,
    ()
);

macro_rules! prove_for {
    ($name:ident, $loader:ident, $fc:ty, $n:ty, $d:ty) => {
        pub fn $name(
            f_circuit: $fc,
            z_0: Vec<Fr>,
            external_inputs: Vec<<$fc as FCircuit<Fr>>::ExternalInputs>,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            use std::time::Instant;

            let load_start = Instant::now();
            let (nova_pp, nova_vp, decider_pp, _) = $loader()?;
            eprintln!(
                "[{}] load_params={:?}",
                stringify!($name),
                load_start.elapsed()
            );
            let nova_params = (nova_pp, nova_vp);

            let rng = ark_std::rand::rngs::OsRng;

            let init_start = Instant::now();
            let mut nova =
                <$n as FoldingScheme<G1, G2, $fc>>::init(&nova_params, f_circuit.clone(), z_0)?;
            eprintln!("[{}] init={:?}", stringify!($name), init_start.elapsed());

            let n_steps = external_inputs.len();
            let fold_start = Instant::now();
            for ext in external_inputs {
                nova.prove_step(rng, ext, None)?;
            }
            let fold_elapsed = fold_start.elapsed();

            let decider_start = Instant::now();
            let proof = <$d as Decider<G1, G2, $fc, $n>>::prove(rng, decider_pp, nova.clone())?;
            let decider_elapsed = decider_start.elapsed();

            let avg = if n_steps > 0 {
                format!("{:?}/step", fold_elapsed / n_steps as u32)
            } else {
                "n/a".to_string()
            };
            eprintln!(
                "[{}] steps={} fold={:?} ({}) decider={:?}",
                stringify!($name),
                n_steps,
                fold_elapsed,
                avg,
                decider_elapsed,
            );

            let cal_start = Instant::now();
            let calldata = prepare_calldata_for_nova_cyclefold_verifier(
                NovaVerificationMode::Opaque,
                nova.i,
                nova.z_0,
                nova.z_i,
                &nova.U_i,
                &nova.u_i,
                &proof,
            )?;
            eprintln!(
                "[{}] prepare_calldata={:?}",
                stringify!($name),
                cal_start.elapsed()
            );

            Ok(calldata)
        }
    };
}

prove_for!(
    prove_root_transition,
    load_root_params,
    RootTransitionCircuit,
    RootN,
    RootD
);
prove_for!(
    prove_withdraw,
    load_withdraw_params,
    WithdrawCircuit,
    WithdrawN,
    WithdrawD
);

macro_rules! gen_verifier_for {
    ($name:ident, $loader:ident, $d:ty, $state_len:expr) => {
        pub fn $name() -> Result<String, Box<dyn std::error::Error>> {
            let (_nova_pp, _nova_vp, _decider_pp, decider_vp) = $loader()?;
            let nova_cyclefold_vk = NovaCycleFoldVerifierKey::from((decider_vp, $state_len));
            Ok(get_decider_template_for_cyclefold_decider(
                nova_cyclefold_vk,
            ))
        }
    };
}

gen_verifier_for!(gen_root_transition_verifier, load_root_params, RootD, 3);
gen_verifier_for!(gen_withdraw_verifier, load_withdraw_params, WithdrawD, 4);

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;

    use crate::{
        burn::recipient,
        tree::{MerkleTree, TREE_DEPTH},
    };

    use super::*;

    #[test]
    fn root_transition_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
        use crate::burn::address_to_fr;
        use crate::tree::MerkleTree;
        use solidity_verifiers::evm::{Evm, compile_solidity};

        let transfers = [([0x01u8; 20], 100u64), ([0x02u8; 20], 200u64)];

        let mut tree = MerkleTree::new(TREE_DEPTH);
        let mut witnesses = Vec::new();
        for (i, (to, val)) in transfers.iter().enumerate() {
            let proof = tree.proof_for_empty(i);
            let mut merkle_path = [Fr::zero(); TREE_DEPTH];
            merkle_path.copy_from_slice(&proof);
            witnesses.push(RootTransitionWitness {
                to: address_to_fr(*to),
                value: Fr::from(*val),
                merkle_path,
            });
            let leaf = poseidon2(address_to_fr(*to), Fr::from(*val)).unwrap();
            tree.insert(leaf);
        }

        let initial_root = MerkleTree::new(TREE_DEPTH).root();
        let z_0 = vec![Fr::zero(), Fr::zero(), initial_root];

        let circuit = RootTransitionCircuit::new(()).unwrap();
        let calldata = prove_root_transition(circuit, z_0, witnesses)?;
        let solidity_code = gen_root_transition_verifier()?;

        let bytecode = compile_solidity(&solidity_code, "NovaDecider");
        let mut evm = Evm::default();
        let verifier_address = evm.create(bytecode);
        let (_, output) = evm.call(verifier_address, calldata);
        assert_eq!(*output.last().unwrap(), 1);

        Ok(())
    }

    /// Schnorr keypair + signature for one receipt, plus its Merkle leaf.
    #[cfg(test)]
    fn signed_leaf(
        rng: &mut impl ark_std::rand::RngCore,
        recipient: Fr,
        expiry: u64,
        value: u64,
    ) -> Result<(G2, G2, ark_bn254::Fq, u64, Fr), Box<dyn std::error::Error>> {
        use crate::burn::{address_to_fr, trim_to_160};
        use ark_bn254::Fq;
        use ark_ec::{CurveGroup, PrimeGroup};
        use ark_ff::{BigInteger, PrimeField, UniformRand};

        // P = x·G
        let x = Fq::rand(rng);
        let pubkey = (G2::generator() * x).into_affine();

        // Schnorr: R = k·G, z = k + e·x, e = poseidon4(R.x, P.x, recipient, expiry)
        let k = Fq::rand(rng);
        let sig_r = (G2::generator() * k).into_affine();
        let e_fr = poseidon4(sig_r.x, pubkey.x, recipient, Fr::from(expiry))?;
        let e = Fq::from_be_bytes_mod_order(&e_fr.into_bigint().to_bytes_be());
        let sig_z = k + e * x;

        let burn_addr = address_to_fr(trim_to_160(poseidon2(recipient, pubkey.x)?));
        let leaf = poseidon2(burn_addr, Fr::from(value))?;
        Ok((G2::from(pubkey), G2::from(sig_r), sig_z, expiry, leaf))
    }

    /// Merkle-proof witness — taken from the FINAL tree (after all inserts).
    /// `index` is the global burn index (== tree index here: test tree is root 0).
    #[cfg(test)]
    fn receipt_witness(
        tree: &MerkleTree,
        index: usize,
        pubkey: G2,
        sig_r: G2,
        sig_z: ark_bn254::Fq,
        expiry: u64,
        value: u64,
    ) -> Result<WithdrawWitness, Box<dyn std::error::Error>> {
        let proof = tree.proof(index);
        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        Ok(WithdrawWitness {
            pubkey,
            sig_r,
            sig_z,
            value: Fr::from(value),
            index: Fr::from(index as u64),
            expiry: Fr::from(expiry),
            merkle_path,
        })
    }

    #[test]
    fn withdraw_circuit_is_satisfied() -> Result<(), Box<dyn std::error::Error>> {
        use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, fields::fp::FpVar};
        use ark_relations::gr1cs::ConstraintSystem;

        let recipient = recipient(31337, [0x11u8; 20], [0x22u8; 32]);
        let mut rng = ark_std::test_rng();

        let (_, _, _, _, filler) = signed_leaf(&mut rng, recipient, 1, 0)?;
        let (pk, r, z, expiry, leaf) = signed_leaf(&mut rng, recipient, 100, 0)?;

        let mut tree = MerkleTree::new(TREE_DEPTH);
        tree.insert(filler);
        tree.insert(leaf);
        let transfer_root = tree.root();

        let witness = receipt_witness(&tree, 1, pk, r, z, expiry, 100)?;
        let z_i = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];

        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_i_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i.clone()))?;
        let w_var = WithdrawWitnessVar::new_witness(cs.clone(), || Ok(witness))?;
        let circuit = WithdrawCircuit::new(())?;
        let out = circuit.generate_step_constraints(cs.clone(), 0, z_i_var, w_var)?;

        assert!(cs.is_satisfied()?);
        assert_eq!(out[0].value()?, Fr::from(2u64)); // indexWithOffset' = index + 1
        assert_eq!(out[1].value()?, Fr::from(100u64)); // totalValue' = 0 + 100

        // expired signature must be rejected by the circuit
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let (pk, r, z, _, leaf) = signed_leaf(&mut rng, recipient, 0, 50)?; // expiry = 0
        let mut tree2 = MerkleTree::new(TREE_DEPTH);
        tree2.insert(leaf);
        let w = receipt_witness(&tree2, 0, pk, r, z, 0, 50)?; // index 0, but cursor...
        let z_i_var2 = Vec::<FpVar<Fr>>::new_witness(cs2.clone(), || {
            Ok(vec![Fr::zero(), Fr::zero(), tree2.root(), recipient])
        })?;
        let w_var2 = WithdrawWitnessVar::new_witness(cs2.clone(), || Ok(w))?;
        circuit.generate_step_constraints(cs2.clone(), 0, z_i_var2, w_var2)?;
        assert!(!cs2.is_satisfied()?);

        Ok(())
    }

    #[test]
    fn withdraw_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
        use solidity_verifiers::evm::{Evm, compile_solidity};

        let recipient = recipient(31337, [0x11u8; 20], [0x22u8; 32]);
        let mut rng = ark_std::test_rng();

        // Two receipts: the decider requires >= 2 folded steps.
        let (pk0, r0, z0, e0, leaf0) = signed_leaf(&mut rng, recipient, 1_000_000, 100)?;
        let (pk1, r1, z1, e1, leaf1) = signed_leaf(&mut rng, recipient, 1_000_000, 200)?;

        let mut tree = MerkleTree::new(TREE_DEPTH);
        tree.insert(leaf0);
        tree.insert(leaf1);
        let transfer_root = tree.root();

        let witness0 = receipt_witness(&tree, 0, pk0, r0, z0, e0, 100)?;
        let witness1 = receipt_witness(&tree, 1, pk1, r1, z1, e1, 200)?;

        let z_0 = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];
        let circuit = WithdrawCircuit::new(())?;
        let calldata = prove_withdraw(circuit, z_0, vec![witness0, witness1])?;
        let solidity_code = gen_withdraw_verifier()?;

        let bytecode = compile_solidity(&solidity_code, "NovaDecider");
        let mut evm = Evm::default();
        let verifier_address = evm.create(bytecode);
        let (_, output) = evm.call(verifier_address, calldata);
        assert_eq!(*output.last().unwrap(), 1);

        Ok(())
    }
}
