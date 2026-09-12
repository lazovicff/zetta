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
    WithdrawParams { pow_bits: 20 }
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

    use crate::tree::TREE_DEPTH;

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

        let initial_root = MerkleTree::new(32).root();
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

    #[test]
    fn withdraw_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
        use crate::burn::{find_burn_address, recipient};
        use crate::tree::MerkleTree;
        use solidity_verifiers::evm::{Evm, compile_solidity};

        let recipient = recipient(31337, [0x11u8; 20], [0x22u8; 32]);
        let pow_bits = 8u32;
        let (_burn_addr, secret) = find_burn_address(recipient, pow_bits);

        let value = Fr::from(100u64);
        let burn = poseidon2(recipient, secret).unwrap();
        let burn_addr = crate::burn::address_to_fr(crate::burn::trim_to_160(burn));
        let leaf = poseidon2(burn_addr, value).unwrap();

        let mut tree = MerkleTree::new(TREE_DEPTH);
        tree.insert(leaf);
        let transfer_root = tree.root();
        let proof = tree.proof(0);

        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        let witness = WithdrawWitness {
            secret,
            value,
            index: Fr::zero(),
            merkle_path,
        };

        let z_0 = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];

        let circuit = WithdrawCircuit::new(WithdrawParams { pow_bits }).unwrap();
        let calldata = prove_withdraw(circuit, z_0, vec![witness])?;
        let solidity_code = gen_withdraw_verifier()?;

        let bytecode = compile_solidity(&solidity_code, "NovaDecider");
        let mut evm = Evm::default();
        let verifier_address = evm.create(bytecode);
        let (_, output) = evm.call(verifier_address, calldata);
        assert_eq!(*output.last().unwrap(), 1);

        Ok(())
    }
}
