use ark_bn254::Fr;
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::gr1cs::SynthesisError;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;

/// In-circuit 2-ary Poseidon over bn254 (circomlib params).
/// Matches `crate::burn::poseidon2` (light-poseidon `new_circom(2)`).
pub fn poseidon2_var(a: FpVar<Fr>, b: FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let params = get_poseidon_parameters::<Fr>(3).expect("poseidon params");
    let width = params.width; // 3
    let full_rounds = params.full_rounds; // 8
    let partial_rounds = params.partial_rounds; // 57

    // state = [0, a, b] (domain tag 0, then inputs)
    let mut state = vec![FpVar::<Fr>::zero(), a, b];

    let all_rounds = full_rounds + partial_rounds;
    let half_rounds = full_rounds / 2;

    for round in 0..half_rounds {
        apply_ark(&mut state, &params.ark, round, width);
        sbox_full(&mut state);
        state = apply_mds(&state, &params.mds);
    }
    for round in half_rounds..half_rounds + partial_rounds {
        apply_ark(&mut state, &params.ark, round, width);
        state[0] = sbox(&state[0]);
        state = apply_mds(&state, &params.mds);
    }
    for round in half_rounds + partial_rounds..all_rounds {
        apply_ark(&mut state, &params.ark, round, width);
        sbox_full(&mut state);
        state = apply_mds(&state, &params.mds);
    }

    Ok(state[0].clone())
}

fn apply_ark(state: &mut [FpVar<Fr>], ark: &[Fr], round: usize, width: usize) {
    for i in 0..width {
        state[i] += FpVar::<Fr>::constant(ark[round * width + i]);
    }
}

/// x^5 (circomlib bn254 S-box).
fn sbox(x: &FpVar<Fr>) -> FpVar<Fr> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    &x4 * x
}

fn sbox_full(state: &mut [FpVar<Fr>]) {
    for i in 0..state.len() {
        state[i] = sbox(&state[i]);
    }
}

fn apply_mds(state: &[FpVar<Fr>], mds: &[Vec<Fr>]) -> Vec<FpVar<Fr>> {
    let width = state.len();
    (0..width)
        .map(|i| {
            let mut acc = FpVar::<Fr>::zero();
            for j in 0..width {
                acc += &state[j] * FpVar::<Fr>::constant(mds[i][j]);
            }
            acc
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};

    use super::*;

    #[test]
    fn poseidon_var_matches_native() {
        use crate::burn::poseidon2;
        use ark_relations::gr1cs::ConstraintSystem;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a)).unwrap();
        let b_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(b)).unwrap();
        let h_var = poseidon2_var(a_var, b_var).unwrap();
        let h_native = poseidon2(a, b).unwrap();
        assert_eq!(h_var.value().unwrap(), h_native);
    }
}
