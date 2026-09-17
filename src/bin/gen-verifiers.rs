use std::{fs, path::Path};

use zetta::zkp::{
    gen_root_transition_verifier, gen_single_withdraw_verifier, gen_withdraw_verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("contracts/src/verifiers");
    fs::create_dir_all(out_dir)?;

    println!("generating root-transition verifier (z_len=3)...");
    fs::write(
        out_dir.join("RootTransitionVerifier.sol"),
        gen_root_transition_verifier()?,
    )?;

    println!("generating withdraw verifier (z_len=4, pow_bits=20)...");
    fs::write(
        out_dir.join("WithdrawVerifier.sol"),
        gen_withdraw_verifier()?,
    )?;

    println!("generating single-withdraw verifier (4 public inputs)...");
    fs::write(
        out_dir.join("SingleWithdrawVerifier.sol"),
        gen_single_withdraw_verifier()?,
    )?;

    println!("done");
    Ok(())
}
