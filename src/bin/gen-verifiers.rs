use std::fs;
use std::path::Path;

use zetta::zkp::{gen_root_transition_verifier, gen_withdraw_verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("contracts/src/verifiers");
    fs::create_dir_all(out_dir)?;

    println!("generating root-transition verifier (z_len=3)...");
    let root_code = gen_root_transition_verifier()?;
    fs::write(out_dir.join("RootTransitionVerifier.sol"), root_code)?;

    println!("generating withdraw verifier (z_len=4, pow_bits=20)...");
    let withdraw_code = gen_withdraw_verifier()?;
    fs::write(out_dir.join("WithdrawVerifier.sol"), withdraw_code)?;

    println!("done");
    Ok(())
}
