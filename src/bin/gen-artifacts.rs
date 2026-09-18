use std::path::Path;

use zetta::zkp::{
    ARTIFACTS_DIR, create_root_params, create_single_root_params, create_single_withdraw_params,
    create_withdraw_params, write_root_params, write_single_root_params,
    write_single_withdraw_params, write_withdraw_params,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(ARTIFACTS_DIR);

    println!("generating root-transition params (slow)...");
    write_root_params(dir, &create_root_params()?)?;

    println!("generating withdraw params (slow)...");
    write_withdraw_params(dir, &create_withdraw_params()?)?;

    println!("generating single-step Groth16 keys...");
    let (sr_pk, sr_vk) = create_single_root_params()?;
    write_single_root_params(dir, &sr_pk, &sr_vk)?;
    let (sw_pk, sw_vk) = create_single_withdraw_params()?;
    write_single_withdraw_params(dir, &sw_pk, &sw_vk)?;

    println!("artifacts written to {}", dir.display());
    println!("next: cargo run --release --bin gen-verifiers && redeploy");
    Ok(())
}
