use alloy::primitives::{Address, B256};
use clap::Parser;
use zetta::burn::{gen_secrets, recipient};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    address: Address,
    #[arg(long)]
    tweak: B256,
    #[arg(long, default_value_t = 20)]
    pow_bits: u32,
    #[arg(long, default_value_t = 1)]
    count: usize,
}

fn main() {
    let args = Args::parse();
    let recipient = recipient(args.chain_id, args.address.into_array(), args.tweak.0);
    let secrets = gen_secrets(recipient, args.count, args.pow_bits);

    let list: Vec<String> = secrets.iter().map(|(_, s)| s.to_string()).collect();
    println!("SECRETS={}", list.join(","));
    for (addr, s) in &secrets {
        println!("secret {} -> burn 0x{}", s, hex::encode(addr));
    }
}
