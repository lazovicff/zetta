mod burn;
mod gen_verifiers;
mod indexer;
mod tree;
mod update_root;
mod withdraw;
mod zkp;

use alloy::primitives::{Address, B256, U256};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zetta", version, about = "zERC20 private transfer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Watch Transfer events and maintain the hash chain + tree.
    Indexer {
        #[arg(long, default_value = "ws://localhost:8545")]
        ws_url: String,
        #[arg(long)]
        token: Address,
    },
    /// Derive a burn address and send a plain transfer to it.
    Burn {
        #[arg(long, default_value = "http://localhost:8545")]
        rpc_url: String,
        #[arg(long)]
        token: Address,
        #[arg(long)]
        recipient: Address,
        #[arg(long)]
        tweak: B256,
        #[arg(long)]
        amount: U256,
        #[arg(long, default_value_t = 20)]
        pow_bits: u32,
        #[arg(long)]
        private_key: String,
    },
    /// Submit a withdrawal proof (fold + decider) and print calldata.
    Withdraw {
        #[arg(long, default_value = "http://localhost:8545")]
        rpc_url: String,
        #[arg(long)]
        token: Address,
        #[arg(long)]
        verifier: Address,
        #[arg(long)]
        recipient: Address,
        #[arg(long)]
        tweak: B256,
        /// Comma-separated decimal Fr secrets, one per burn receipt.
        #[arg(long)]
        secret: String,
        /// Comma-separated amounts, same count as --secret.
        #[arg(long)]
        value: String,
        #[arg(long)]
        private_key: String,
    },

    /// Prove the tree root matches the on-chain hash chain and submit updateRoot.
    UpdateRoot {
        #[arg(long, default_value = "http://localhost:8545")]
        rpc_url: String,
        #[arg(long)]
        token: Address,
        #[arg(long)]
        verifier: Address,
        #[arg(long)]
        private_key: String,
    },

    /// Generate the Nova decider verifier contracts.
    GenVerifiers,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Indexer { ws_url, token } => indexer::run(&ws_url, token).await?,
        Command::Burn {
            rpc_url,
            token,
            recipient,
            tweak,
            amount,
            pow_bits,
            private_key,
        } => {
            burn::run(
                &rpc_url,
                token,
                recipient,
                tweak,
                amount,
                pow_bits,
                &private_key,
            )
            .await?
        }
        Command::Withdraw {
            rpc_url,
            token,
            verifier,
            recipient,
            tweak,
            secret,
            value,
            private_key,
        } => {
            withdraw::run(
                &rpc_url,
                token,
                verifier,
                recipient,
                tweak,
                &secret,
                &value,
                &private_key,
            )
            .await?
        }

        Command::UpdateRoot {
            rpc_url,
            token,
            verifier,
            private_key,
        } => update_root::run(&rpc_url, token, verifier, &private_key).await?,

        Command::GenVerifiers => gen_verifiers::run()?,
    }
    Ok(())
}
