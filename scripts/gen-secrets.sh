#!/usr/bin/env bash
# Generate N PoW-valid secrets for the server's recipient, for pasting into .env.
set -euo pipefail

set -a; source .env; set +a

COUNT=${1:-5}

EXCHANGE_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY")

cargo build --release --bin gen-secrets
./target/release/gen-secrets \
  --chain-id "$CHAIN_ID" \
  --address "$EXCHANGE_ADDR" \
  --tweak "$TWEAK" \
  --count "$COUNT"
