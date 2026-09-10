#!/usr/bin/env bash
# e2e runbook: burn x2 -> update-root -> batch withdraw, against local anvil.
# Prereqs: fresh `anvil`, then `cargo run --release -- gen-verifiers`, then bash scripts/deploy.sh
# (all commands run from the repo root).

set -euo pipefail

RPC=http://localhost:8545
PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil account 0
RECIPIENT=0x70997970C51812dc3A010C7d01b50e0d17dc79C8                   # anvil account 1
TWEAK=0x2222222222222222222222222222222222222222222222222222222222222222
AMOUNT=100

RUN_JSON=broadcast/Deploy.s.sol/31337/run-latest.json
command -v jq >/dev/null || { echo "jq is required (brew install jq)"; exit 1; }
[ -f "$RUN_JSON" ] || { echo "no deployment broadcast — run scripts/deploy.sh first"; exit 1; }
TOKEN=$(jq -r '.transactions[] | select(.transactionType=="CREATE" and .contractName=="zERC20") | .contractAddress' "$RUN_JSON" | tail -1)
VERIFIER=$(jq -r '.transactions[] | select(.transactionType=="CREATE" and .contractName=="Verifier") | .contractAddress' "$RUN_JSON" | tail -1)
echo "token    = $TOKEN"
echo "verifier = $VERIFIER"

burn() { # runs one burn and prints the generated secret
  cargo run --release -- burn \
    --rpc-url $RPC --token "$TOKEN" --recipient "$RECIPIENT" \
    --tweak $TWEAK --amount $AMOUNT --private-key $PK \
    | tee /dev/stderr | awk -F'= *' '/^secret/ {print $2}'
}

echo "== burn #1"
S1=$(burn); : "${S1:?no secret printed}"
echo "== burn #2"
S2=$(burn); : "${S2:?no secret printed}"

echo "== update-root (first run generates root-transition params — several minutes)"
cargo run --release -- update-root \
  --rpc-url $RPC --token "$TOKEN" --verifier "$VERIFIER" --private-key $PK

echo "== withdraw both burns in one batch proof"
echo "   (the on-chain decider requires >= 2 folded steps; single receipts are rejected)"
cargo run --release -- withdraw \
  --rpc-url $RPC --token "$TOKEN" --verifier "$VERIFIER" \
  --recipient "$RECIPIENT" --tweak $TWEAK \
  --secret "$S1,$S2" --value "$AMOUNT,$AMOUNT" --private-key $PK
