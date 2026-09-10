#!/usr/bin/env bash
# Send private transfers to burn addresses served by the running server.
# Prereqs: server running (serves /deposit-address), token deployed.

set -euo pipefail

RPC=http://localhost:8545
SERVER=http://localhost:3000
PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil account 0
AMOUNT=100
COUNT=2   # >= 2 so the server's batch withdraw has enough receipts

RUN_JSON=broadcast/Deploy.s.sol/31337/run-latest.json
command -v jq >/dev/null || { echo "jq is required (brew install jq)"; exit 1; }
command -v cast >/dev/null || { echo "cast is required (foundry)"; exit 1; }
[ -f "$RUN_JSON" ] || { echo "no deployment broadcast — run scripts/deploy.sh first"; exit 1; }
TOKEN=$(jq -r '.transactions[] | select(.transactionType=="CREATE" and .contractName=="zERC20") | .contractAddress' "$RUN_JSON" | tail -1)

echo "token = $TOKEN"

for i in $(seq 1 "$COUNT"); do
  BURN=$(curl -s "$SERVER/deposit-address" | jq -r '.address')
  : "${BURN:?no burn address from server}"
  echo "burn #$i = $BURN"
  cast send "$TOKEN" "transfer(address,uint256)" "$BURN" "$AMOUNT" \
    --rpc-url "$RPC" --private-key "$PK"
done
