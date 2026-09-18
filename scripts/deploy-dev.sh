#!/bin/sh
set -e

RPC_URL=http://localhost:8545
CHAIN_ID=31337
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
CLIENT=0x70997970c51812dc3a010c7d01b50e0d17dc79c8

forge build
forge script Deploy --rpc-url "$RPC_URL" --broadcast --private-key "$KEY"

BROADCAST=broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json

TOKEN=$(jq -r '.transactions[] | select(.transactionType == "CREATE" and .contractName == "zERC20") | .contractAddress' "$BROADCAST")
echo "TOKEN=$TOKEN"

cast send "$TOKEN" "transfer(address,uint256)" "$CLIENT" 1000000 \
  --private-key "$KEY" --rpc-url "$RPC_URL"
