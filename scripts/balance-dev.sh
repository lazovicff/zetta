#!/bin/sh
set -e

RPC_URL=http://localhost:8545
CHAIN_ID=31337
ADDRESS=${1:?usage: balance-dev.sh <address>}

BROADCAST=broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json

TOKEN=$(jq -r '.transactions[] | select(.transactionType == "CREATE" and .contractName == "zERC20") | .contractAddress' "$BROADCAST")
echo "TOKEN=$TOKEN"

RAW=$(cast call "$TOKEN" "balanceOf(address)(uint256)" "$ADDRESS" --rpc-url "$RPC_URL")
RAW=${RAW%% *} # strip cast's " [5.399e20]" annotation
case "$RAW" in
  0x*) WEI=$(cast to-dec "$RAW") ;;   # hex-decoded output
  *)   WEI=$RAW ;;                   # already decimal
esac

echo "WEI=$WEI"
echo "balance: $(cast --from-wei "$WEI" ether) zDAI"
