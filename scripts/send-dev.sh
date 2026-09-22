RPC_URL=http://localhost:8545
CHAIN_ID=31337
KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
ADDRESS=${1:?usage: send.sh <address>}

BROADCAST=broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json

TOKEN=$(jq -r '.transactions[] | select(.transactionType == "CREATE" and .contractName == "zERC20") | .contractAddress' "$BROADCAST")
echo "TOKEN=$TOKEN"

cast send "$TOKEN" "transfer(address,uint256)" "$ADDRESS" $(cast --to-wei 500 ether) \
  --private-key "$KEY" --rpc-url "$RPC_URL"
