# zetta

Private ERC-20 transfers via ZK proof-of-burn (EIP-7503 / zERC20), with a neobank layer (card loads, payouts) on top.

## Core idea

A private "transfer" is a **burn + mint**. Money goes into a dead-looking address; the rightful owner later proves ownership in zero knowledge and the contract mints the same amount back to a public exchange address.

**Burn addresses.** The exchange publishes a namespace `recipient = trim246(keccak(chain_id ‖ exchange_addr ‖ tweak))`. A user's burn address is `low160(poseidon3(recipient, pubkey.x, salt))` — a fresh salt mints a fresh one-use address, so each top-up lands somewhere with no history and no owner on-chain. Depositing is a plain ERC-20 `transfer`: no special contract call, no UI fingerprint — the deposit is indistinguishable from burning tokens (plausible deniability).

**Registration.** Before using an address, the user registers it with the server: the address must recompute from `(pubkey.x, salt)` under the current `recipient`, plus a Schnorr signature proving key ownership (challenge `e = poseidon3(R.x, P.x, recipient)`). Deposits to unregistered addresses are treated as burned — the `registered_from` boundary fixes the claim boundary.

**On-chain trail.** `zERC20._update` appends every non-mint transfer to a Poseidon hash chain (`burnHashChain`, `burnIndex`); a `VALUE_LIMIT < 2²⁴⁸` keeps values inside the field. The server mirrors the chain, inserts `poseidon2(address, value)` leaves into a depth-32 Poseidon Merkle tree, and publishes the new `transferRoot` — with a Nova+Groth16 folding proof per transfer batch (`updateRoot`), or plain Groth16 for single-leaf epochs. `reserveHashChain` pins an epoch target so proofs race-free against new transfers.

**Claim.** A second Nova proof aggregates all receipts for the recipient: for each leaf, the circuit enforces the address derivation, the Schnorr ownership check, Merkle membership against `transferRoot`, a strictly increasing index, and range checks. The contract recomputes `recipient` from `(chainId, addr, tweak)`, verifies the proof, and mints `sum − totalWithdrawn[recipient]` to the exchange — cumulative per-recipient accounting instead of per-nullifier, so top-ups and partial withdrawals compose and no spend registry exists.

**Neobank layer.** With deposits teleported to the exchange, balances are off-chain ledger entries: users sign card loads and payout requests with Schnorr (`POST /cards`, `POST /withdraw`); Postgres records them append-only; the worker settles payouts as regular token transfers.

## Security invariants

- Circuit enforces PoW bits on burn addresses (else birthday attack on 160 bits).
- Contract mints only `sum − totalWithdrawn`, atomically; re-checks `chain_id` and binds `recipient` to the proof.
- Secrets never leave the device; server stores only pubkeys, signatures, salts.
- Groth16 decider keys are per-circuit (dev: single-party setup; ceremony before production).

Full protocol detail: `PLAN.md`.
