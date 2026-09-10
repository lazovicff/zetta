# zetta — Private ERC-20 Transfers via ZK Proof-of-Burn

https://ethereum-magicians.org/t/zerc20-cross-chain-private-erc-20-based-on-zk-proof-of-burn/26452

https://ethereum-magicians.org/t/eip-7503-zero-knowledge-wormholes-private-proof-of-burn-ppob/15456

## 1. Concept

Private transfer = **burn + mint**:

1. Sender does a **plain ERC-20 `transfer`** to a *burn address* derived from `(recipient identity, secret)`. On-chain it is indistinguishable from an ordinary transfer to a fresh address → plausible deniability (the core win of EIP-7503). No special deposit function, no custom UI.
2. Recipient later submits a **ZK proof**: "a transfer of `value` to burn address `B` exists in the transfer tree, and I know `secret` such that `B = trim160(Poseidon(recipient, secret))`". The verifier contract **mints** the tokens to them.
3. Double-withdrawal is prevented by **cumulative accounting** per recipient, not per-nullifier: contract stores `totalWithdrawn[recipient]`, proof reveals cumulative `sum`, contract mints only `sum − totalWithdrawn` (> 0).

## 2. Cryptographic spec

- Field: **bn254** scalar field `Fr`. Nova cycle: **bn254 / grumpkin**.
- Hashes: **Poseidon** (2-in-1-out, circomlib params — used by `light-poseidon` off-circuit and the patched `ark-crypto-primitives` gadget in-circuit, same as reference); **keccak256** for recipients; **SHA-256** for the on-chain hash chain.
- `trimN(x)`: keep the **lower N bits** of `x`.

```
recipient   = trim246(keccak256(chain_id_be8 ‖ address_20 ‖ tweak_32))   ∈ Fr
burnAddress = trim160(Poseidon(recipient, secret))                       ∈ 160 bits
leaf        = Poseidon(burnAddress, value)
hashChain_0 = 0
hashChain_i = trim246(sha256(bytes32_be(hashChain_{i-1}) ‖ to_20 ‖ value_32))   // 84-byte preimage
```

- **Proof-of-work on burn addresses**: bits `[160, 160+n)` of the Poseidon output must be zero (`hash >> (160+n) == 0`). Default **n = 20** → collision resistance ≈ 80+20 = 100 bits; keygen cost ≈ 2²⁰ Poseidon evals (~1 s). Without PoW, a birthday attack on `trim160` finds colliding `(recipient, secret)` pairs (~2⁸⁰) enabling double-withdrawal from one address.
- `tweak`: arbitrary 32 bytes. Rotating it mints a fresh `recipient` namespace for the same `(chain_id, address)` — resets withdrawal batch size (privacy ↔ cost tradeoff, §4-F).
- `value < 2²⁴⁸` enforced (fits `Fr` with room).

## 3. Repo layout
```
zetta/
├─ src/                        # single Rust crate (binary `zetta`)
│  ├─ main.rs                  #    CLI entry: indexer / burn / withdraw subcommands
│  ├─ burn.rs                  # A: poseidon2, recipient, trim_to_160, check_pow, find_burn_address + `burn` cmd
│  ├─ tree.rs                  # B: MerkleTree, HashChain, hash_chain_step
│  ├─ indexer.rs               # E: Transfer-event watcher — hash chain + tree builder
│  ├─ withdraw.rs              # E: `withdraw` cmd (reconstruct tree, fold, decider)
│  └─ zkp/                     # D: step circuits + Nova IVC + decider + Solidity verifier export
│     ├─ mod.rs                #    prove_root_transition / prove_withdraw (Nova + Groth16 decider)
│     ├─ poseidon.rs           #    in-circuit Poseidon gadget (circomlib params)
│     ├─ root.rs               #    RootTransitionCircuit
│     └─ withdraw.rs           #    WithdrawCircuit
├─ contracts/                  # C (Foundry)
│  ├─ src/zERC20.sol           #    ERC-20 + hash chain
│  ├─ src/Verifier.sol         #    root registry, totalWithdrawn, mint
│  ├─ test/                    #    Foundry tests (zERC20.t.sol, Verifier.t.sol)
│  ├─ lib/                     #    openzeppelin-contracts (git submodule)
│  └─ out/                     #    build artifacts
├─ cache/                      # Foundry cache (gitignored)
└─ target/                     # Cargo build output (gitignored)
```


## 4. Phases

### A — zk-crypto (Rust)

Deps: `light-poseidon 0.4`, `ark-bn254/ark-ff 0.5` (git-pinned, §7), `sha3 0.10`, `rand 0.8`.

- `poseidon2(a,b)` — circomlib params (identical off-/in-circuit).
- `recipient(chain_id, address, tweak)`.
- `trim_to_160(x)`, `check_pow(x, n)`.
- `find_burn_address(recipient, n) -> (address, secret)`.

Tests:
- Known vector: `poseidon2(1, 2) == 7853200120776062878684798364095072458815029376092732009249414926327459813530` (validates params — must pass).
- PoW soundness edge cases; recipient determinism; trim roundtrips.

### B — zk-tree (Rust)

- Append-only Poseidon binary Merkle tree, **depth 32**, empty leaf = `poseidon(0,0)`; cached zero-subtree roots `Z(0)=poseidon(0,0)`, `Z(h)=poseidon(Z(h−1),Z(h−1))`.
- `insert(index, leaf) -> root`, `proof(index) -> siblings`.
- Hash-chain mirror: apply ordered `Transfer` events (by `blockNumber, logIndex`), assert equality with on-chain `hashChain`.
- Rule: include all transfers with `from != 0x0` (verifier mints excluded from tree).

### C — Contracts (Foundry)

- `ZettaToken.sol`: ERC-20; hook `_update` → for `from != address(0)`: `burnHashChain = trim246(sha256(abi.encodePacked(uint256(burnHashChain), to, value)))`, `burnIndex++`. Require `value < 2**248`.
- `ZettaVerifier.sol`:
  - `updateRoot(proof)`: verify root-transition decider proof; publics `[prevIndex, prevHashChain, prevRoot]` must match token's current `(burnIndex, burnHashChain)` and stored root; store `(newRoot, newIndex)`.
  - `withdraw(chainId, addr, tweak, proof)`: require `chainId == block.chainid`; recompute `recipient`; verify withdraw decider proof (publics `[transferRoot, recipient, sum]`, `transferRoot` must be a stored root); `delta = sum − totalWithdrawn[recipient]`; require `delta > 0`; `totalWithdrawn[recipient] = sum`; mint `delta` to `addr`.
- Foundry tests incl. reverts: double-withdraw, wrong chain id, stale root ordering.

### D — zkp (Sonobe: Nova IVC + Groth16 decider, Rust-native — no circom)

Step circuits as arkworks R1CS implementing sonobe's `FCircuit` (arkworks frontend). SHA-256 in-circuit via the patched `ark-crypto-primitives` gadget; Poseidon in-circuit via its Poseidon gadget (circomlib params).

**`RootTransitionCircuit`** — folded one step per transfer:
- `z_i = [index, hashChain, transferRoot]` (public I/O).
- Witness per step: `to, value, merkle_path`.
- Constraints: `hashChain' = trim246(sha256(bytes32_be(hashChain) ‖ to_20 ‖ value_32))`; old leaf at `index` is `poseidon(0,0)`; new leaf `poseidon(to, value)`; `index' = index + 1`.

**`WithdrawCircuit`** — folded one step per receipt:
- `z = [indexWithOffset, totalValue]`; fixed publics `[transferRoot, recipient]`.
- Witness per step: `secret, value, index, merkle_path`.
- Constraints: `burn = poseidon(recipient, secret)`; **enforce PoW bits** `[160,160+n)` zero; `transferRoot == getRoot(index, poseidon(burn, value))`; `index + 1 > indexWithOffset` (strictly increasing); `totalValue += value`; `value < 2²⁴⁸`; `recipient < 2²⁴⁶`.

**Pipeline**: fold N steps as Nova IVC → prove **decider** once (Groth16 over bn254 decider circuit) → generate Solidity verifier via `solidity-verifiers` crate → `contracts/src/verifiers/`. Decider cost ~30 s on M4, fixed regardless of step count → amortize over batches.

**Artifacts per circuit** (versioned, SHA256 manifest): `*_nova_pp/vp.bin`, `*_decider_pp/vp.bin`, `*_groth16_pk/vk.bin`, `*_verifier.sol`.

**Trusted setup**: Groth16 per decider circuit (dev: single-party via `arkworks-phase2` fork; prod: ceremony). Nova params themselves are setup-free.

Targets (zERC20 @ M4): root-transition step 242 ms, withdraw step 142 ms, decider 30–32 s; withdraw gas 302 k (single) / 914 k (batch); token transfer 47.8 k gas.

### E — indexer / prover / CLI (Rust) + e2e demo on anvil

- `indexer` (alloy): subscribe `Transfer`; maintain hash chain + tree; emit ordered transfer batches to the prover.
- `prover`: native — folds steps with the `zkp` crate, runs decider, returns calldata. Heavy process; long-running service with artifact cache (mirrors reference `decider-prover`).
- `cli` (alloy + zkp): `zetta burn` (derive burn address, call `transfer`), `zetta withdraw` (fetch leaves from indexer, fold, decider, submit tx).
- e2e: `forge script` deploy to anvil + scripted runbook (burn → index → fold+decider → updateRoot → withdraw).

### F — Batch withdrawals & tweak rotation

- Fold K receipts into one Withdraw Nova before a single decider ⇒ only the **total** per recipient is public; decider cost amortized.
- Rotate `tweak` per receipt ⇒ fresh `recipient` ⇒ each withdrawal is a 1-step Nova (amount revealed publicly — privacy tradeoff).
- Withdrawal proof must process receipts in strictly increasing index order; cumulative `sum − totalWithdrawn` accounting allows later top-ups.

### G — Cross-chain hub

- Each chain's verifier relays its local `transferRoot` to a **Hub** contract (LayerZero/CCIP).
- Hub builds a **global tree** over per-chain roots (each chain root incorporated exactly once), broadcasts global root back.
- Withdraw proofs then reference the global tree index — cross-chain burn-and-mint.

## 5. MVP deviations (explicit, temporary)

1. **Old sonobe API** (`folding-schemes`, kbizikav fork @ `update-revm`) instead of the `sonobe 0.1.0-alpha` rewrite — the rewrite's on-chain decider (LegoGroth16) is not merged yet. Revisit when it lands.
2. **Single chain** first.
3. **Dev single-party** trusted setup for the decider (ceremony before production).

## 6. Security invariants

- Circuit **must** enforce PoW bits — else collision search drops to ~2⁸⁰ (birthday on 160 bits).
- Mint strictly `sum − totalWithdrawn[recipient]`, only if `> 0`; update accounting atomically.
- `withdraw` re-checks `chain_id == block.chainid` and binds `recipient` to the proof.
- Decider Groth16 keys are **per-circuit**, never reused across circuits; artifacts versioned + hash-verified.
- Never log/persist `secret` server-side.
- Anonymity set = all transfers into burn-looking addresses; amount/timing correlation remains possible → tooling should default to uniform amounts + randomized delays (per EIP-7503 thread).
- Hash chain byte layout (84-byte preimage) must identically match between Solidity, indexer, and circuit — pin with cross-language test vectors in Phase B/C/D.
