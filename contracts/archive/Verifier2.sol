// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {zERC20} from "../src/zERC20.sol";

interface IRootTransitionVerifier {
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
}

interface IWithdrawVerifier {
    function verifyOpaqueNovaProof(uint256[34] calldata proof) external view returns (bool);
}

interface ISingleRootTransitionVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata pubSignals
    ) external view returns (bool);
}

interface ISingleWithdrawVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external view returns (bool);
}

/// One verifier = one tree (depth 32). On rollover a new Verifier is deployed:
/// tree state restarts (empty root, tree-local index 0) while the token's hash
/// chain continues from the previous generation's frozen frontier.
contract Verifier {
    zERC20 public token;

    /// Previous generation (address(0) at genesis).
    Verifier public immutable prev;
    /// Global token burnIndex at which this tree's local index 0 starts.
    uint256 public treeStart;

    // This generation's tree. Frontier = state proven on-chain.
    uint256 public transferRoot;
    uint256 public transferIndex;      // tree-local: leaves folded into transferRoot
    uint256 public transferHashChain;  // global chain value, continuous across generations

    uint256 public reservedHashChain;
    uint256 public reservedIndex;      // tree-local

    mapping(uint256 => uint256) public totalWithdrawn; // recipient => sum minted (this tree)

    // Legacy: claims against prev's frozen tree, settled by this contract.
    mapping(uint256 => uint256) public legacyWithdrawn; // recipient => sum minted here from prev's tree

    IRootTransitionVerifier public rootTransitionVerifier;
    IWithdrawVerifier public withdrawVerifier;
    ISingleRootTransitionVerifier public singleRootTransitionVerifier;
    ISingleWithdrawVerifier public singleWithdrawVerifier;

    address public owner;

    uint256 private constant HASH_CHAIN_MASK = (1 << 246) - 1;
    uint256 private constant TREE_CAPACITY = 1 << 32;

    constructor(zERC20 token_, uint256 initialRoot_, Verifier prev_) {
        token = token_;
        transferRoot = initialRoot_; // empty depth-32 tree root
        prev = prev_;
        if (address(prev_) != address(0)) {
            // prev is frozen for good once finalized: updateRoot requires
            // newIndex == reservedIndex AND newIndex > prevIndex, so nothing
            // can advance it past its final reservation.
            require(prev_.transferIndex() == prev_.reservedIndex(), "prev not finalized");
            treeStart = prev_.treeStart() + prev_.transferIndex(); // global boundary index
            transferHashChain = prev_.transferHashChain();         // boundary chain value
        }
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setVerifiers(
        IRootTransitionVerifier root_,
        IWithdrawVerifier withdraw_,
        ISingleWithdrawVerifier singleWithdraw_,
        ISingleRootTransitionVerifier singleRoot_
    ) external onlyOwner {
        rootTransitionVerifier = root_;
        withdrawVerifier = withdraw_;
        singleWithdrawVerifier = singleWithdraw_;
        singleRootTransitionVerifier = singleRoot_;
    }

    /// Snapshot the token's burn hash chain (tree-local rebased) as the epoch
    /// target. Index semantics: reservedIndex counts THIS tree's leaves.
    function reserveHashChain() external onlyOwner {
        uint256 index = token.burnIndex() - treeStart;
        require(index <= TREE_CAPACITY, "tree full");
        reservedIndex = index;
        reservedHashChain = token.burnHashChain();
    }

    /// proof = [i, z0[0..3], zi[0..3], 25 decider elements]
    /// z0 = [prevIndex, prevHashChain, prevRoot], zi = [newIndex, newHashChain, newRoot]
    function updateRoot(uint256[32] calldata proof) external {
        uint256 prevIndex = proof[1];
        uint256 prevHashChain = proof[2];
        uint256 prevRoot = proof[3];
        uint256 newIndex = proof[4];
        uint256 newHashChain = proof[5];
        uint256 newRoot = proof[6];

        require(prevIndex == transferIndex, "stale index");
        require(prevHashChain == transferHashChain, "stale hash chain");
        require(prevRoot == transferRoot, "stale root");
        require(newIndex > prevIndex, "no progress");
        require(newHashChain == reservedHashChain, "hash chain mismatch");
        require(newIndex == reservedIndex, "hash index mismatch");

        require(rootTransitionVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        transferRoot = newRoot;
        transferIndex = newIndex;
        transferHashChain = newHashChain;
    }

    /// Single-leaf epoch — Groth16 instead of the Nova decider (which needs >= 2 steps).
    function updateRootSingle(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata pubSignals
    ) external {
        require(pubSignals[0] == transferIndex, "stale index");
        require(pubSignals[1] == transferHashChain, "stale hash chain");
        require(pubSignals[2] == transferRoot, "stale root");
        require(pubSignals[3] == pubSignals[0] + 1, "not single-step");
        require(pubSignals[4] == reservedHashChain, "hash chain mismatch");
        require(pubSignals[3] == reservedIndex, "hash index mismatch");

        require(singleRootTransitionVerifier.verifyProof(pA, pB, pC, pubSignals), "invalid proof");

        transferRoot = pubSignals[5];
        transferIndex = pubSignals[3];
        transferHashChain = pubSignals[4];
    }

    /// proof = [i, z0[0..4], zi[0..4], 25 decider elements]
    /// z0[0] is the fold's start index — ordering token only, not checked here.
    function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256[34] calldata proof) external {
        require(chainId == block.chainid, "wrong chain");

        uint256 recipient = computeRecipient(chainId, addr, tweak);

        uint256 root = proof[3];           // z0[2] = transferRoot
        uint256 proofRecipient = proof[4]; // z0[3] = recipient
        uint256 sum = proof[6];            // zi[1] = lifetime sum for recipient (this tree)

        require(root == transferRoot, "unknown root");
        require(proofRecipient == recipient, "recipient mismatch");

        require(withdrawVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        uint256 delta = sum - totalWithdrawn[recipient];
        require(delta > 0, "nothing to withdraw");
        totalWithdrawn[recipient] = sum;

        token.teleport(addr, delta);
    }

    /// pubSignals = [transferRoot, recipient, indexWithOffset, value]
    function withdrawSingle(
        uint256 chainId,
        address addr,
        bytes32 tweak,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external {
        require(chainId == block.chainid, "wrong chain");

        uint256 recipient = computeRecipient(chainId, addr, tweak);

        uint256 transferRoot_ = pubSignals[0];
        uint256 proofRecipient = pubSignals[1];
        uint256 sum = pubSignals[3];

        require(transferRoot_ == transferRoot, "unknown root");
        require(proofRecipient == recipient, "recipient mismatch");

        require(singleWithdrawVerifier.verifyProof(pA, pB, pubSignals), "invalid proof");

        uint256 delta = sum - totalWithdrawn[recipient];
        require(delta > 0, "nothing to withdraw");
        totalWithdrawn[recipient] = sum;

        token.teleport(addr, delta);
    }

    /// Withdraw from the previous generation's frozen tree. Its frontier is
    /// immutable, so both state reads are safe to take lazily, per recipient.
    function withdrawLegacy(uint256 chainId, address addr, bytes32 tweak, uint256[34] calldata proof) external {
        require(address(prev) != address(0), "no prev");
        require(proof[3] == prev.transferRoot(), "unknown legacy root");
        require(withdrawVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        _settleLegacy(chainId, addr, tweak, proof[4], proof[6]);
    }

    function withdrawLegacySingle(
        uint256 chainId,
        address addr,
        bytes32 tweak,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external {
        require(address(prev) != address(0), "no prev");
        require(pubSignals[0] == prev.transferRoot(), "unknown legacy root");
        require(singleWithdrawVerifier.verifyProof(pA, pB, pC, pubSignals), "invalid proof");

        _settleLegacy(chainId, addr, tweak, pubSignals[1], pubSignals[3]);
    }

    function _settleLegacy(
        uint256 chainId,
        address addr,
        bytes32 tweak,
        uint256 proofRecipient,
        uint256 sum
    ) internal {
        require(chainId == block.chainid, "wrong chain");
        uint256 recipient = computeRecipient(chainId, addr, tweak);
        require(proofRecipient == recipient, "recipient mismatch");

        uint256 delta = sum - prev.totalWithdrawn(recipient) - legacyWithdrawn[recipient];
        require(delta > 0, "nothing to withdraw");
        legacyWithdrawn[recipient] += delta;

        token.teleport(addr, delta);
    }

    function computeRecipient(uint256 chainId, address addr, bytes32 tweak)
        public
        pure
        returns (uint256)
    {
        bytes32 h = keccak256(abi.encodePacked(uint64(chainId), addr, tweak));
        return uint256(h) & HASH_CHAIN_MASK;
    }
}
