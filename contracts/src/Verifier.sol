// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {zERC20} from "./zERC20.sol";

interface IRootTransitionVerifier {
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
}

interface IWithdrawVerifier {
    function verifyOpaqueNovaProof(uint256[34] calldata proof) external view returns (bool);
}

interface ISingleWithdrawVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[3] calldata pubSignals
    ) external view returns (bool);
}

contract Verifier {
    zERC20 public token;

    // Single ever-growing tree (depth 32). Frontier = state proven on-chain.
    uint256 public transferRoot;
    uint256 public transferIndex;      // leaves folded into transferRoot
    uint256 public transferHashChain;

    uint256 public reservedHashChain;
    uint256 public reservedIndex;

    mapping(uint256 => uint256) public totalWithdrawn; // recipient => lifetime sum already minted

    IRootTransitionVerifier public rootTransitionVerifier;
    IWithdrawVerifier public withdrawVerifier;
    ISingleWithdrawVerifier public singleWithdrawVerifier;

    address public owner;

    uint256 private constant HASH_CHAIN_MASK = (1 << 246) - 1;

    constructor(zERC20 token_, uint256 initialRoot_) {
        token = token_;
        transferRoot = initialRoot_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setVerifiers(
        IRootTransitionVerifier root_,
        IWithdrawVerifier withdraw_,
        ISingleWithdrawVerifier single_
    ) external onlyOwner {
        rootTransitionVerifier = root_;
        withdrawVerifier = withdraw_;
        singleWithdrawVerifier = single_;
    }

    /// Snapshot the token's burn hash chain so updateRoot proofs have a stable target.
    function reserveHashChain() external onlyOwner {
        reservedIndex = token.burnIndex();
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

    /// proof = [i, z0[0..4], zi[0..4], 25 decider elements]
    /// z0[0] is the fold's start index — ordering token only, not checked here.
    function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256[34] calldata proof) external {
        require(chainId == block.chainid, "wrong chain");

        uint256 recipient = computeRecipient(chainId, addr, tweak);

        uint256 root = proof[3];           // z0[2] = transferRoot
        uint256 proofRecipient = proof[4]; // z0[3] = recipient
        uint256 sum = proof[6];            // zi[1] = lifetime sum for recipient

        require(root == transferRoot, "unknown root");
        require(proofRecipient == recipient, "recipient mismatch");

        require(withdrawVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        uint256 delta = sum - totalWithdrawn[recipient];
        require(delta > 0, "nothing to withdraw");
        totalWithdrawn[recipient] = sum;

        token.teleport(addr, delta);
    }

    /// pubSignals = [transferRoot, recipient, value]
    function withdrawSingle(
        uint256 chainId,
        address addr,
        bytes32 tweak,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[3] calldata pubSignals
    ) external {
        require(chainId == block.chainid, "wrong chain");

        uint256 recipient = computeRecipient(chainId, addr, tweak);

        uint256 transferRoot_ = pubSignals[0];
        uint256 proofRecipient = pubSignals[1];
        uint256 sum = pubSignals[2];

        require(transferRoot_ == transferRoot, "unknown root");
        require(proofRecipient == recipient, "recipient mismatch");

        require(singleWithdrawVerifier.verifyProof(pA, pB, pC, pubSignals), "invalid proof");

        uint256 delta = sum - totalWithdrawn[recipient];
        require(delta > 0, "nothing to withdraw");
        totalWithdrawn[recipient] = sum;

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
