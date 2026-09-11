// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {zERC20} from "./zERC20.sol";

/// Nova+CycleFold decider verifier, root-transition circuit (z_len = 3).
interface IRootTransitionVerifier {
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
}

/// Nova+CycleFold decider verifier, withdraw circuit (z_len = 4).
interface IWithdrawVerifier {
    function verifyOpaqueNovaProof(uint256[34] calldata proof) external view returns (bool);
}

contract Verifier {
    zERC20 public token;

    uint256 public transferRoot;
    uint256 public transferIndex;
    uint256 public transferHashChain;

    mapping(uint256 => uint256) public totalWithdrawn;

    IRootTransitionVerifier public rootTransitionVerifier;
    IWithdrawVerifier public withdrawVerifier;

    uint256 public immutable INITIAL_ROOT;
    address public owner;

    uint256 private constant HASH_CHAIN_MASK = (1 << 246) - 1;

    constructor(zERC20 token_, uint256 initialRoot_) {
        token = token_;
        INITIAL_ROOT = initialRoot_;
        transferRoot = initialRoot_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setVerifiers(IRootTransitionVerifier root_, IWithdrawVerifier withdraw_) external onlyOwner {
        rootTransitionVerifier = root_;
        withdrawVerifier = withdraw_;
    }

    /// proof = [i, z0[0..3], zi[0..3], 25 decider elements]
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
        require(newIndex == token.burnIndex(), "index mismatch");
        require(newHashChain == token.burnHashChain(), "hash chain mismatch");

        require(rootTransitionVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        transferRoot = newRoot;
        transferIndex = newIndex;
        transferHashChain = newHashChain;
    }

    /// proof = [i, z0[0..4], zi[0..4], 25 decider elements]
    function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256[34] calldata proof) external {
        require(chainId == block.chainid, "wrong chain");

        uint256 recipient = computeRecipient(chainId, addr, tweak);

        uint256 root = proof[3];          // z0[2] = transferRoot
        uint256 proofRecipient = proof[4]; // z0[3] = recipient
        uint256 sum = proof[6];           // zi[1] = sum

        require(root == transferRoot, "stale root");
        require(proofRecipient == recipient, "recipient mismatch");

        require(withdrawVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

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
