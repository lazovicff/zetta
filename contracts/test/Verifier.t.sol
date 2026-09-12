// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {zERC20} from "../src/zERC20.sol";
import {Verifier, IRootTransitionVerifier, IWithdrawVerifier} from "../src/Verifier.sol";

contract MockRootVerifier is IRootTransitionVerifier {
    bool public result = true;

    function setResult(bool r) external {
        result = r;
    }

    function verifyOpaqueNovaProof(uint256[32] calldata) external view returns (bool) {
        return result;
    }
}

contract MockWithdrawVerifier is IWithdrawVerifier {
    bool public result = true;

    function setResult(bool r) external {
        result = r;
    }

    function verifyOpaqueNovaProof(uint256[34] calldata) external view returns (bool) {
        return result;
    }
}

contract VerifierTest is Test {
    zERC20 token;
    Verifier verifier;
    MockRootVerifier rootV;
    MockWithdrawVerifier withdrawV;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    uint256 constant INITIAL_ROOT =
        7694308195910501081009121293114024464085863242234210875116972222894508088593;

    function setUp() public {
        token = new zERC20("Zetta USDC", "zUSDC");
        token.mint(alice, 1000 ether);
        verifier = new Verifier(token, INITIAL_ROOT);
        rootV = new MockRootVerifier();
        withdrawV = new MockWithdrawVerifier();
        verifier.setVerifiers(rootV, withdrawV);
        token.setVerifier(address(verifier));
    }

    function _updateRoot(uint256 newRoot) internal {
        uint256[32] memory proof;
        proof[1] = 0;                    // new tree
        proof[2] = verifier.transferHashChain();
        proof[3] = INITIAL_ROOT;         // empty root
        proof[4] = 1 << 18;              // full capacity
        proof[5] = token.burnHashChain();
        proof[6] = newRoot;
        verifier.updateRoot(proof);
    }

    function test_compute_recipient_cross_language() view public {
        address addr = 0x1111111111111111111111111111111111111111;
        bytes32 tweak = 0x2222222222222222222222222222222222222222222222222222222222222222;
        uint256 r = verifier.computeRecipient(31337, addr, tweak);
        assertEq(r, 38947493555405088571125232569743075901989035976403659344180345740786637377);
    }

    function test_update_root() public {
        vm.startPrank(alice);
        token.transfer(bob, 100 ether);
        token.transfer(bob, 200 ether);
        token.transfer(bob, 300 ether);
        vm.stopPrank();

        uint256 newRoot = 12345;
        _updateRoot(newRoot);

        assertEq(verifier.transferRoots(0), newRoot);
        assertEq(verifier.transferHashChain(), token.burnHashChain());
    }

    function test_update_root_stale_reverts() public {
        vm.prank(alice);
        token.transfer(bob, 100 ether);

        uint256[32] memory proof;
        proof[1] = 1; // wrong prevIndex (stored is 0)
        proof[3] = INITIAL_ROOT;
        proof[4] = token.burnIndex();
        proof[5] = token.burnHashChain();
        proof[6] = 12345;
        vm.expectRevert("not a new tree");
        verifier.updateRoot(proof);
    }

    function test_withdraw_mints_delta() public {
        vm.prank(alice);
        token.transfer(bob, 100 ether);
        _updateRoot(12345);

        bytes32 tweak = 0x2222222222222222222222222222222222222222222222222222222222222222;
        uint256 recipient = verifier.computeRecipient(31337, bob, tweak);
        uint256 sum = 100 ether;

        uint256[34] memory wproof;
        wproof[3] = 12345;     // transferRoot
        wproof[4] = recipient; // recipient
        wproof[6] = sum;       // sum

        uint256 balBefore = token.balanceOf(bob);
        verifier.withdraw(31337, bob, tweak, 0, wproof);
        assertEq(token.balanceOf(bob), balBefore + sum);
        assertEq(verifier.totalWithdrawn(0, recipient), sum);
    }

    function test_withdraw_double_reverts() public {
        vm.prank(alice);
        token.transfer(bob, 100 ether);
        _updateRoot(12345);

        bytes32 tweak = 0x2222222222222222222222222222222222222222222222222222222222222222;
        uint256 recipient = verifier.computeRecipient(31337, bob, tweak);

        uint256[34] memory wproof;
        wproof[3] = 12345;
        wproof[4] = recipient;
        wproof[6] = 100 ether;

        verifier.withdraw(31337, bob, tweak, 0, wproof);

        vm.expectRevert("nothing to withdraw");
        verifier.withdraw(31337, bob, tweak, 0, wproof);
    }

    function test_withdraw_wrong_chain_reverts() public {
        bytes32 tweak = 0x2222222222222222222222222222222222222222222222222222222222222222;
        uint256 recipient = verifier.computeRecipient(31337, bob, tweak);

        uint256[34] memory wproof;
        wproof[3] = 12345;
        wproof[4] = recipient;
        wproof[6] = 100 ether;

        vm.expectRevert("wrong chain");
        verifier.withdraw(99999, bob, tweak, 0, wproof);
    }
}
