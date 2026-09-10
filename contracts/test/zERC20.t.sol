// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {zERC20} from "../src/zERC20.sol";

contract zERC20Test is Test {
    zERC20 token;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        token = new zERC20("Zetta USDC", "zUSDC");
        token.mint(alice, 1000 ether);
    }

    function test_transfer_updates_hash_chain() public {
        uint256 before = token.burnHashChain();
        uint256 idxBefore = token.burnIndex();
        vm.prank(alice);
        token.transfer(bob, 100 ether);
        assertEq(token.burnIndex(), idxBefore + 1);
        assertTrue(token.burnHashChain() != before);
    }

    function test_mint_does_not_update_hash_chain() public {
        uint256 before = token.burnHashChain();
        uint256 idxBefore = token.burnIndex();
        token.mint(bob, 50 ether);
        assertEq(token.burnHashChain(), before);
        assertEq(token.burnIndex(), idxBefore);
    }

    function test_value_limit_reverts() public {
        vm.prank(alice);
        vm.expectRevert("value too large");
        token.transfer(bob, 1 << 248);
    }

    function test_hash_chain_deterministic() public {
        zERC20 t2 = new zERC20("Zetta USDC", "zUSDC");
        t2.mint(alice, 1000 ether);
        vm.prank(alice);
        token.transfer(bob, 100 ether);
        vm.prank(alice);
        t2.transfer(bob, 100 ether);
        assertEq(token.burnHashChain(), t2.burnHashChain());
    }

    function test_hash_chain_cross_language() public {
        zERC20 t = new zERC20("Zetta USDC", "zUSDC");
        t.mint(alice, 1000 ether);
        address to = 0x0101010101010101010101010101010101010101;
        vm.prank(alice);
        t.transfer(to, 100);
        assertEq(t.burnHashChain(), 94009485829705651613127649803317583580033047011779242563751609366187085044);
    }

}
