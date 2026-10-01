// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {zERC20} from "../src/zERC20.sol";
import {USDCVault} from "../src/USDCVault.sol";
import {MockUSDC} from "../mocks/MockUSDC.sol";

contract VaultTest is Test {
    MockUSDC usdc;
    zERC20 token;
    USDCVault vault;

    address alice = address(0xA11CE);

    function setUp() public {
        usdc = new MockUSDC();
        token = new zERC20("Zetta USDC", "zUSDC");
        vault = new USDCVault(usdc, token);

        token.setMinter(address(vault));

        usdc.mint(alice, 1000e6);
    }

    function test_wrap_mints_1to1() public {
        vm.startPrank(alice);
        usdc.approve(address(vault), 100e6);
        vault.wrap(100e6);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 100e6);
        assertEq(usdc.balanceOf(address(vault)), 100e6);
    }

    function test_unwrap_returns_usdc() public {
        vm.startPrank(alice);
        usdc.approve(address(vault), 100e6);
        vault.wrap(100e6);
        vault.unwrap(40e6);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 60e6);
        assertEq(usdc.balanceOf(alice), 940e6);
    }

    function test_unwrap_reverts_without_balance() public {
        vm.startPrank(alice);
        vm.expectRevert();
        vault.unwrap(1e6);
        vm.stopPrank();
    }
}
