// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {zERC20} from "../src/zERC20.sol";
import {Vault} from "../src/Vault.sol";
import {MockDAI} from "../mocks/MockDAI.sol";
import {MockSDAI} from "../mocks/MockSDAI.sol";

contract VaultTest is Test {
    MockDAI dai;
    MockSDAI sdai;
    zERC20 token;
    Vault vault;

    address alice = address(0xA11CE);

    function setUp() public {
        dai = new MockDAI();
        sdai = new MockSDAI(dai);
        token = new zERC20("Zetta DAI", "zDAI");
        vault = new Vault(dai, sdai, token);

        token.setMinter(address(vault));

        dai.mint(alice, 1000 ether);
    }

    function test_wrap_mints_1to1() public {
        vm.startPrank(alice);
        dai.approve(address(vault), 100 ether);
        vault.wrap(100 ether);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 100 ether);
        assertEq(sdai.balanceOf(address(vault)), 100 ether);
    }

    function test_unwrap_returns_dai() public {
        vm.startPrank(alice);
        dai.approve(address(vault), 100 ether);
        vault.wrap(100 ether);
        vault.unwrap(40 ether);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 60 ether);
        assertEq(dai.balanceOf(alice), 940 ether);
    }

}
