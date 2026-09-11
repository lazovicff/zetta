// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {zERC20} from "../src/zERC20.sol";
import {DAIVault} from "../src/DAIVault.sol";
import {MockDAI} from "../mocks/MockDAI.sol";
import {MockSDAI} from "../mocks/MockSDAI.sol";

contract VaultTest is Test {
    MockDAI dai;
    MockSDAI sdai;
    zERC20 token;
    DAIVault daiVault;

    address alice = address(0xA11CE);

    function setUp() public {
        dai = new MockDAI();
        sdai = new MockSDAI(dai);
        token = new zERC20("Zetta DAI", "zDAI");
        daiVault = new DAIVault(dai, sdai, token);

        token.setMinter(address(daiVault));

        dai.mint(alice, 1000 ether);
    }

    function test_wrap_mints_1to1() public {
        vm.startPrank(alice);
        dai.approve(address(daiVault), 100 ether);
        daiVault.wrap(100 ether);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 100 ether);
        assertEq(sdai.balanceOf(address(daiVault)), 100 ether);
    }

    function test_unwrap_returns_dai() public {
        vm.startPrank(alice);
        dai.approve(address(daiVault), 100 ether);
        daiVault.wrap(100 ether);
        daiVault.unwrap(40 ether);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 60 ether);
        assertEq(dai.balanceOf(alice), 940 ether);
    }

}
