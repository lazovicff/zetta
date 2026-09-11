// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {MockDAI} from "./MockDAI.sol";

/// @notice Mock sDAI: an ERC-4626 vault over DAI that accrues yield on demand.
contract MockSDAI is ERC4626 {
    MockDAI public immutable dai;

    constructor(MockDAI dai_) ERC20("Mock sDAI", "sDAI") ERC4626(dai_) {
        dai = dai_;
    }

    /// Simulate DSR yield: mint `amount` DAI into the vault, raising the share price.
    function accrue(uint256 amount) external {
        dai.mint(address(this), amount);
    }
}
