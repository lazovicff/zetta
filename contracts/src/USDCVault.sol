// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {zERC20} from "./zERC20.sol";

/// @notice USDC reserve vault: wraps USDC 1:1 into zUSDC. USDC is held as backing, no yield.
contract USDCVault {
    using SafeERC20 for IERC20;

    IERC20 public immutable USDC;
    zERC20 public immutable TOKEN;

    constructor(IERC20 usdc_, zERC20 token_) {
        USDC = usdc_;
        TOKEN = token_;
    }

    /// Deposit USDC, receive zUSDC 1:1.
    function wrap(uint256 amount) external {
        USDC.safeTransferFrom(msg.sender, address(this), amount);
        TOKEN.mint(msg.sender, amount);
    }

    /// Burn zUSDC, receive USDC 1:1.
    function unwrap(uint256 amount) external {
        TOKEN.burn(msg.sender, amount);
        USDC.safeTransfer(msg.sender, amount);
    }
}
