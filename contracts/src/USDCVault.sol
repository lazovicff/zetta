// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {zERC20} from "./zERC20.sol";

/// @notice USDC reserve vault: wraps USDC 1:1 into zUSDC. USDC is held as backing, no yield.
contract USDCVault {
    using SafeERC20 for IERC20;

    IERC20 public immutable usdc;
    zERC20 public immutable token;

    constructor(IERC20 usdc_, zERC20 token_) {
        usdc = usdc_;
        token = token_;
    }

    /// Deposit USDC, receive zUSDC 1:1.
    function wrap(uint256 amount) external {
        usdc.safeTransferFrom(msg.sender, address(this), amount);
        token.mint(msg.sender, amount);
    }

    /// Burn zUSDC, receive USDC 1:1.
    function unwrap(uint256 amount) external {
        token.burn(msg.sender, amount);
        usdc.safeTransfer(msg.sender, amount);
    }
}
