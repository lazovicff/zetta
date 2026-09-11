// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {zERC20} from "./zERC20.sol";

interface IRewardDistributor {
    function notifyRewardAmount(uint256 reward) external;
}

/// @notice DAI treasury vault: wraps DAI 1:1 into zDAI, holds sDAI as yield-bearing backing,
/// and sweeps the DSR yield to stakers and (optionally) the protocol.
contract DAIVault {
    IERC20 public immutable dai;
    IERC4626 public immutable sdai;
    zERC20 public immutable token;

    address public owner;
    address public yieldRecipient;        // RewardDistributor (stakers)
    address public protocolFeeRecipient;  // protocol treasury

    uint256 public constant MAX_PROTOCOL_FEE_BPS = 2000; // 20%
    uint256 public protocolFeeBps; // 0 by default (no protocol fee)

    uint256 public totalMinted; // cumulative zDAI minted via wrap
    uint256 public totalBurned; // cumulative zDAI burned via unwrap

    constructor(IERC20 dai_, IERC4626 sdai_, zERC20 token_) {
        dai = dai_;
        sdai = sdai_;
        token = token_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setYieldRecipient(address r) external onlyOwner {
        require(r != address(0), "zero recipient");
        yieldRecipient = r;
    }

    function setProtocolFeeRecipient(address r) external onlyOwner {
        require(r != address(0), "zero recipient");
        protocolFeeRecipient = r;
    }

    function setProtocolFeeBps(uint256 bps) external onlyOwner {
        require(bps <= MAX_PROTOCOL_FEE_BPS, "too high");
        protocolFeeBps = bps;
    }

    /// Deposit DAI, receive zDAI 1:1. DAI is converted to sDAI to earn the DSR.
    function wrap(uint256 amount) external {
        dai.transferFrom(msg.sender, address(this), amount);
        dai.approve(address(sdai), amount);
        sdai.deposit(amount, address(this));
        token.mint(msg.sender, amount);
        totalMinted += amount;
    }

    /// Burn zDAI, receive DAI 1:1. sDAI is withdrawn back to DAI.
    function unwrap(uint256 amount) external {
        token.burn(msg.sender, amount);
        sdai.withdraw(amount, msg.sender, address(this));
        totalBurned += amount;
    }

    /// Sweep accumulated DSR yield to stakers, minus the protocol fee (if any). Permissionless.
    function sweepYield() external {
        require(yieldRecipient != address(0), "no recipient");

        uint256 sdaiValue = sdai.previewRedeem(sdai.balanceOf(address(this)));
        uint256 netDeposited = totalMinted - totalBurned;
        uint256 yield = sdaiValue > netDeposited ? sdaiValue - netDeposited : 0;

        uint256 buffer = netDeposited / 100; // 1% safety buffer
        uint256 sweepable = yield > buffer ? yield - buffer : 0;
        require(sweepable > 0, "no yield");

        uint256 protocolShare = sweepable * protocolFeeBps / 10000;
        uint256 userShare = sweepable - protocolShare;

        sdai.withdraw(userShare, yieldRecipient, address(this));
        IRewardDistributor(yieldRecipient).notifyRewardAmount(userShare);

        if (protocolShare > 0) {
            require(protocolFeeRecipient != address(0), "no protocol recipient");
            sdai.withdraw(protocolShare, protocolFeeRecipient, address(this));
        }
    }
}
