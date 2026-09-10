// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice ERC-20 with a burn hash chain (zERC20-style on-chain commitment).
/// Every transfer (from != address(0)) extends the chain:
///   hashChain = trim246(sha256(hashChain || to || value))
/// Mints (from == address(0)) are excluded, so verifier withdrawals don't enter the tree.
contract zERC20 is ERC20 {
    uint256 public burnHashChain;
    uint256 public burnIndex;

    uint256 private constant VALUE_LIMIT = 1 << 248;
    uint256 private constant HASH_CHAIN_MASK = (1 << 246) - 1;

    address public minter;

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
        minter = msg.sender;
    }

    function setMinter(address newMinter) external {
        require(msg.sender == minter, "not minter");
        minter = newMinter;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        require(value < VALUE_LIMIT, "value too large");
        super._update(from, to, value);
        if (from != address(0)) {
            burnHashChain =
                uint256(sha256(abi.encodePacked(burnHashChain, to, value))) & HASH_CHAIN_MASK;
            burnIndex += 1;
        }
    }
}
