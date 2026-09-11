// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";

contract zERC20 is ERC20 {
    uint256 public burnHashChain;
    uint256 public burnIndex;

    uint256 private constant VALUE_LIMIT = 1 << 248;

    address public minter;   // the Vault (wrap/unwrap)
    address public verifier; // the Verifier (teleport)

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
        minter = msg.sender;
        verifier = msg.sender;
    }

    function setMinter(address newMinter) external {
        require(msg.sender == minter, "not minter");
        minter = newMinter;
    }

    function setVerifier(address newVerifier) external {
        require(msg.sender == verifier, "not verifier");
        verifier = newVerifier;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        _burn(from, amount);
    }

    function teleport(address to, uint256 amount) external {
        require(msg.sender == verifier, "not verifier");
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        require(value < VALUE_LIMIT, "value too large");
        super._update(from, to, value);
        if (from != address(0) && to != address(0)) {
            burnHashChain = PoseidonT4.hash([burnHashChain, uint256(uint160(to)), value]);
            burnIndex += 1;
        }
    }
}
