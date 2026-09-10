// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {zERC20} from "../src/zERC20.sol";
import {Verifier, IRootTransitionVerifier, IWithdrawVerifier} from "../src/Verifier.sol";
import {NovaDecider as RootVerifier} from "../src/verifiers/RootTransitionVerifier.sol";
import {NovaDecider as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

contract Deploy is Script {
    uint256 constant INITIAL_ROOT =
        7694308195910501081009121293114024464085863242234210875116972222894508088593;

    function run() external {
        vm.startBroadcast();

        zERC20 token = new zERC20("Zetta USDC", "zUSDC");

        RootVerifier rootV = new RootVerifier();
        WithdrawVerifier withdrawV = new WithdrawVerifier();

        Verifier verifier = new Verifier(token, INITIAL_ROOT);
        verifier.setVerifiers(
            IRootTransitionVerifier(address(rootV)),
            IWithdrawVerifier(address(withdrawV))
        );

        token.mint(msg.sender, 1000 ether); // mint to deployer before handing over minter
        token.setMinter(address(verifier));

        vm.stopBroadcast();

        console.log("token     =", address(token));
        console.log("verifier  =", address(verifier));
        console.log("rootV     =", address(rootV));
        console.log("withdrawV =", address(withdrawV));
    }
}
