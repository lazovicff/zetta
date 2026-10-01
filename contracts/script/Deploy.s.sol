// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {zERC20} from "../src/zERC20.sol";
import {USDCVault} from "../src/USDCVault.sol";
import {
    Verifier,
    IRootTransitionVerifier,
    IWithdrawVerifier,
    ISingleWithdrawVerifier,
    ISingleRootTransitionVerifier
} from "../src/Verifier.sol";
import {NovaDecider as RootVerifier} from "../src/verifiers/RootTransitionVerifier.sol";
import {NovaDecider as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {Groth16Verifier as SingleWithdrawVerifier} from "../src/verifiers/SingleWithdrawVerifier.sol";
import {Groth16Verifier as SingleRootTransitionVerifier} from "../src/verifiers/SingleRootTransitionVerifier.sol";
import {MockUSDC} from "../mocks/MockUSDC.sol";

contract Deploy is Script {
    uint256 constant INITIAL_ROOT =
        7694308195910501081009121293114024464085863242234210875116972222894508088593;

    function run() external {
        vm.startBroadcast();

        MockUSDC usdc = new MockUSDC();

        zERC20 token = new zERC20("Zetta USDC", "zUSDC");
        USDCVault vault = new USDCVault(usdc, token);

        RootVerifier rootV = new RootVerifier();
        WithdrawVerifier withdrawV = new WithdrawVerifier();
        SingleRootTransitionVerifier singleRootV = new SingleRootTransitionVerifier();
        SingleWithdrawVerifier singleV = new SingleWithdrawVerifier();

        Verifier verifier = new Verifier(token, INITIAL_ROOT);
        verifier.setVerifiers(
            IRootTransitionVerifier(address(rootV)),
            IWithdrawVerifier(address(withdrawV)),
            ISingleWithdrawVerifier(address(singleV)),
            ISingleRootTransitionVerifier(address(singleRootV))
        );

        usdc.mint(msg.sender, 1000e6);
        token.mint(msg.sender, 1000e6); // before handing over minter

        token.setMinter(address(vault));
        token.setVerifier(address(verifier));

        vm.stopBroadcast();

        console.log("usdc      =", address(usdc));
        console.log("token     =", address(token));
        console.log("vault     =", address(vault));
        console.log("verifier  =", address(verifier));
        console.log("rootV     =", address(rootV));
        console.log("withdrawV =", address(withdrawV));
    }
}
