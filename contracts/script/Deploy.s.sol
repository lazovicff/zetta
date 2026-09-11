// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {zERC20} from "../src/zERC20.sol";
import {Vault} from "../src/Vault.sol";
import {RewardDistributor} from "../src/RewardDistributor.sol";
import {Verifier, IRootTransitionVerifier, IWithdrawVerifier} from "../src/Verifier.sol";
import {NovaDecider as RootVerifier} from "../src/verifiers/RootTransitionVerifier.sol";
import {NovaDecider as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {MockDAI} from "../mocks/MockDAI.sol";
import {MockSDAI} from "../mocks/MockSDAI.sol";

contract Deploy is Script {
    uint256 constant INITIAL_ROOT =
        7694308195910501081009121293114024464085863242234210875116972222894508088593;

    function run() external {
        vm.startBroadcast();

        MockDAI dai = new MockDAI();
        MockSDAI sdai = new MockSDAI(dai);

        zERC20 token = new zERC20("Zetta DAI", "zDAI");
        Vault vault = new Vault(dai, sdai, token);
        RewardDistributor distributor = new RewardDistributor(token, dai, address(vault));
        vault.setYieldRecipient(address(distributor));
        vault.setProtocolFeeRecipient(msg.sender);

        RootVerifier rootV = new RootVerifier();
        WithdrawVerifier withdrawV = new WithdrawVerifier();
        Verifier verifier = new Verifier(token, INITIAL_ROOT);
        verifier.setVerifiers(
            IRootTransitionVerifier(address(rootV)),
            IWithdrawVerifier(address(withdrawV))
        );

        dai.mint(msg.sender, 1000 ether);
        token.mint(msg.sender, 1000 ether); // before handing over minter

        token.setMinter(address(vault));
        token.setVerifier(address(verifier));

        vm.stopBroadcast();

        console.log("dai       =", address(dai));
        console.log("sdai      =", address(sdai));
        console.log("token     =", address(token));
        console.log("vault     =", address(vault));
        console.log("verifier  =", address(verifier));
        console.log("rootV     =", address(rootV));
        console.log("withdrawV =", address(withdrawV));
    }
}
