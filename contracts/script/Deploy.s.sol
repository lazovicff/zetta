// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {zERC20} from "../src/zERC20.sol";
import {DAIVault} from "../src/DAIVault.sol";
import {RewardDistributor} from "../src/RewardDistributor.sol";
import {Verifier, IRootTransitionVerifier, IWithdrawVerifier} from "../src/Verifier.sol";
import {NovaDecider as RootVerifier} from "../src/verifiers/RootTransitionVerifier.sol";
import {NovaDecider as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {MockDAI} from "../mocks/MockDAI.sol";
import {MockSDAI} from "../mocks/MockSDAI.sol";

contract Deploy is Script {
    uint256 constant INITIAL_ROOT =
        10941962436777715901943463195175331263348098796018438960955633645115732864202;

    function run() external {
        vm.startBroadcast();

        MockDAI dai = new MockDAI();
        MockSDAI sdai = new MockSDAI(dai);

        zERC20 token = new zERC20("Zetta DAI", "zDAI");
        DAIVault daiVault = new DAIVault(dai, sdai, token);
        RewardDistributor distributor = new RewardDistributor(token, dai, address(daiVault));
        daiVault.setYieldRecipient(address(distributor));
        daiVault.setProtocolFeeRecipient(msg.sender);

        RootVerifier rootV = new RootVerifier();
        WithdrawVerifier withdrawV = new WithdrawVerifier();
        Verifier verifier = new Verifier(token, INITIAL_ROOT);
        verifier.setVerifiers(
            IRootTransitionVerifier(address(rootV)),
            IWithdrawVerifier(address(withdrawV))
        );

        dai.mint(msg.sender, 1000 ether);
        token.mint(msg.sender, 1000 ether); // before handing over minter

        token.setMinter(address(daiVault));
        token.setVerifier(address(verifier));

        vm.stopBroadcast();

        console.log("dai       =", address(dai));
        console.log("sdai      =", address(sdai));
        console.log("token     =", address(token));
        console.log("vault     =", address(daiVault));
        console.log("verifier  =", address(verifier));
        console.log("rootV     =", address(rootV));
        console.log("withdrawV =", address(withdrawV));
    }
}
