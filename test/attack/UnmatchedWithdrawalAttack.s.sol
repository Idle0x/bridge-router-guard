// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../src/mocks/MockBridgeVault.sol";

contract UnmatchedWithdrawalAttack is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy fresh vault for isolated simulation
        address dummyToken = address(0x111);
        MockBridgeVault vault = new MockBridgeVault();

        console.log("--- INITIATING VECTOR 1: UNMATCHED DRAIN ---");

        // Attacker drains 50,000 ETH without a matching source-chain deposit
        vault.removeLiquidity(50000 ether);

        console.log("Result: ", vault.cumulativeWithdrawals() / 1 ether, "ETH removed successfully.");
        console.log("Status: EXPLOIT SUCCESSFUL (TRAP INACTIVE)");

        vm.stopBroadcast();
    }
}
