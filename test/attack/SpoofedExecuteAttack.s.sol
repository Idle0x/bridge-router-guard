// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../src/mocks/MockBridgeRouter.sol";

contract SpoofedExecuteAttack is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        MockBridgeRouter router = new MockBridgeRouter();

        console.log("--- INITIATING VECTOR 3: SPOOFED EXECUTE ---");

        // Attacker forces execution of a payload that skips canonical validation
        router.expressExecute(bytes("spoofed_payload"), bytes32(0));

        console.log("Result: Router spoofed executed:", router.spoofedMessageExecuted());
        console.log("Status: EXPLOIT SUCCESSFUL (TRAP INACTIVE)");

        vm.stopBroadcast();
    }
}
