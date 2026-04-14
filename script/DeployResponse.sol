// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/BridgeRouterGuardResponse.sol";

contract DeployResponse is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        BridgeRouterGuardResponse response = new BridgeRouterGuardResponse();

        vm.stopBroadcast();

        console.log("--- RESPONSE ADDRESS ---");
        console.log("RESPONSE_CONTRACT: ", address(response));
    }
}
