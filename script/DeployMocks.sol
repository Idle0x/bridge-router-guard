// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/mocks/MockBridgeVault.sol";
import "../src/mocks/MockTokenGateway.sol";
import "../src/mocks/MockBridgeRouter.sol";

contract DeployMocks is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        MockBridgeVault vault = new MockBridgeVault();
        MockTokenGateway gateway = new MockTokenGateway();
        MockBridgeRouter router = new MockBridgeRouter();

        console.log("Vault deployed to:", address(vault));
        console.log("Gateway deployed to:", address(gateway));
        console.log("Router deployed to:", address(router));

        vm.stopBroadcast();
    }
}
