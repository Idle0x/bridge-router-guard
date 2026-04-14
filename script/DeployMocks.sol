// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockBridgeVault.sol";
import "../src/mocks/MockTokenGateway.sol";
import "../src/mocks/MockBridgeRouter.sol";

contract DeployMocks is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        MockERC20 token = new MockERC20();
        MockBridgeVault vault = new MockBridgeVault(address(token));
        MockTokenGateway gateway = new MockTokenGateway();
        MockBridgeRouter router = new MockBridgeRouter();

        vm.stopBroadcast();

        console.log("--- MOCK ADDRESSES TO COPY ---");
        console.log("VAULT:  ", address(vault));
        console.log("GATEWAY:", address(gateway));
        console.log("ROUTER: ", address(router));
    }
}
