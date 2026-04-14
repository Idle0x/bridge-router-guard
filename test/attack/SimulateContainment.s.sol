// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../src/mocks/MockBridgeVault.sol";
import "../../src/mocks/MockTokenGateway.sol";
import "../../src/mocks/MockBridgeRouter.sol";
import "../../src/TestableBridgeRouterGuardTrap.sol";
import "../../src/BridgeRouterGuardResponse.sol";

contract SimulateContainment is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        MockBridgeVault vault = new MockBridgeVault();
        MockTokenGateway gateway = new MockTokenGateway();
        MockBridgeRouter router = new MockBridgeRouter();

        TestableBridgeRouterGuardTrap trap =
            new TestableBridgeRouterGuardTrap(address(vault), address(gateway), address(router));
        BridgeRouterGuardResponse response = new BridgeRouterGuardResponse();

        console.log("Simulated Setup Complete");
        vm.stopBroadcast();
    }
}
