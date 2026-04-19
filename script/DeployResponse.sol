// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/BridgeRouterGuardResponse.sol";

// Set in .env before running:
//   VAULT_ADDR   = 0x83c9e182b10aC6B62C559F9092C0Cfc12394Ab1E
//   GATEWAY_ADDR = 0x544fFbCde66A95b24829EB6a5e803d27E7737Dc1
//   ROUTER_ADDR  = 0xca324202c796Aa8A5d8Ddcac384852854A253D66

contract DeployResponse is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address vault   = vm.envAddress("VAULT_ADDR");
        address gateway = vm.envAddress("GATEWAY_ADDR");
        address router  = vm.envAddress("ROUTER_ADDR");

        vm.startBroadcast(deployerPrivateKey);
        
        // Passing the required 3 arguments
        BridgeRouterGuardResponse response = new BridgeRouterGuardResponse(vault, gateway, router);
        
        vm.stopBroadcast();

        console.log("--- RESPONSE CONTRACT ---");
        console.log("RESPONSE_CONTRACT:", address(response));
        console.log("VAULT:  ", vault);
        console.log("GATEWAY:", gateway);
        console.log("ROUTER: ", router);
        console.log("Owner:  ", response.owner());
    }
}
