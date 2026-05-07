// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "src/core/BridgeRouterGuardResponse.sol";

// ─────────────────────────────────────────────────────────────────────────────
// DeployResponse.s.sol (v3)
//
// Deploys BridgeRouterGuardResponse and wires it to the deployed mocks.
// Must be run AFTER DeployMocks.s.sol.
//
// CRITICAL POST-DEPLOY STEP:
//   This script calls setOperator(DROSERA_EXECUTOR, true) automatically.
//   Without this, the Drosera network can detect but cannot execute snapFreeze().
//   The DROSERA_EXECUTOR address is read from .env.
//
//   If you do not know your Drosera executor address yet, deploy the trap first
//   via `drosera apply`, note the executor address from the Drosera dashboard,
//   then call response.setOperator(executor, true) separately.
//
// Usage:
//   export VAULT_ADDR=0x...
//   export GATEWAY_ADDR=0x...
//   export ROUTER_ADDR=0x...
//   export DROSERA_EXECUTOR=0x...   # address Drosera uses to call snapFreeze
//
//   forge script scripts/DeployResponse.s.sol \
//     --rpc-url https://rpc.hoodi.ethpandaops.io/ \
//     --broadcast \
//     --verify
// ─────────────────────────────────────────────────────────────────────────────
contract DeployResponse is Script {
    function run() external {
        uint256 deployerKey     = vm.envUint("PRIVATE_KEY");
        address vault           = vm.envAddress("VAULT_ADDR");
        address gateway         = vm.envAddress("GATEWAY_ADDR");
        address router          = vm.envAddress("ROUTER_ADDR");
        
        // DROSERA_EXECUTOR is optional at deploy time -- can be set later via setOperator
        address droseraExecutor;
        try vm.envAddress("DROSERA_EXECUTOR") returns (address exec) {
            droseraExecutor = exec;
        } catch {
            droseraExecutor = address(0);
        }
        
        vm.startBroadcast(deployerKey);
        
        BridgeRouterGuardResponse response = new BridgeRouterGuardResponse(
            vault, gateway, router
        );
        
        console.log("Response deployed to:", address(response));
        
        // Wire the Drosera executor as an authorized operator
        if (droseraExecutor != address(0)) {
            response.setOperator(droseraExecutor, true);
            console.log("Drosera executor authorized:", droseraExecutor);
        } else {
            console.log("[!] DROSERA_EXECUTOR not set.");
            console.log("    Run after deployment:");
            console.log("    response.setOperator(<executor_address>, true)");
        }
        
        vm.stopBroadcast();
        
        console.log("\n--- RESPONSE DEPLOYMENT COMPLETE ---");
        console.log("RESPONSE_CONTRACT:", address(response));
        console.log("VAULT:  ", vault);
        console.log("GATEWAY:", gateway);
        console.log("ROUTER: ", router);
        console.log("Owner:  ", response.owner());
        
        console.log("\nUpdate drosera.toml:");
        console.log("  response_contract = \"", address(response), "\"");
    }
}
