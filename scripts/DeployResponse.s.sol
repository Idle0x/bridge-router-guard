// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "src/core/BridgeRouterGuardResponse.sol";

// ─────────────────────────────────────────────────────────────────────────────
// DeployResponse.s.sol (v3 — orchestrator compatible)
//
// CHANGES FROM PREVIOUS VERSION:
//
//   1. Reads VAULT, GATEWAY, ROUTER (not VAULT_ADDR etc.)
//      The orchestrator sets VAULT/GATEWAY/ROUTER in process.env after running
//      DeployMocks. If this script read VAULT_ADDR, it would use stale values
//      from the .env file instead of the freshly deployed addresses.
//
//   2. console.log format updated to match orchestrator parser exactly:
//        "BridgeRouterGuardResponse deployed at: 0x..."
//      The orchestrator's parseResponseOutput() matches this exact prefix.
//
//   3. DROSERA_EXECUTOR wiring unchanged — reads from env, skips gracefully
//      if not set (can be wired manually later via setOperator).
//
// Usage (manual):
//   export PRIVATE_KEY=0x...
//   export VAULT=0x...         ← use VAULT not VAULT_ADDR
//   export GATEWAY=0x...
//   export ROUTER=0x...
//   export DROSERA_EXECUTOR=0x...
//
//   forge script scripts/DeployResponse.s.sol \
//     --rpc-url https://rpc.hoodi.ethpandaops.io/ \
//     --broadcast
//
// Note: The orchestrator runs this automatically during deployCycle().
// ─────────────────────────────────────────────────────────────────────────────
contract DeployResponse is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        // Read from VAULT/GATEWAY/ROUTER — matches what orchestrator sets in process.env
        // after DeployMocks completes. Do NOT use VAULT_ADDR etc.
        address vault   = vm.envAddress("VAULT");
        address gateway = vm.envAddress("GATEWAY");
        address router  = vm.envAddress("ROUTER");

        // DROSERA_EXECUTOR is optional — can be set later via setOperator
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

        // Wire the Drosera executor as an authorized operator
        if (droseraExecutor != address(0)) {
            response.setOperator(droseraExecutor, true);
            console.log("Drosera executor authorized:", droseraExecutor);
        } else {
            console.log("[!] DROSERA_EXECUTOR not set — wire manually via setOperator");
        }

        vm.stopBroadcast();

        // ─── ORCHESTRATOR-PARSEABLE OUTPUT ─────────────────────────────────────
        // parseResponseOutput() matches this exact prefix. Do not change it.
        console.log("BridgeRouterGuardResponse deployed at:", address(response));

        console.log("VAULT:  ", vault);
        console.log("GATEWAY:", gateway);
        console.log("ROUTER: ", router);
        console.log("Owner:  ", response.owner());
    }
}
