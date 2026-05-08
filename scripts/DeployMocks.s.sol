// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "src/mocks/core/MockERC20.sol";
import "src/mocks/core/MockSourceChainOracle.sol";
import "src/mocks/core/MockMessageValidator.sol";
import "src/mocks/core/MockBridgeVault.sol";
import "src/mocks/core/MockTokenGateway.sol";
import "src/mocks/core/MockBridgeRouter.sol";
import "src/mocks/concepts/MockLendingPool.sol";
import "src/mocks/concepts/MockPrivilegedBridge.sol";
import "src/mocks/concepts/MockUpgradeableGateway.sol";

// ─────────────────────────────────────────────────────────────────────────────
// DeployMocks.s.sol (v3)
//
// Deploys the complete core mock infrastructure in the correct dependency order.
// Run this first. The output addresses go into:
//   - drosera.toml (VAULT, GATEWAY, ROUTER constants)
//   - BridgeRouterGuardTrap.sol (update the three constant addresses)
//   - DeployResponse.s.sol (.env VAULT_ADDR, GATEWAY_ADDR, ROUTER_ADDR)
//
// Wiring order matches the dependency chain in BridgeTestBase.t.sol.
// The deployer becomes the initial validator signer and oracle relayer.
//
// CRITICAL WIRING STEP:
//   oracle.addRelayer(address(validator)) -- binds the validator as an authorized
//   relayer to the oracle. Without this, legitimate flows revert with
//   "Oracle: not relayer" because the oracle enforces onlyRelayer on all
//   register/confirm/consume calls.
//
// Usage:
//   export PRIVATE_KEY=0x...
//   forge script scripts/DeployMocks.s.sol \
//     --rpc-url https://rpc.hoodi.ethpandaops.io/ \
//     --broadcast \
//     --verify
// ─────────────────────────────────────────────────────────────────────────────
contract DeployMocks is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer    = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // ── Step 1: Deploy token ──────────────────────────────────────────────
        MockERC20 token = new MockERC20("Bridged ETH", "bETH", 18);
        console.log("Token deployed to:     ", address(token));
        // ── Step 2: Deploy oracle ─────────────────────────────────────────────
        MockSourceChainOracle oracle = new MockSourceChainOracle();
        console.log("Oracle deployed to:    ", address(oracle));        
        // ── Step 3: Deploy validator (needs oracle) ───────────────────────────
        // requiredSigners = 1 for testnet (PoC). Use >= 3 for production.
        MockMessageValidator validator = new MockMessageValidator(address(oracle), 1);
        console.log("Validator deployed to: ", address(validator));

        // ── CRITICAL: Bind validator as authorized relayer ────────────────────
        // The oracle enforces onlyRelayer on all register/confirm/consume calls.
        // The validator represents the relayer execution surface in v3 architecture.
        // Without this binding, legitimate flows revert with "Oracle: not relayer".
        oracle.addRelayer(address(validator));
        console.log("Validator bound as oracle relayer");

        // ── Step 4: Deploy bridge contracts (need token + validator) ──────────
        MockBridgeVault   vault   = new MockBridgeVault(address(token), address(validator));
        MockTokenGateway  gateway = new MockTokenGateway(address(token), address(validator));
        MockBridgeRouter  router  = new MockBridgeRouter(address(validator));

        console.log("Vault deployed to:     ", address(vault));
        console.log("Gateway deployed to:   ", address(gateway));
        console.log("Router deployed to:    ", address(router));

        // ── Step 5: Wire validator -> bridge contracts ─────────────────────────
        validator.setVault(address(vault));
        validator.setGateway(address(gateway));
        validator.setRouter(address(router));
        console.log("Validator wired to vault/gateway/router");

        // ── Step 6: Authorize bridge contracts as token minters ───────────────
        token.addMinter(address(vault));
        token.addMinter(address(gateway));
        console.log("Vault and Gateway authorized as token minters");

        // ── Step 7: Seed vault with initial liquidity ─────────────────────────
        // Mint 1000 ETH worth of tokens to deployer, then seed vault.
        uint256 seedAmount = 1_000 ether;
        token.mint(deployer, seedAmount);
        token.approve(address(vault), seedAmount);
        vault.seedLiquidity(seedAmount);
        console.log("Vault seeded with 1000 ETH equivalent tokens");

        // ── Step 8: Deploy concept mocks (independent of core mocks) ───────────
        MockLendingPool     lendingPool     = new MockLendingPool();
        MockPrivilegedBridge privBridge     = new MockPrivilegedBridge(1);
        MockUpgradeableGateway upgradeGateway = new MockUpgradeableGateway(address(0));

        console.log("LendingPool deployed to:   ", address(lendingPool));
        console.log("PrivilegedBridge deployed: ", address(privBridge));        console.log("UpgradeableGateway deployed:", address(upgradeGateway));

        vm.stopBroadcast();

        console.log("\n--- DEPLOYMENT COMPLETE ---");
        console.log("Update BridgeRouterGuardTrap.sol constants:");
        console.log("  VAULT   =", address(vault));
        console.log("  GATEWAY =", address(gateway));
        console.log("  ROUTER  =", address(router));
        console.log("\nSet in .env for DeployResponse.s.sol:");
        console.log("  VAULT_ADDR  =", address(vault));        console.log("  GATEWAY_ADDR=", address(gateway));
        console.log("  ROUTER_ADDR =", address(router));
        console.log("\nConcept mock addresses (for drosera.toml extensions):");
        console.log("  LENDING_POOL_ADDR     =", address(lendingPool));
        console.log("  PRIVILEGED_BRIDGE_ADDR=", address(privBridge));
        console.log("  UPGRADE_GATEWAY_ADDR  =", address(upgradeGateway));
    }
}
