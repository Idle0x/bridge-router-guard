// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BridgeRouterGuardTrap.sol";

// ─────────────────────────────────────────────────────────────────────────────
// TestableBridgeRouterGuardTrap
//
// CI/CD shadow. Inherits ALL logic from BridgeRouterGuardTrap unchanged.
// Only overrides collect() to read from constructor-injected test addresses
// instead of hardcoded constants.
//
// Why this exists:
//   Drosera requires trap contracts to have no constructor arguments (stateless).
//   But Foundry tests need to inject mock addresses for isolated testing.
//   This wrapper solves both constraints: production uses constants, tests use injection.
//
// Architecture note:
//   shouldRespond() and shouldAlert() are pure and address-independent.
//   Only collect() requires address injection. This wrapper overrides only collect().
// ─────────────────────────────────────────────────────────────────────────────
contract TestableBridgeRouterGuardTrap is BridgeRouterGuardTrap {
    address public immutable VAULT_TEST;
    address public immutable GATEWAY_TEST;
    address public immutable ROUTER_TEST;

    constructor(address v, address g, address r) {
        require(v != address(0), "TestableTrap: zero vault");
        require(g != address(0), "TestableTrap: zero gateway");
        require(r != address(0), "TestableTrap: zero router");
        VAULT_TEST   = v;
        GATEWAY_TEST = g;
        ROUTER_TEST  = r;
    }

    // Override collect() to read from test-injected addresses
    function collect() external view override returns (bytes memory) {
        return abi.encode(CollectOutput({
            schemaVersion:               SCHEMA_VERSION,
            executedWithdrawals:         IVault(VAULT_TEST).executedWithdrawals(),
            validatedInboundCredits:     IVault(VAULT_TEST).validatedInboundCredits(),
            cumulativeMinted:            IGateway(GATEWAY_TEST).cumulativeMinted(),
            validatedMintAuthorizations: IGateway(GATEWAY_TEST).validatedMintAuthorizations(),
            executedMessages:            IRouter(ROUTER_TEST).executedMessages(),
            gatewayValidatedMessages:    IRouter(ROUTER_TEST).gatewayValidatedMessages(),
            vaultTokenBalance:           IVault(VAULT_TEST).vaultTokenBalance(),
            gatewayTokenSupply:          IGateway(GATEWAY_TEST).gatewayTokenSupply()
        }));
    }
}
