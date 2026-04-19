// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BridgeRouterGuardTrap.sol";

// ─────────────────────────────────────────────────────────────────────────────
// TestableBridgeRouterGuardTrap
//
// CI/CD shadow contract for isolated Foundry testing.
// Inherits ALL logic from BridgeRouterGuardTrap unchanged.
// Only overrides collect() to read from constructor-injected addresses.
//
// Note: shouldRespond() and shouldAlert() are pure and do not need overriding.
// ─────────────────────────────────────────────────────────────────────────────
contract TestableBridgeRouterGuardTrap is BridgeRouterGuardTrap {

    address public immutable VAULT_TEST;
    address public immutable GATEWAY_TEST;
    address public immutable ROUTER_TEST;

    constructor(address v, address g, address r) {
        require(v != address(0), "vault zero");
        require(g != address(0), "gateway zero");
        require(r != address(0), "router zero");
        VAULT_TEST   = v;
        GATEWAY_TEST = g;
        ROUTER_TEST  = r;
    }

    function collect() external view override returns (bytes memory) {
        return abi.encode(CollectOutput({
            schemaVersion:          SCHEMA_VERSION,
            cumulativeWithdrawals:  IMockVault(VAULT_TEST).cumulativeWithdrawals(),
            phantomMinted:          IMockGateway(GATEWAY_TEST).phantomMinted(),
            spoofedMessageExecuted: IMockRouter(ROUTER_TEST).spoofedMessageExecuted()
        }));
    }
}
