// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./BridgeRouterGuardTrap.sol";

contract TestableBridgeRouterGuardTrap is BridgeRouterGuardTrap {
    address public immutable VAULT_TEST;
    address public immutable GATEWAY_TEST;
    address public immutable ROUTER_TEST;

    constructor(address v, address g, address r) {
        VAULT_TEST = v;
        GATEWAY_TEST = g;
        ROUTER_TEST = r;
    }

    function collect() external view override returns (bytes memory) {
        return abi.encode(
            IMockVault(VAULT_TEST).cumulativeWithdrawals(),
            IMockGateway(GATEWAY_TEST).phantomMinted(),
            IMockRouter(ROUTER_TEST).spoofedMessageExecuted()
        );
    }
}
