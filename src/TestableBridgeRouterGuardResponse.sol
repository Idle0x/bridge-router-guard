// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./BridgeRouterGuardResponse.sol";

contract TestableBridgeRouterGuardResponse is BridgeRouterGuardResponse {
    address public immutable VAULT_TEST;
    address public immutable GATEWAY_TEST;
    address public immutable ROUTER_TEST;

    constructor(address v, address g, address r) {
        VAULT_TEST = v;
        GATEWAY_TEST = g;
        ROUTER_TEST = r;
    }

    function snapFreeze(uint256 vaultV, uint256 phantomV, bool spoof) external override onlyOperator {
        IPausable(VAULT_TEST).emergencyPause();
        IPausable(GATEWAY_TEST).emergencyPause();
        IPausable(ROUTER_TEST).emergencyPause();
        emit AttackPrevented(vaultV, phantomV, spoof);
    }
}
