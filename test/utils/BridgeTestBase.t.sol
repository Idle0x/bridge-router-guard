// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/mocks/MockBridgeVault.sol";
import "../../src/mocks/MockTokenGateway.sol";
import "../../src/mocks/MockBridgeRouter.sol";
import "../../src/TestableBridgeRouterGuardTrap.sol";
import "../../src/TestableBridgeRouterGuardResponse.sol";

contract BridgeTestBase is Test {
    MockBridgeVault vault;
    MockTokenGateway gateway;
    MockBridgeRouter router;
    TestableBridgeRouterGuardTrap trap;
    TestableBridgeRouterGuardResponse response;

    address owner = address(1);
    address operator = address(2);

    function setUp() public virtual {
        vm.startPrank(owner);
        vault = new MockBridgeVault();
        gateway = new MockTokenGateway();
        router = new MockBridgeRouter();

        trap = new TestableBridgeRouterGuardTrap(address(vault), address(gateway), address(router));
        response = new TestableBridgeRouterGuardResponse(address(vault), address(gateway), address(router));

        response.setOperator(operator, true);
        vm.stopPrank();
    }
}
