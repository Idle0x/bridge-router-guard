// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

contract ResponseAuthTest is BridgeTestBase {
    function test_RevertUnauthorizedOperator() public {
        address attacker = address(0xBAD);

        // Attacker tries to trigger the containment response
        vm.prank(attacker);
        vm.expectRevert("not authorized");
        response.snapFreeze(1000 ether, 0, false);
    }

    function test_RevertUnauthorizedAdmin() public {
        address attacker = address(0xBAD);

        // Attacker tries to authorize themselves as an operator
        vm.prank(attacker);
        vm.expectRevert("not owner");
        response.setOperator(attacker, true);
    }

    function test_OwnerCanSetOperator() public {
        address newOperator = address(0x888);

        // Owner (deployer) successfully adds a new operator
        vm.prank(owner);
        response.setOperator(newOperator, true);

        assertTrue(response.authorizedOperators(newOperator), "Owner failed to set operator");
    }
}
