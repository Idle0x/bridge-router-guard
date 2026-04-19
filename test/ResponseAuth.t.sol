
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/BridgeRouterGuardResponse.sol";
import "../src/mocks/MockBridgeVault.sol";
import "../src/mocks/MockTokenGateway.sol";
import "../src/mocks/MockBridgeRouter.sol";

contract ResponseAuthTest is Test {
    MockBridgeVault vault;
    MockTokenGateway gateway;
    MockBridgeRouter router;
    BridgeRouterGuardResponse response;

    address owner = address(this);
    address operator = address(0x1111);
    address unauthorized = address(0xBAD);

    function setUp() public {
        vault = new MockBridgeVault();
        gateway = new MockTokenGateway();
        router = new MockBridgeRouter();
        
        // The address deploying the contract becomes the owner
        response = new BridgeRouterGuardResponse(address(vault), address(gateway), address(router));
        
        // Authorize our test operator
        response.setOperator(operator, true);

        // Fast-forward the EVM past the initial 33-block cooldown period.
        // Foundry starts at block 1. Without this, the very first freeze fails.
        vm.roll(40);
    }

    // ─── Operator Execution Tests ─────────────────────────────────────────────

    function test_snapFreeze_revertsIfNotOperator() public {
        vm.prank(unauthorized);
        vm.expectRevert("not authorized operator");
        response.snapFreeze(0, 0, false);
    }

    function test_snapFreeze_succeedsIfOperator() public {
        vm.prank(operator);
        response.snapFreeze(1000 ether, 0, false);
        
        assertTrue(vault.paused(), "Vault should be paused");
        assertTrue(gateway.paused(), "Gateway should be paused");
        assertTrue(router.paused(), "Router should be paused");
    }

    function test_snapFreeze_revertsInCooldown() public {
        vm.startPrank(operator);
        
        // First freeze succeeds
        response.snapFreeze(1000 ether, 0, false);
        
        // Attempt second freeze immediately (same block)
        vm.expectRevert("cooldown active");
        response.snapFreeze(1000 ether, 0, false);

        // Advance 32 blocks (still in cooldown, 33 needed)
        vm.roll(block.number + 32);
        vm.expectRevert("cooldown active");
        response.snapFreeze(1000 ether, 0, false);

        // Advance 1 more block (cooldown cleared)
        vm.roll(block.number + 1);
        response.snapFreeze(1000 ether, 0, false); // Should succeed
        
        vm.stopPrank();
    }

    // ─── Admin Role Tests ─────────────────────────────────────────────────────

    function test_setOperator_revertsIfNotOwner() public {
        vm.prank(unauthorized);
        vm.expectRevert("not owner");
        response.setOperator(unauthorized, true);
    }

    function test_setOperator_succeedsIfOwner() public {
        response.setOperator(unauthorized, true);
        assertTrue(response.authorizedOperators(unauthorized));
    }

    // ─── Two-Step Ownership Tests ─────────────────────────────────────────────

    function test_ownershipTransfer_twoStepSuccess() public {
        address newOwner = address(0x2222);
        
        // Step 1: Owner initiates transfer
        response.transferOwnership(newOwner);
        assertEq(response.pendingOwner(), newOwner);
        assertEq(response.owner(), owner, "Owner should not change until accepted");

        // Step 2: New owner accepts
        vm.prank(newOwner);
        response.acceptOwnership();
        
        assertEq(response.owner(), newOwner, "Ownership failed to transfer");
        assertEq(response.pendingOwner(), address(0), "Pending owner not cleared");
    }

    function test_ownershipTransfer_revertsIfUnauthorizedAccept() public {
        address newOwner = address(0x2222);
        response.transferOwnership(newOwner);

        // Random address tries to hijack the pending transfer
        vm.prank(unauthorized);
        vm.expectRevert("not pending owner");
        response.acceptOwnership();
    }

    function test_ownershipTransfer_cancelWorks() public {
        address newOwner = address(0x2222);
        response.transferOwnership(newOwner);
        assertEq(response.pendingOwner(), newOwner);

        // Owner changes their mind
        response.cancelOwnershipTransfer();
        assertEq(response.pendingOwner(), address(0), "Pending owner should be zeroed");
    }
}
