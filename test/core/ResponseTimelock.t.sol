// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// ResponseTimelock.t.sol -- Operator authorization timelock tests
//
// Validates the 24-hour timelock on setOperator() in BridgeRouterGuardResponse.
// This hardening prevents instant deauthorization if the owner key is compromised.
//
// KEY BEHAVIOR:
//   • First call after deployment: bypasses timelock (lastOperatorChange == 0)
//   • Subsequent calls: require block.timestamp >= lastOperatorChange + 24 hours
//   • Zero address input: always reverts, regardless of timelock state
//
// This test suite proves the authority model is hardened against instant grief.
// ─────────────────────────────────────────────────────────────────────────────
contract ResponseTimelockTest is BridgeTestBase {

    address internal constant NEW_OPERATOR = address(0x9999);
    address internal constant UNAUTHORIZED = address(0xBADF00D);

    // ── First-call bypass (post-deploy initialization) ───────────────────────

    function test_setOperator_firstCall_bypasses_timelock() public {
        // After deployment, lastOperatorChange == 0, so first call bypasses timelock.
        // This is intentional: allows deployer to authorize Drosera executor immediately.
        response.setOperator(NEW_OPERATOR, true);
        assertTrue(response.authorizedOperators(NEW_OPERATOR), "First call must succeed");
    }

    // ── Subsequent-call enforcement (24-hour delay) ───────────────────────────

    function test_setOperator_subsequentCall_reverts_before_24h() public {
        // First call: succeeds (bypasses timelock)
        response.setOperator(NEW_OPERATOR, true);
        uint256 firstCallTime = block.timestamp;

        // Advance time by 23 hours, 59 minutes, 59 seconds -- still before 24h
        vm.warp(firstCallTime + 24 hours - 1);

        // Second call: must revert because 24h has not elapsed
        vm.prank(response.owner());
        vm.expectRevert("operator timelock active");
        response.setOperator(UNAUTHORIZED, true);
    }

    function test_setOperator_succeeds_after_24h() public {
        // First call: succeeds (bypasses timelock)        response.setOperator(NEW_OPERATOR, true);
        uint256 firstCallTime = block.timestamp;

        // Advance time by exactly 24 hours
        vm.warp(firstCallTime + 24 hours);

        // Second call: must succeed because 24h has elapsed
        vm.prank(response.owner());
        response.setOperator(UNAUTHORIZED, true);
        assertTrue(response.authorizedOperators(UNAUTHORIZED), "Call after 24h must succeed");
    }

    // ── Edge cases ───────────────────────────────────────────────────────────

    function test_setOperator_zeroAddress_reverts() public {
        // Zero address input must always revert, regardless of timelock state
        vm.prank(response.owner());
        vm.expectRevert("zero address");
        response.setOperator(address(0), true);
    }

    function test_setOperator_revertsIfNotOwner() public {
        // Only owner may call setOperator -- timelock check happens after owner check
        vm.prank(UNAUTHORIZED);
        vm.expectRevert("not owner");
        response.setOperator(NEW_OPERATOR, true);
    }

    // ── Integration: operator authorization affects snapFreeze ────────────────

    function test_snapFreeze_requiresAuthorizedOperator() public {
        // Authorize a new operator (first call, bypasses timelock)
        response.setOperator(NEW_OPERATOR, true);

        // NEW_OPERATOR can now call snapFreeze
        vm.prank(NEW_OPERATOR);
        response.snapFreeze(1_000 ether, 0, 0, 0);
        assertTrue(vault.paused(), "Vault must be paused by authorized operator");

    }

    function test_snapFreeze_revertsIfOperatorRevoked() public {
        // Revoke operator authorization
        vm.prank(response.owner());
        response.setOperator(operator, false);

        // operator can no longer call snapFreeze        vm.prank(operator);
        vm.expectRevert("not authorized operator");
        response.snapFreeze(1_000 ether, 0, 0, 0);

    }
}
