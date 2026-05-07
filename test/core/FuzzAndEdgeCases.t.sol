// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// FuzzAndEdgeCases.t.sol — Property-based boundary testing + ResponseAuth tests
// ─────────────────────────────────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════════════════
// FuzzAndEdgeCasesTest — Property-based boundary testing for trap logic
// ══════════════════════════════════════════════════════════════════════════════
contract FuzzAndEdgeCasesTest is BridgeTestBase {

    // Any drain mismatch at or below threshold must never trigger
    function testFuzz_subThresholdDrainMismatch_neverTriggers(uint256 delta) public view {
        delta = bound(delta, 0, 999 ether);
        // Provide 100 ETH credit growth to bypass zero-backing hard trigger
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            delta + 100 ether, 100 ether, 0, 0, 0, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Sub-threshold drain mismatch must never trigger");
    }

    // Any drain mismatch above threshold must always trigger
    function testFuzz_superThresholdDrainMismatch_alwaysTriggers(uint256 delta) public view {
        delta = bound(delta, 1_000 ether + 1, type(uint128).max);
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            delta, 0, 0, 0, 0, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Super-threshold drain mismatch must always trigger");
    }

    // Balanced counters (no mismatch) must never trigger regardless of absolute values
    function testFuzz_balancedCounters_neverTrigger(uint256 value) public view {
        value = bound(value, 0, type(uint128).max);
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            value, value, value, value, value, value, value, value  // all balanced
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Balanced counters must never trigger regardless of absolute value");
    }

    // Any phantom mint mismatch at or below threshold must never trigger
    function testFuzz_subThresholdMintMismatch_neverTriggers(uint256 delta) public view {        delta = bound(delta, 0, 9_999 ether);
        // Provide 100 ETH auth growth to bypass zero-backing hard trigger
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, delta + 100 ether, 100 ether, 0, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Sub-threshold mint mismatch must never trigger");
    }

    // Any phantom mint above threshold must always trigger
    function testFuzz_superThresholdMintMismatch_alwaysTriggers(uint256 delta) public view {
        delta = bound(delta, 10_000 ether + 1, type(uint128).max);
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, delta, 0, 0, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Super-threshold mint mismatch must always trigger");
    }

    // Any unauthorized router execution must trigger immediately (single sample)
    function testFuzz_anyUnauthorizedExec_alwaysTriggers(uint256 execCount) public view {
        execCount = bound(execCount, 1, 1000);
        bytes[] memory data = new bytes[](1);
        data[0] = _enc(0, 0, 0, 0, execCount, 0, 0, 0); // executed > validated
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Any unauthorized router execution must trigger");
    }

    function test_malformedData_noRevert() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = hex"deadbeef";
        data[1] = hex"cafebabe";
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Malformed data must not revert");
    }

    function test_emptyFirstSample_noRevert() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = bytes("");
        data[1] = _enc(500 ether, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Empty first sample must not revert");
    }

    function test_allTargetsAlreadyPaused_snapFreezeNoRevert() public {
        vault.emergencyPause();
        gateway.emergencyPause();
        router.emergencyPause();        vm.prank(operator);
        response.snapFreeze(0, 0, 0, 0); // must not revert on already-paused targets
    }

    function test_partiallyPaused_remainingGetPaused() public {
        vault.emergencyPause();
        // gateway and router not yet paused
        vm.prank(operator);
        response.snapFreeze(0, 0, 0, 0);
        assertTrue(vault.paused(), "Vault already paused -> stays paused");
        assertTrue(gateway.paused(), "Gateway gets paused");
        assertTrue(router.paused(), "Router gets paused");
    }
}


// ══════════════════════════════════════════════════════════════════════════════
// ResponseAuthTest — Operator authorization, cooldown, ownership transfer tests
// ══════════════════════════════════════════════════════════════════════════════
contract ResponseAuthTest is BridgeTestBase {

    address internal newOwner    = address(0x2222);
    address internal unauthorized = address(0xBADF00D);

    // ── Operator authorization ─────────────────────────────────────────────────

    function test_snapFreeze_revertsIfNotOperator() public {
        vm.prank(unauthorized);
        vm.expectRevert("not authorized operator");
        response.snapFreeze(0, 0, 0, 0);
    }

    function test_snapFreeze_succeedsIfOperator() public {
        vm.prank(operator);
        response.snapFreeze(1_000 ether, 0, 0, 0);
        assertTrue(vault.paused(),   "Vault paused by operator");
        assertTrue(gateway.paused(), "Gateway paused by operator");
        assertTrue(router.paused(),  "Router paused by operator");
    }

    function test_snapFreeze_revertsInCooldown() public {
        vm.startPrank(operator);

        response.snapFreeze(1_000 ether, 0, 0, 0);

        vm.expectRevert("cooldown active");
        response.snapFreeze(1_000 ether, 0, 0, 0);

        vm.roll(block.number + 32); // 32 blocks: still in cooldown
        vm.expectRevert("cooldown active");        response.snapFreeze(1_000 ether, 0, 0, 0);

        vm.roll(block.number + 1); // 33 blocks total: cooldown cleared
        // Already paused — emergencyPause is idempotent, snapFreeze must not revert
        response.snapFreeze(1_000 ether, 0, 0, 0);

        vm.stopPrank();
    }

    // ── Admin role management ──────────────────────────────────────────────────

    function test_setOperator_revertsIfNotOwner() public {
        vm.prank(unauthorized);
        vm.expectRevert("not owner");
        response.setOperator(unauthorized, true);
    }

    function test_setOperator_succeedsIfOwner() public {
        response.setOperator(unauthorized, true);
        assertTrue(response.authorizedOperators(unauthorized),
                   "Operator must be authorized after setOperator");
    }

    function test_setOperator_revokeWorks() public {
        response.setOperator(operator, false);
        assertFalse(response.authorizedOperators(operator), "Operator must be revoked");

        vm.prank(operator);
        vm.expectRevert("not authorized operator");
        response.snapFreeze(0, 0, 0, 0);
    }

    // ── Two-step ownership ────────────────────────────────────────────────────

    function test_ownershipTransfer_twoStep_success() public {
        response.transferOwnership(newOwner);
        assertEq(response.pendingOwner(), newOwner, "Pending owner set");
        assertEq(response.owner(), address(this),   "Current owner unchanged");

        vm.prank(newOwner);
        response.acceptOwnership();

        assertEq(response.owner(),        newOwner,    "Ownership transferred");
        assertEq(response.pendingOwner(), address(0),  "Pending cleared");
    }

    function test_ownershipTransfer_revertsIfUnauthorizedAccept() public {
        response.transferOwnership(newOwner);

        vm.prank(unauthorized);        vm.expectRevert("not pending owner");
        response.acceptOwnership();
    }

    function test_ownershipTransfer_cancelWorks() public {
        response.transferOwnership(newOwner);
        assertEq(response.pendingOwner(), newOwner);

        response.cancelOwnershipTransfer();
        assertEq(response.pendingOwner(), address(0), "Pending owner cleared after cancel");
    }

    function test_payloadSemantics_emittedValuesAreDeltas() public {
        // VELOCITY FIX VALIDATION (reviewer finding #3):
        // AttackPrevented must emit actual deltas, not cumulative totals.
        vault.executeDirectWithdrawal(attacker, 1_500 ether);

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (, bytes memory payload) = trap.shouldRespond(data);

        (uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain) =
            abi.decode(payload, (uint256, uint256, uint256, uint256));

        assertEq(drainDelta,        1_500 ether, "drainDelta must be the mismatch delta, not cumulative");
        assertEq(mintDelta,         0,           "No mint delta");
        assertEq(unauthorizedExecs, 0,           "No router exec");
        assertEq(reserveDrain,      0,           "No reserve drain");

        vm.prank(operator);
        vm.expectEmit(true, false, false, true);
        emit BridgeRouterGuardResponse.AttackPrevented(
            operator, drainDelta, mintDelta, unauthorizedExecs, reserveDrain, block.number
        );
        response.snapFreeze(drainDelta, mintDelta, unauthorizedExecs, reserveDrain);
    }
}
