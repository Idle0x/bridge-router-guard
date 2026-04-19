// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// FuzzAndEdgeCases.t.sol
// Property-based boundary testing.
// ─────────────────────────────────────────────────────────────────────────────
contract FuzzAndEdgeCasesTest is BridgeTestBase {

    function testFuzz_subThresholdVault_neverTriggers(uint256 delta) public view {
        delta = bound(delta, 0, 1_000 ether);
        (bool trigger,) = trap.shouldRespond(_buildWindow(0, 0, false, delta, 0, false));
        assertFalse(trigger);
    }

    function testFuzz_superThresholdVault_alwaysTriggers(uint256 delta) public view {
        delta = bound(delta, 1_000 ether + 1, type(uint128).max);
        (bool trigger,) = trap.shouldRespond(_buildWindow(0, 0, false, delta, 0, false));
        assertTrue(trigger);
    }

    function testFuzz_subThresholdPhantom_neverTriggers(uint256 delta) public view {
        delta = bound(delta, 0, 10_000 ether);
        (bool trigger,) = trap.shouldRespond(_buildWindow(0, 0, false, 0, delta, false));
        assertFalse(trigger);
    }

    function testFuzz_superThresholdPhantom_alwaysTriggers(uint256 delta) public view {
        delta = bound(delta, 10_000 ether + 1, type(uint128).max);
        (bool trigger,) = trap.shouldRespond(_buildWindow(0, 0, false, 0, delta, false));
        assertTrue(trigger);
    }

    function test_malformedData_noRevert() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = hex"deadbeef";
        data[1] = hex"cafebabe";
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger);
    }

    function test_emptyFirstSample_noRevert() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = bytes("");
        data[1] = abi.encode(CollectOutput(1, 500 ether, 0, false));
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger);
    }

    function test_allTargetsAlreadyPaused_noRevert() public {
        vault.emergencyPause();
        gateway.emergencyPause();
        router.emergencyPause();
        vm.prank(operator);
        response.snapFreeze(0, 0, false); // must not revert
    }

    function test_partiallyPaused_remainingGetPaused() public {
        vault.emergencyPause();
        vm.prank(operator);
        response.snapFreeze(0, 0, false);
        assertTrue(vault.paused());
        assertTrue(gateway.paused());
        assertTrue(router.paused());
    }

    function test_ownershipTransfer_twoStep() public {
        address newOwner = address(0xABCD);
        response.transferOwnership(newOwner);
        assertEq(response.pendingOwner(), newOwner);
        assertEq(response.owner(), address(this));
        vm.prank(newOwner);
        response.acceptOwnership();
        assertEq(response.owner(), newOwner);
        assertEq(response.pendingOwner(), address(0));
    }

    function test_nonPendingOwner_cannotAccept() public {
        response.transferOwnership(address(0xABCD));
        vm.prank(address(0x1234));
        vm.expectRevert("not pending owner");
        response.acceptOwnership();
    }
}
