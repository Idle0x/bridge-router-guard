// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "test/core/utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// VaultDrain.t.sol -- Vector 1: executedWithdrawals - validatedInboundCredits
//
// Case studies: Multichain Jul 2023, Orbit Chain Dec 2023, Force Bridge Jun 2025
//
// KEY v3 IMPROVEMENT:
//   We no longer call a toy `drain()` function. We test `executeDirectWithdrawal()`,
//   which simulates a compromised key moving funds without registering a credit.
//   This creates a real mismatch between `executedWithdrawals` and `validatedInboundCredits`.
//   Payload now includes reserveDrain (Vector 4) for full v3 telemetry alignment.
// ─────────────────────────────────────────────────────────────────────────────
contract VaultDrainTest is BridgeTestBase {

    // ── Normal operation ──────────────────────────────────────────────────────

    function test_normalWithdrawal_noMismatch_noTrigger() public {
        bytes32 eventHash = _makeHash(1);
        _legitimateWithdrawal(eventHash, 500 ether, legitUser);

        vm.prank(legitUser);
        vault.executeWithdrawal(eventHash);

        assertEq(vault.getMismatch(), 0, "No mismatch after legitimate withdrawal");
        assertEq(token.balanceOf(legitUser), 500 ether, "User received tokens");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Legitimate withdrawal must NOT trigger");
    }

    function test_highVolumeLegitimate_noTrigger() public {
        token.mint(address(this), 5_000 ether);
        token.approve(address(vault), 5_000 ether);
        vault.seedLiquidity(5_000 ether);

        for (uint256 i = 0; i < 5; i++) {
            bytes32 h      = _makeHash(100 + i);
            address recip  = address(uint160(0xF000 + i));
            _legitimateWithdrawal(h, 1_000 ether, recip);
            vm.prank(recip);
            vault.executeWithdrawal(h);
        }
        assertEq(vault.getMismatch(), 0, "High-volume legitimate: mismatch must be 0");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "High-volume legitimate must NOT trigger");
    }

    // ── Exploit scenarios ─────────────────────────────────────────────────────

    function test_drain_MultichainPattern_triggers() public {
        // [EXPLOIT: Multichain Jul 2023] MPC keys gone -> executeDirectWithdrawal() with no credit
        uint256 drainAmount = 1_500 ether;
        vault.executeDirectWithdrawal(attacker, drainAmount);

        assertEq(vault.getMismatch(), drainAmount, "Mismatch = drain amount");
        assertEq(token.balanceOf(attacker), drainAmount, "Attacker holds real tokens");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);

        assertTrue(trigger, "Multichain drain MUST trigger");

        (uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain) =
            abi.decode(payload, (uint256, uint256, uint256, uint256));
        assertEq(drainDelta,        drainAmount, "Payload: correct drain delta (not cumulative total)");
        assertEq(mintDelta,         0,           "Payload: no mint delta");
        assertEq(unauthorizedExecs, 0,           "Payload: no router exec");
        assertEq(reserveDrain,      0,           "Payload: no reserve drain");
    }

    function test_drain_exactThreshold_noTrigger() public {
        vault.executeDirectWithdrawal(attacker, 1_000 ether);
        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Exactly 1000 ETH must NOT trigger (> not >=)");
    }

    function test_drain_oneWeiAboveThreshold_triggers() public {
        vault.executeDirectWithdrawal(attacker, 1_000 ether + 1);
        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "1000 ETH + 1 wei MUST trigger");    }

    function test_drain_OrbitChainPattern_parallelDrains_triggers() public {
        // [EXPLOIT: Orbit Chain Dec 2023] 5 parallel asset channels drained
        token.mint(address(this), 2_000 ether);
        token.approve(address(vault), 2_000 ether);
        vault.seedLiquidity(2_000 ether);

        uint256[] memory amounts = new uint256[](5);
        amounts[0] = 250 ether; amounts[1] = 200 ether; amounts[2] = 150 ether;
        amounts[3] = 150 ether; amounts[4] = 280 ether; // total: 1030 ETH

        uint256 totalDrained;
        for (uint256 i = 0; i < amounts.length; i++) {
            vault.executeDirectWithdrawal(attacker, amounts[i]);
            totalDrained += amounts[i];
        }

        assertEq(vault.getMismatch(), totalDrained, "Mismatch = all parallel drains");
        assertEq(token.balanceOf(attacker), totalDrained, "Attacker holds all tokens");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Orbit Chain parallel drain MUST trigger");
    }

    function test_drain_interleavedLegit_onlyMismatchCounts() public {
        // Legitimate 800 ETH through the bridge -- mismatch stays 0
        bytes32 legitHash = _makeHash(99);
        _legitimateWithdrawal(legitHash, 800 ether, legitUser);
        vm.prank(legitUser);
        vault.executeWithdrawal(legitHash);
        assertEq(vault.getMismatch(), 0, "After legit: no mismatch");

        // Exploit: 600 ETH unauthorized drain
        vault.executeDirectWithdrawal(attacker, 600 ether);
        assertEq(vault.getMismatch(), 600 ether, "Mismatch = exploit portion only");

        // Window delta from the legit-baseline: 600 ETH < 1000 ETH -> no trigger yet
        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(800 ether, 800 ether, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "600 ETH mismatch delta below threshold must NOT trigger");

        // Drain another 500 ETH -> mismatch delta = 1100 ETH -> trigger
        token.mint(address(this), 500 ether);
        token.approve(address(vault), 500 ether);        vault.seedLiquidity(500 ether);
        vault.executeDirectWithdrawal(attacker, 500 ether);

        bytes[] memory data2 = new bytes[](2);
        data2[0] = trap.collect();
        data2[1] = _enc(800 ether, 800 ether, 0, 0, 0, 0, 0, 0);
        (bool trigger2,) = trap.shouldRespond(data2);
        assertTrue(trigger2, "1100 ETH mismatch delta MUST trigger");
    }

    // ── Burst detection ───────────────────────────────────────────────────────

    function test_consecutiveBursts_trigger() public view {
        // Two consecutive intervals with 450 ETH mismatch each (> 400 ETH burst threshold)
        // Window total: 900 ETH (< 1000 ETH) -- window check alone would NOT fire
        // Burst streak = 2 -> burst detector fires
        bytes[] memory data = _buildBurstWindow(
            0,         0,  0, 0,
            450 ether, 0,  0, 0,
            900 ether, 0,  0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Two consecutive bursts MUST trigger burst detector");
    }

    function test_nonConsecutiveBursts_noTrigger() public view {
        // [CONSECUTIVENESS FIX] Burst at newest->mid, gap at mid->oldest.
        // Streak resets on gap. streak = 1, not 2. No trigger.
        bytes[] memory data = _buildBurstWindow(
            0,         0,  0, 0,   // oldest: 0 (gap after this)
            0,         0,  0, 0,   // mid: 0 (gap -- resets streak)
            450 ether, 0,  0, 0    // newest: burst
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Non-consecutive bursts must NOT trigger (consecutiveness fix)");
    }

    // ── Bootstrap safety ──────────────────────────────────────────────────────

    function test_coldStart_singleSample_noTrigger() public view {
        bytes[] memory data = new bytes[](1);
        data[0] = _enc(50_000 ether, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Cold start single sample must NOT trigger velocity vectors");
    }

    function test_emptyData_noRevert() public view {
        (bool trigger,) = trap.shouldRespond(new bytes[](0));
        assertFalse(trigger, "Empty data must not revert");
    }
    function test_malformedData_noRevert() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = hex"deadbeef";
        data[1] = hex"cafebabe";
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Malformed data must not revert");
    }

    // ── Alert threshold (Hyperbridge Phase 1 scenario) ────────────────────────

    function test_shouldAlert_firesAtLowerThreshold_notRespond() public {
        // 245 ETH -- Hyperbridge Phase 1 sub-threshold drain
        vault.executeDirectWithdrawal(attacker, 245 ether);

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);

        (bool respondFire,) = trap.shouldRespond(data);
        assertFalse(respondFire, "245 ETH must NOT trigger shouldRespond (< 1000 ETH)");

        (bool alertFire,) = trap.shouldAlert(data);
        assertTrue(alertFire, "245 ETH MUST trigger shouldAlert (> 200 ETH alert threshold)");
    }

    // ── Documented limitation ─────────────────────────────────────────────────

    function test_slowDrain_belowThreshold_noTrigger_documentedLimitation() public {
        // Attacker drains 100 ETH/block -- never crosses 1000 ETH window threshold
        for (uint256 i = 0; i < 8; i++) vault.executeDirectWithdrawal(attacker, 100 ether);

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(700 ether, 0, 0, 0, 0, 0, 0, 0); // 7 blocks ago baseline

        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Slow drain correctly NOT caught -- documented static-threshold limitation");
    }

    // ── Vector 4: Reserve Reconciliation ──────────────────────────────────────
    function test_vector4_reserveReconciliation_triggers() public {
        // Simulate silent drain: tokens leave vault but executedWithdrawals doesn't move
        uint256 balanceBefore = token.balanceOf(address(vault));
        vault.directTokenTransfer(attacker, 1_200 ether);
        assertEq(token.balanceOf(address(vault)), balanceBefore - 1_200 ether, "Balance dropped");
        assertEq(vault.executedWithdrawals(), 0, "Counter unchanged");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();        data[1] = _enc(0, 0, 0, 0, 0, 0, balanceBefore, 0);
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger, "Vector 4 MUST trigger on silent reserve drain");
        (,,, uint256 reserveDrain) = abi.decode(payload, (uint256, uint256, uint256, uint256));
        assertEq(reserveDrain, 1_200 ether, "Payload: correct reserve drain delta");
    }

    // ── Post-freeze containment ───────────────────────────────────────────────

    function test_snapFreeze_haltsSubsequentDrains() public {
        vault.executeDirectWithdrawal(attacker, 1_500 ether);

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger);

        (uint256 d, uint256 m, uint256 u, uint256 r) = abi.decode(payload, (uint256, uint256, uint256, uint256));
        vm.prank(operator);
        response.snapFreeze(d, m, u, r);

        assertTrue(vault.paused(),   "Vault must be paused");
        assertTrue(gateway.paused(), "Gateway must be paused");
        assertTrue(router.paused(),  "Router must be paused");

        vm.expectRevert("MockBridgeVault: paused");
        vault.executeDirectWithdrawal(attacker, 100 ether);
    }
}
