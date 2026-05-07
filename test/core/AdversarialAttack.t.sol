// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// AdversarialAttack.t.sol
//
// Tests that attempt to EVADE the detector, establishing structural resilience.
// All evasion attempts that SHOULD fail are documented. Where evasion succeeds,
// it is labeled as a documented limitation.
//
// KEY v3 ALIGNMENT:
//   • All _enc() calls use 8-parameter signature matching CollectOutput
//   • All _buildWindow()/_buildBurstWindow() calls use v3 parameter counts
//   • vault.executeDirectWithdrawal() replaces legacy vault.drain()
//   • CollectOutput structs include reserve fields (Vector 4)
// ─────────────────────────────────────────────────────────────────────────────
contract AdversarialAttackTest is BridgeTestBase {

    // ── Sub-threshold: attacker knows the threshold ───────────────────────────

    function test_normalVaultTraffic_noTrigger() public {
        // 20 × 40 ETH = 800 ETH drained -- below 1000 ETH threshold
        for (uint256 i = 0; i < 20; i++) {
            vault.executeDirectWithdrawal(attacker, 40 ether);
        }
        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Sub-threshold drain must NOT trigger");
    }

    function test_normalGatewayTraffic_noTrigger() public {
        // 50 × 180 ETH = 9000 ETH minted -- below 10000 ETH threshold
        gateway.changeAdmin(attacker, "");
        for (uint256 i = 0; i < 50; i++) {
            vm.prank(attacker);
            gateway.mint(attacker, 180 ether);
        }
        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Sub-threshold phantom mint must NOT trigger");
    }

    // ── Boundary precision ────────────────────────────────────────────────────
    function test_exactVaultThreshold_noTrigger() public view {
        // Exactly 1000 ETH -> does NOT fire (strictly greater-than)
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            1_000 ether, 0, 0, 0, 0, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Exactly 1000 ETH must NOT trigger");
    }

    function test_oneWeiAboveVaultThreshold_triggers() public view {
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            1_000 ether + 1, 0, 0, 0, 0, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "1000 ETH + 1 wei MUST trigger");
    }

    // ── Non-monotonic counter (oracle restart / reorg recovery) ──────────────

    function test_nonMonotonicCounter_noTrigger() public view {
        // Oldest shows 5000 ETH executed. Newest shows 100 ETH.
        // Counter appears to have gone backwards (reorg, reset, or restart).
        // _evaluateMismatches() uses max(0, newest - oldest) -- no underflow.
        // mismatch delta = 0. No trigger.
        bytes[] memory data = _buildWindow(
            5_000 ether, 5_000 ether, 0, 0, 0, 0, 0, 0,  // old: balanced at 5000
            100 ether,   100 ether,  0, 0, 0, 0, 0, 0    // new: appears reset
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Non-monotonic counter must NOT trigger");
    }

    // ── Chunked drain evasion ─────────────────────────────────────────────────

    function test_chunkedDrainAcrossWindow_triggers() public view {
        // Attacker splits drain across window: 1500, 1000, 500, 0 ETH cumulative
        // Window delta = 1500 - 0 = 1500 ETH > 1000 ETH threshold
        bytes[] memory data = new bytes[](4);
        data[0] = _enc(1_500 ether, 0, 0, 0, 0, 0, 0, 0);
        data[1] = _enc(1_000 ether, 0, 0, 0, 0, 0, 0, 0);
        data[2] = _enc(500 ether,   0, 0, 0, 0, 0, 0, 0);
        data[3] = _enc(0,           0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Chunked drain across window MUST trigger");
    }

    function test_twoConsecutiveBursts_triggers() public view {
        // [ADVERSARIAL] Two burst blocks of 450 ETH each.        // Newest: 900. Mid: 450. Oldest: 0.
        // Window total mismatch: 900 ETH < 1000 ETH (bypasses window check)
        // Burst deltas: 450 each, both > 400 ETH burst threshold
        // Consecutive streak = 2 ≥ BURST_COUNT_TRIGGER -> fires
        bytes[] memory data = _buildBurstWindow(
            0, 0, 0, 0,
            450 ether, 0, 0, 0,
            900 ether, 0, 0, 0
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Two consecutive burst intervals MUST trigger");
    }

    // ── Cold start / bootstrap safety ─────────────────────────────────────────

    function test_coldStart_highCumulativeMismatch_noTrigger() public view {
        // Bridge with 50000 ETH pre-existing mismatch on first observe.
        // Single sample -> no baseline -> velocity vectors skip -> no trigger.
        // Vector 3 also 0 -> no trigger.
        bytes[] memory data = new bytes[](1);
        data[0] = _enc(50_000 ether, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Cold start with high pre-existing mismatch must NOT trigger");
    }

    function test_emptyDataArray_noRevert() public view {
        (bool trigger,) = trap.shouldRespond(new bytes[](0));
        assertFalse(trigger, "Empty data must return false, not revert");
    }

    // ── Schema version mismatch ───────────────────────────────────────────────

    function test_wrongSchemaVersion_noTrigger() public view {
        // Sample claims schema version 99 -- should be treated as zeroed struct
        bytes memory wrongSchema = abi.encode(CollectOutput({
            schemaVersion:               99, // wrong
            executedWithdrawals:         50_000 ether,
            validatedInboundCredits:     0,
            cumulativeMinted:            0,
            validatedMintAuthorizations: 0,
            executedMessages:            0,
            gatewayValidatedMessages:    0,
            vaultTokenBalance:           0,
            gatewayTokenSupply:          0
        }));
        bytes[] memory data = new bytes[](2);
        data[0] = wrongSchema;
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Wrong schema version must NOT trigger");    }
}
