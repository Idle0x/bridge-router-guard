// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// AdversarialAttack.t.sol
//
// Tests that attempt to EVADE the detector, establishing structural resilience.
// ─────────────────────────────────────────────────────────────────────────────
contract AdversarialAttackTest is BridgeTestBase {

    function test_normalVaultTraffic_noTrigger() public {
        for (uint256 i = 0; i < 20; i++) vault.removeLiquidity(40 ether);
        bytes[] memory data = _buildWindow(0, 0, false, vault.cumulativeWithdrawals(), 0, false);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Should NOT trigger on sub-threshold normal volume");
    }

    function test_normalGatewayTraffic_noTrigger() public {
        for (uint256 i = 0; i < 50; i++) gateway.mintPhantom(180 ether);
        bytes[] memory data = _buildWindow(0, 0, false, 0, gateway.phantomMinted(), false);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Should NOT trigger on sub-threshold phantom mints");
    }

    function test_exactVaultThreshold_noTrigger() public view {
        bytes[] memory data = _buildWindow(0, 0, false, 1_000 ether, 0, false);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Exactly 1000 ETH should NOT trigger");
    }

    function test_oneWeiAboveVaultThreshold_triggers() public view {
        bytes[] memory data = _buildWindow(0, 0, false, 1_000 ether + 1, 0, false);
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "1000 ETH + 1 wei SHOULD trigger");
    }

    function test_chunkedDrainAcrossWindow_triggers() public view {
        bytes[] memory data = new bytes[](4);
        data[0] = abi.encode(CollectOutput({schemaVersion:1, cumulativeWithdrawals:1500 ether, phantomMinted:0, spoofedMessageExecuted:false}));
        data[1] = abi.encode(CollectOutput({schemaVersion:1, cumulativeWithdrawals:1000 ether, phantomMinted:0, spoofedMessageExecuted:false}));
        data[2] = abi.encode(CollectOutput({schemaVersion:1, cumulativeWithdrawals: 500 ether, phantomMinted:0, spoofedMessageExecuted:false}));
        data[3] = abi.encode(CollectOutput({schemaVersion:1, cumulativeWithdrawals:       0,   phantomMinted:0, spoofedMessageExecuted:false}));
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Chunked 1500 ETH drain SHOULD trigger");
    }

    function test_twoConsecutiveBursts_triggers() public view {
        // [EXPLOIT EXECUTION] Two burst blocks of 450 ETH each.
        // Newest: 900. Mid: 450. Oldest: 0. Total Window Delta = 900 ETH.
        // 900 ETH < 1000 ETH Window Threshold (Bypasses Window Detector)
        // 450 ETH > 400 ETH Burst Threshold (Fires Burst Detector)
        bytes[] memory data = _buildBurstWindow(
            0, 0, false,           // Oldest
            450 ether, 0, false,   // Mid (Delta = 450)
            900 ether, 0, false    // Newest (Delta = 450)
        );
        
        // -> [NEUTRALIZED PURELY BY] shouldRespond() burst count check
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Two consecutive isolated burst blocks SHOULD trigger");
    }

    function test_slowDrain_noTrigger_documentedLimitation() public view {
        bytes[] memory data = new bytes[](8);
        for (uint256 i = 0; i < 8; i++) {
            data[i] = abi.encode(CollectOutput({
                schemaVersion: 1,
                cumulativeWithdrawals: (7 - i) * 100 ether,
                phantomMinted: 0,
                spoofedMessageExecuted: false
            }));
        }
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Slow drain below threshold correctly NOT caught - documented limitation");
    }

    function test_nonMonotonicCounter_noTrigger() public view {
        bytes[] memory data = _buildWindow(5_000 ether, 0, false, 100 ether, 0, false);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Non-monotonic counter should NOT trigger");
    }

    function test_coldStart_highCumulativeValue_noTrigger() public view {
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(CollectOutput(1, 50_000 ether, 0, false));
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Cold start with high cumulative value must NOT trigger");
    }

    function test_emptyDataArray_noTrigger() public view {
        bytes[] memory data = new bytes[](0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Empty data array must return false, not revert");
    }
}
