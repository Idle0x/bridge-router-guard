// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// RouterSpoof.t.sol -- Vector 3: executedMessages - gatewayValidatedMessages > 0
//
// Case studies: CrossCurve Feb 2026, Socket Protocol Jan 2024, Kelp DAO Apr 2026
//
// KEY v3 IMPROVEMENT:
//   Payload now includes reserveDrain (Vector 4) for full v3 telemetry alignment.
//   All _enc() calls use 8-parameter signature matching CollectOutput.
//   All snapFreeze() calls pass 4 arguments matching v3 response contract.
// ─────────────────────────────────────────────────────────────────────────────
contract RouterSpoofTest is BridgeTestBase {

    // ── Normal operation ──────────────────────────────────────────────────────

    function test_legitimateRouterExecution_noMismatch_noTrigger() public {
        bytes32 eventHash = _makeHash(1);
        bytes32 messageHash = keccak256("legitimate_message");
        _legitimateRouterMessage(eventHash, messageHash);

        assertEq(router.executedMessages(), 1, "One message executed");
        assertEq(router.gatewayValidatedMessages(), 1, "One message validated");
        assertEq(router.getUnauthorizedExecutions(), 0, "No mismatch");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Legitimate router execution must NOT trigger");
    }

    // ── Exploit: CrossCurve / BYPASSED validator pattern ─────────────────────

    function test_routerSpoof_CrossCurvePattern_triggers() public {
        // [EXPLOIT: CrossCurve Feb 2026]
        // expressExecute() called directly. No prior registerValidatedMessage().
        // executedMessages++ but gatewayValidatedMessages stays 0.
        // One unauthorized execution = immediate trigger. No history needed.
        router.expressExecute(hex"deadbeef", bytes32(0));

        assertEq(router.executedMessages(), 1, "One message executed");
        assertEq(router.gatewayValidatedMessages(), 0, "No validation registered");
        assertEq(router.getUnauthorizedExecutions(), 1, "Mismatch = 1");

        // Vector 3 fires with a SINGLE sample -- no baseline needed
        bytes[] memory data = new bytes[](1);        data[0] = trap.collect();
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger, "CrossCurve router spoof MUST trigger with single sample");

        (uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain) =
            abi.decode(payload, (uint256, uint256, uint256, uint256));
        assertEq(unauthorizedExecs, 1, "Payload: one unauthorized execution");
        assertEq(drainDelta, 0, "Payload: no drain");
        assertEq(mintDelta, 0, "Payload: no mint");
        assertEq(reserveDrain, 0, "Payload: no reserve drain");
    }

    function test_multipleUnauthorizedExecutions_eachCounts() public {
        // Each expressExecute() call grows the mismatch
        router.expressExecute(hex"aabb", bytes32(uint256(1)));
        router.expressExecute(hex"ccdd", bytes32(uint256(2)));
        router.expressExecute(hex"eeff", bytes32(uint256(3)));

        assertEq(router.getUnauthorizedExecutions(), 3, "Three unauthorized executions");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Multiple unauthorized executions MUST trigger");
    }

    // ── Kelp DAO pattern (POISONED validator) ────────────────────────────────

    function test_routerSpoof_KelpDAOPoisonedDVNPattern() public {
        // [EXPLOIT: Kelp DAO Apr 2026] DVN RPC nodes poisoned.
        // The validator DID attest the message -- but against a poisoned oracle.
        // registerValidatedMessage() was called (counters appear balanced on router).
        // BUT the vault drain mismatch fires instead.

        // Setup: oracle compromised to POISONED mode
        oracle.compromisePoisoned();
        validator.compromisePoisoned();

        // Attacker creates a forged event hash (never existed on source chain)
        bytes32 forgedEventHash = keccak256("forged_kelp_lzReceive_message");
        bytes32 messageHash = keccak256("forged_message_body");

        // Oracle poisons the event -- will now attest it as confirmed
        oracle.poisonEvent(forgedEventHash, address(token), 116_500 ether, attacker);

        // Poisoned validator registers the message as "validated" (accepts poisoned oracle)
        validator.validateRouterMessage(forgedEventHash, messageHash);

        // Router executes -- counters appear balanced (both increment)
        router.executePoisonedMessage(messageHash, "");
        assertEq(router.executedMessages(), 1, "Message executed");
        assertEq(router.gatewayValidatedMessages(), 1, "Message appears validated");
        assertEq(router.getUnauthorizedExecutions(), 0, "Router counters balanced (Kelp path)");

        // Router mismatch is 0 in the Kelp path -- Vector 3 does NOT fire
        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        // This should NOT fire on Vector 3 alone because router counters are balanced.
        // The vault drain mismatch (Vector 1) fires instead -- see FullExploitSequence.t.sol
        // This test documents the distinction explicitly.
        assertFalse(trigger,
            "Kelp DVN path: router counters balanced -> Vector 3 does not fire alone. "
            "Vector 1 (vault drain) is the detection path for Kelp.");
    }

    function test_noHistory_vector3_stillFires() public {
        // Vector 3 is a hard invariant. Zero history required.
        // Even with a single sample and no baseline, it fires immediately.
        router.expressExecute(hex"ff", bytes32(0));

        bytes[] memory singleSample = new bytes[](1);
        singleSample[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(singleSample);
        assertTrue(trigger, "Vector 3 must fire with single sample (no history needed)");
    }

    function test_snapFreeze_haltsRouter() public {
        router.expressExecute(hex"deadbeef", bytes32(0));

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger);

        (uint256 d, uint256 m, uint256 u, uint256 r) = abi.decode(payload, (uint256, uint256, uint256, uint256));
        vm.prank(operator);
        response.snapFreeze(d, m, u, r);

        assertTrue(router.paused(), "Router must be paused");

        vm.expectRevert("Router paused");
        router.expressExecute(hex"0000", bytes32(0));
    }
}
