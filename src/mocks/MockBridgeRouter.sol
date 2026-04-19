// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// [EXPLOIT MODEL: Vector 3 — CrossCurve Feb 2026 / Socket Protocol Jan 2024]
//
// Replicates the ROUTER side of the forged payload execution pattern.
//
// CrossCurve (Feb 2026, ~$3M): the ReceiverAxelar contract was missing access
// control on expressExecute(). An attacker called it directly with a crafted
// payload, bypassing the Axelar gateway entirely. No message proof required.
//
// Socket Protocol (Jan 2024, ~$3.3M): flawed approval logic allowed infinite
// cross-chain execution via unauthorized execute() calls.
//
// Invariant broken: a router must only execute payloads validated by the
// canonical gateway. expressExecute() has no such check — it executes freely.
//
// This is a HARD BOOLEAN INVARIANT. Fires immediately on detection.
// One unauthorized execution is one too many. No velocity window required.
// ─────────────────────────────────────────────────────────────────────────────
contract MockBridgeRouter {
    bool public spoofedMessageExecuted;
    bool public paused; // NOTE: must be named `paused` (not `isPaused`) to satisfy IPausable interface
    mapping(bytes32 => bool) public validatedPayloads;

    // [NORMAL BEHAVIOR] Legitimate execution path.
    // Requires a payload hash previously validated by the gateway.
    // Used in normal-traffic tests to confirm the trap does not fire on
    // legitimate router activity.
    function validatePayload(bytes32 payloadHash) external {
        validatedPayloads[payloadHash] = true;
    }

    function executeValidated(bytes32 payloadHash, bytes calldata /*payload*/) external view {
        require(!paused, "Router paused");
        require(validatedPayloads[payloadHash], "Payload not validated by gateway");
        // Normal execution — does NOT set spoofedMessageExecuted.
    }

    // [EXPLOIT EXECUTION — CrossCurve Feb 2026 / Socket Protocol Jan 2024]
    // Replicates expressExecute() executing without gateway validation.
    // CrossCurve: missing access control on ReceiverAxelar.expressExecute().
    // Socket: flawed approval logic on execute() path.
    // → [NEUTRALIZED BY] BridgeRouterGuardTrap.sol shouldRespond():
    //   if (newest.spoofedMessageExecuted) → immediate trigger, no velocity needed.
    //   Hard invariant: one unauthorized execution = immediate snapFreeze.
    function expressExecute(bytes calldata /*payload*/, bytes32 /*proof*/) external {
        require(!paused, "Router paused");
        // [VULNERABILITY] No validation of proof against gateway-approved message root.
        spoofedMessageExecuted = true;
    }

    // [RESPONSE TARGET] Called by BridgeRouterGuardResponse.snapFreeze()
    // via the IPausable interface to halt further unauthorized execution.
    function emergencyPause() external {
        paused = true;
    }
}
