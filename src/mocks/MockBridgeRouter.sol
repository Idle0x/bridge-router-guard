// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// [EXPLOIT MODEL: Vector 3 — CrossCurve Feb 2026 / Socket Protocol Jan 2024 /
//                            Kelp DAO Apr 2026]
//
// Replicates the ROUTER side of the forged payload execution pattern.
//
// CrossCurve (Feb 2026, ~$3M): the ReceiverAxelar contract was missing access
// control on expressExecute(). An attacker called it directly with a crafted
// payload, bypassing the Axelar gateway entirely. No message proof required.
// See: case-studies/005-crosscurve-feb-2026.md
//
// Socket Protocol (Jan 2024, ~$3.3M): flawed approval logic allowed injection
// of arbitrary transferFrom() calldata via an unsanitized swapExtraData param,
// draining user wallet approvals via the SocketGateway router.
// See: case-studies/003-socket-protocol-jan-2024.md
//
// Kelp DAO (Apr 2026, ~$292M): the trust failure was at the DVN layer rather
// than a missing access control check. Attackers poisoned the RPC nodes used
// by LayerZero Labs' 1-of-1 DVN, causing it to attest a forged cross-chain
// message as valid. The attacker then called lzReceive() on EndpointV2 — the
// exact same execution path as a legitimate LayerZero OFT receive. The DVN
// confirmed it. 116,500 rsETH released. One transaction. One block.
//
// The mechanism of trust failure differs across the three incidents:
//   CrossCurve  — missing function-level access control (anyone could call)
//   Socket      — unsanitized calldata in a publicly callable function
//   Kelp DAO    — compromised off-chain verifier approved a forged message
//
// The on-chain consequence is identical in all three cases: a router-side
// contract executed a payload without valid upstream authorization. This is
// the invariant expressExecute() violates here, and the invariant that
// spoofedMessageExecuted captures.
//
// Note: Kelp DAO occurred after this trap was deployed to Hoodi Testnet. It
// was not anticipated in the original source — the DVN trust-failure pattern
// was identified as a matching case study post-deployment because it produces
// the same on-chain signal as CrossCurve. The trap generalizes correctly.
// See: case-studies/008-kelp-dao-apr-2026.md → Case Study Note
//
// Invariant broken: a router must only execute payloads validated by the
// canonical gateway (or, in LayerZero's model, by an honest multi-DVN quorum).
// expressExecute() has no such check — it executes freely.
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

    // [EXPLOIT EXECUTION — CrossCurve Feb 2026 / Socket Protocol Jan 2024 / Kelp DAO Apr 2026]
    //
    // CrossCurve: ReceiverAxelar.expressExecute() callable by anyone with no
    // gateway validation. Attacker passed a fresh commandId and spoofed
    // sourceChain/sourceAddress to trigger PortalV2.unlock() directly.
    //
    // Socket: performAction() passed user-supplied swapExtraData to a low-level
    // call() without sanitization, enabling transferFrom() injection on approved
    // wallets. Amount=0 bypassed the native balance check.
    //
    // Kelp DAO: lzReceive() called on EndpointV2 with a forged cross-chain
    // message. The 1-of-1 DVN (LayerZero Labs) had been compromised via RPC
    // poisoning and attested the message as valid. The call was structurally
    // indistinguishable from a legitimate OFT receive — the only failure was in
    // the off-chain verifier, not in any on-chain validation step.
    //
    // In all three cases the result is the same: spoofedMessageExecuted = true.
    // → [NEUTRALIZED BY] BridgeRouterGuardTrap.sol shouldRespond():
    //   if (newest.spoofedMessageExecuted) → immediate trigger, no velocity needed.
    //   Hard invariant: one unauthorized execution = immediate snapFreeze.
    function expressExecute(bytes calldata /*payload*/, bytes32 /*proof*/) external {
        require(!paused, "Router paused");
        // [VULNERABILITY] No validation of proof against gateway-approved message root.
        // CrossCurve: no validateContractCall() check.
        // Socket: no calldata sanitization.
        // Kelp DAO: proof check delegated entirely to a single off-chain DVN that
        //           was compromised — functionally equivalent to no check at all.
        spoofedMessageExecuted = true;
    }

    // [RESPONSE TARGET] Called by BridgeRouterGuardResponse.snapFreeze()
    // via the IPausable interface to halt further unauthorized execution.
    function emergencyPause() external {
        paused = true;
    }
}
