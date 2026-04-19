// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// [EXPLOIT MODEL: Vector 2 — IoTeX ioTube Feb 2026 / Hyperbridge Apr 2026]
//
// Replicates the GATEWAY side of the privilege escalation + phantom mint pattern.
//
// IoTeX ioTube (Feb 2026, ~$4.4M): a validator upgrade bypassed signature
// checks, granting the attacker admin control over the MinterPool. They minted
// tokens with no backing on the source chain.
//
// Hyperbridge (Apr 2026, $237K loss, 1B phantom tokens): an MMR proof replay
// forged a message that granted admin control over bridged DOT. The attacker
// minted 1 billion unbacked tokens.
//
// Invariant broken: minted supply must only increase when a corresponding
// validated cross-chain message exists. mintPhantom() bypasses this check —
// the missing proof verification in both incidents.
//
// The trap detects this by monitoring phantomMinted velocity. A delta exceeding
// PHANTOM_MINT_THRESHOLD signals unbacked minting.
// ─────────────────────────────────────────────────────────────────────────────
contract MockTokenGateway {
    uint256 public phantomMinted;
    bool public paused; // NOTE: must be named `paused` (not `isPaused`) to satisfy IPausable interface
    address public admin;

    event EmergencyPaused(address by);
    event PhantomMinted(uint256 amount);

    constructor() {
        admin = msg.sender;
    }

    // [EXPLOIT STEP 1 — Privilege escalation]
    // Replicates the IoTeX validator upgrade and Hyperbridge MMR proof replay:
    // an attacker gains admin control without proper authorization.
    // No proof verification — the exact missing signature/MMR validation check.
    // NOTE: The trap monitors the downstream effect (phantom mint spike), not
    // this call directly. Admin change alone does not trigger the trap.
    function changeAdmin(address newAdmin, bytes calldata /*proof*/) external {
        // [VULNERABILITY] No proof verification.
        admin = newAdmin;
    }

    // [EXPLOIT STEP 2 — Phantom mint, no backing]
    // Replicates unbacked mint executed after privilege escalation.
    // Hyperbridge: 1B DOT minted here. IoTeX: tokens from MinterPool without backing.
    // → [NEUTRALIZED BY] BridgeRouterGuardTrap.sol shouldRespond():
    //   phantomVelocity = (newest.phantomMinted - oldest.phantomMinted)
    //   isCritical = phantomVelocity > PHANTOM_MINT_THRESHOLD (10,000 ETH)
    function mintPhantom(uint256 amount) external {
        require(!paused, "Gateway paused");
        phantomMinted += amount;
        emit PhantomMinted(amount);
    }

    // [RESPONSE TARGET] Called by BridgeRouterGuardResponse.snapFreeze()
    // via the IPausable interface to halt further phantom minting.
    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}
