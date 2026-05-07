// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// MockPrivilegedBridge  (concept mock -- concepts/ folder)
//
// Validates the claim from 010-architecture-and-extensions.md (Trap 3):
// Monitors failed privileged function calls to detect attacker preparation
// BEFORE any funds move.
//
// Real-world evidence this concept is grounded in:
//
//   Force Bridge (Jun 2025):
//     The attacker made multiple failed attempts to call unlock() and release()
//     over a 6-hour window before the successful drain. These failed calls were
//     on-chain, observable, and produced no withdrawal signal. Vector 1 could not
//     fire. A pre-attack monitor watching failedAttemptCount would have fired
//     with $0 at risk.
//
//   Orbit Chain (Dec 2023):
//     The attacker spent 4 hours confirming key access with micro-transactions
//     (sub-cent probes across multiple asset channels). Different mechanism --
//     the probes succeeded rather than failed -- but the observable pre-drain
//     window is the same class of pre-attack signal.
//
// INTERFACE CONTRACT (read by PreAttackMonitorTrap.collect()):
//   failedAttemptCount()      -> uint256
//   lastUnauthorizedCaller()  -> address
//   failedAttemptsInWindow(uint256) -> uint256
//   lockedReserve()           -> uint256
//
// Design note on why this is a SEPARATE concept trap:
//   BridgeRouterGuardTrap monitors mismatch in executed vs validated values.
//   It cannot fire when validatedInboundCredits hasn't moved (no withdrawal happened).
//   The pre-attack signal is in the ATTEMPT, not the consequence.
//   Two different on-chain signals. Two different traps. Same Drosera operator network.
//
// PRODUCTION DEPLOYMENT NOTE:
//   This is a concept mock. Real bridge contracts must expose the exact view
//   functions above. The trap assumes minimal instrumentation: public failed-
//   attempt tracking, a ring buffer or equivalent for window analysis, and a
//   readable reserve balance. No state writes occur in the trap; this contract
//   only provides the read surface and exploit simulation paths for testing.
//   In production, emergencyPause() must be restricted to a guardian or
//   Drosera response contract address.
// ─────────────────────────────────────────────────────────────────────────────
contract MockPrivilegedBridge {

    // ─── Authorized signers ───────────────────────────────────────────────────
    // In a real bridge: multisig signers, MPC node set, DVN validators.    // Only these addresses may call privileged functions (unlock, release, etc.)    // ─── Authorized signers ───────────────────────────────────────────────────
    // In a real bridge: multisig signers, MPC node set, DVN validators.
    // Only these addresses may call privileged functions (unlock, release, etc.)
    // Tests verify that unauthorized callers increment failedAttemptCount.
    mapping(address => bool) public authorizedSigners;
    uint256 public requiredSigners;
    address public owner;

    // ─── Pre-attack signal state -- what PreAttackMonitorTrap reads ────────────
    // failedAttemptCount:      cumulative failed privileged calls from unauthorized addresses
    // lastUnauthorizedCaller:  most recent unauthorized caller (for alert routing)
    // failedAttemptBlocks:     ring buffer of block numbers for window analysis
    //                          (newest first, max 32 entries -- enough for any window size)
    uint256 public failedAttemptCount;
    address public lastUnauthorizedCaller;
    uint256[32] public failedAttemptBlocks;  // ring buffer; index = failedAttemptCount % 32
    uint256 public failedAttemptRingHead;    // current write position in ring buffer

    // ─── Reserve state ────────────────────────────────────────────────────────
    uint256 public lockedReserve;   // simulated locked value; does NOT change on failed calls
    bool    public paused;

    // ─── Events ───────────────────────────────────────────────────────────────
    event UnauthorizedAttempt(address indexed caller, string functionName, uint256 blockNumber);
    event AuthorizedRelease(address indexed signer, uint256 amount, bytes32 proofHash);
    event SignerAdded(address indexed signer);
    event EmergencyPaused(address by);

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor(uint256 _requiredSigners) {
        require(_requiredSigners > 0, "MockPrivilegedBridge: zero quorum");
        requiredSigners = _requiredSigners;
        owner           = msg.sender;
        authorizedSigners[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "MockPrivilegedBridge: not owner");
        _;
    }

    // ─── Signer management ────────────────────────────────────────────────────
    function addSigner(address signer) external onlyOwner {
        require(signer != address(0), "MockPrivilegedBridge: zero address");
        authorizedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    // ─── Seed reserve (test setup) ────────────────────────────────────────────
    function seedReserve(uint256 amount) external onlyOwner {        lockedReserve += amount;
    }
    // ─── Privileged functions ─────────────────────────────────────────────────

    // unlock(): release locked assets to a recipient.
    // Requires: caller is an authorized signer AND proof is valid.
    // Failed call from unauthorized address: records a failed attempt.
    //
    // Force Bridge pattern: the attacker had access to the deployer key but was
    // misconfiguring the call during the 6-hour window. Each failed call from
    // a non-authorized address increments failedAttemptCount. The pre-attack
    // monitor fires on this signal before any asset ever moves.
    function unlock(address /*recipient*/, uint256 amount, bytes32 proofHash) external {
        if (!authorizedSigners[msg.sender]) {
            // Record the failed attempt — this is the signal the trap watches.
            // Production instrumentation: unauthorized calls do NOT revert here.
            // Reverting would roll back state changes, making failedAttemptCount invisible
            // to synchronous view-based traps. Real bridges instrument privileged entry
            // points with non-reverting failure counters or catch-and-log wrappers to
            // expose pre-attack signals to on-chain monitors like PreAttackMonitorTrap.
            _recordFailedAttempt("unlock");
            return;
        }
        require(!paused,             "MockPrivilegedBridge: paused");
        require(amount > 0,          "MockPrivilegedBridge: zero amount");
        require(lockedReserve >= amount, "MockPrivilegedBridge: insufficient reserve");

        // Legitimate release -- reserve decreases, but ONLY from authorized callers
        lockedReserve -= amount;
        emit AuthorizedRelease(msg.sender, amount, proofHash);
    }

    // release(): alternate privileged exit function.
    // Same access control pattern. Same failed-attempt tracking.
    function release(address /*recipient*/, uint256 amount) external {
        if (!authorizedSigners[msg.sender]) {
            // Record the failed attempt — this is the signal the trap watches.
            // Production instrumentation: unauthorized calls do NOT revert here.
            // Reverting would roll back state changes, making failedAttemptCount invisible
            // to synchronous view-based traps. Real bridges instrument privileged entry
            // points with non-reverting failure counters or catch-and-log wrappers to
            // expose pre-attack signals to on-chain monitors like PreAttackMonitorTrap.
            _recordFailedAttempt("release");
            return;
        }
        require(!paused,                 "MockPrivilegedBridge: paused");
        require(amount > 0,              "MockPrivilegedBridge: zero amount");
        require(lockedReserve >= amount, "MockPrivilegedBridge: insufficient reserve");

        lockedReserve -= amount;        emit AuthorizedRelease(msg.sender, amount, bytes32(0));
    }

    // withdraw(): third privileged exit. Orbit Chain used multiple exit paths per asset.
    function withdraw(uint256 amount, bytes calldata /*proof*/) external {
        if (!authorizedSigners[msg.sender]) {
            // Record the failed attempt — this is the signal the trap watches.
            // Production instrumentation: unauthorized calls do NOT revert here.
            // Reverting would roll back state changes, making failedAttemptCount invisible
            // to synchronous view-based traps. Real bridges instrument privileged entry
            // points with non-reverting failure counters or catch-and-log wrappers to
            // expose pre-attack signals to on-chain monitors like PreAttackMonitorTrap.
            _recordFailedAttempt("withdraw");
            return;
        }
        require(!paused,                 "MockPrivilegedBridge: paused");
        require(amount > 0,              "MockPrivilegedBridge: zero amount");
        require(lockedReserve >= amount, "MockPrivilegedBridge: insufficient reserve");
        lockedReserve -= amount;
        emit AuthorizedRelease(msg.sender, amount, bytes32(0));
    }

    // ─── Internal: record failed attempt ─────────────────────────────────────
    function _recordFailedAttempt(string memory functionName) internal {
        failedAttemptCount++;
        lastUnauthorizedCaller = msg.sender;

        // Store block number in ring buffer (newest -> oldest, circular)
        uint256 slot = failedAttemptRingHead % 32;
        failedAttemptBlocks[slot] = block.number;
        failedAttemptRingHead++;

        emit UnauthorizedAttempt(msg.sender, functionName, block.number);
    }

    // ─── Read helpers for PreAttackMonitorTrap.collect() ─────────────────────

    // Returns how many failed attempts occurred within the last `windowBlocks` blocks.
    // The trap uses this to implement: "N failed calls within M blocks -> fire"
    function failedAttemptsInWindow(uint256 windowBlocks) external view returns (uint256 count) {
        uint256 cutoff = block.number >= windowBlocks ? block.number - windowBlocks : 0;
        uint256 entries = failedAttemptCount < 32 ? failedAttemptCount : 32;
        for (uint256 i = 0; i < entries; i++) {
            if (failedAttemptBlocks[i] >= cutoff) {
                count++;
            }
        }
    }

    // ─── Response target ──────────────────────────────────────────────────────    // Called by concept response contracts or Drosera operator network.
    // In production, restrict to emergency guardian or Drosera response contract.
    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}
