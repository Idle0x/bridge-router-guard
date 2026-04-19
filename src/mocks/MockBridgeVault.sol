// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// [EXPLOIT MODEL: Vector 1 — Multichain Jul 2023 / Orbit Chain Dec 2023 / Force Bridge Jun 2025]
//
// Replicates the VAULT side of the "execution without validation" pattern.
//
// Multichain (Jul 2023, ~$231M): anySwapOut() executed withdrawals without
// matching source-chain deposit proofs. MPC keys were compromised and used
// to drain the vault directly.
//
// Orbit Chain (Dec 2023, ~$81M): a 7/10 multisig was phished; vault outflows
// proceeded in sequence without any inbound message validation.
//
// Force Bridge (Jun 2025, ~$3.7M): a compromised deployer key triggered
// multi-asset drains across endpoints without matching lock events.
//
// Invariant broken: withdrawals must only execute when a corresponding
// validated inbound deposit exists. removeLiquidity() has no such check —
// it executes freely, exactly replicating the missing validation.
//
// The trap detects this by monitoring cumulativeWithdrawals velocity over
// the 7-block window. A delta exceeding VAULT_DRAIN_THRESHOLD signals
// unmatched outflow.
// ─────────────────────────────────────────────────────────────────────────────
contract MockBridgeVault {
    uint256 public cumulativeWithdrawals;
    uint256 public cumulativeDeposits;
    bool public paused; // NOTE: must be named `paused` (not `isPaused`) to satisfy IPausable interface

    event EmergencyPaused(address by);
    event LiquidityDeposited(uint256 amount);
    event LiquidityWithdrawn(uint256 amount);

    // [NORMAL BEHAVIOR] Legitimate deposits.
    // Used in normal-traffic tests to ensure the trap does not false-positive
    // on balanced bridge activity. The trap only monitors outflow.
    function depositLiquidity(uint256 amount) external {
        require(!paused, "Vault paused");
        cumulativeDeposits += amount;
        emit LiquidityDeposited(amount);
    }

    // [EXPLOIT EXECUTION — Multichain/Orbit Chain pattern]
    // Replicates anySwapOut() executing without a corresponding inbound proof.
    // No validation check exists here — the exact missing guard from Multichain.
    // → [NEUTRALIZED BY] BridgeRouterGuardTrap.sol shouldRespond():
    //   vaultVelocity = (newest.cumulativeWithdrawals - oldest.cumulativeWithdrawals)
    //   isCritical = vaultVelocity > VAULT_DRAIN_THRESHOLD (1,000 ETH)
    function removeLiquidity(uint256 amount) external {
        require(!paused, "Vault paused");
        cumulativeWithdrawals += amount;
        emit LiquidityWithdrawn(amount);
    }

    // [EXPLOIT EXECUTION — alternate drain entry point]
    // Some bridge vaults expose both removeLiquidity and withdraw.
    // Both accumulate into the same counter so the trap catches either path.
    // → [NEUTRALIZED BY] same velocity check as removeLiquidity above.
    function withdraw(uint256 amount) external {
        require(!paused, "Vault paused");
        cumulativeWithdrawals += amount;
        emit LiquidityWithdrawn(amount);
    }

    // [RESPONSE TARGET] Called by BridgeRouterGuardResponse.snapFreeze()
    // via the IPausable interface to halt further withdrawals after trap fires.
    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}
