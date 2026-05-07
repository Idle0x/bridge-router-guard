// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockERC20.sol";

// ─────────────────────────────────────────────────────────────────────────────
// MockBridgeVault  (v3)
//
// The destination-side reserve contract. Holds actual ERC20 tokens that physically
// transfer during drain tests. Attacker wallets receive real token balances that
// are asserted in every drain test.
//
// ARCHITECTURAL CHANGE FROM v1/v2:
//   BEFORE: `drain()` — a function literally named drain. Self-aware toy.
//   AFTER:  `executeWithdrawal()` (legitimate, requires credit) +
//           `executeDirectWithdrawal()` (simulates off-chain key compromise).
//
// Real bridges don't have drain(). Exploits flow through legitimate functions
// called with compromised authorization, or through direct reserve movement
// when off-chain keys (MPC/multisig/deployer) are seized.
//
// INTERFACE CONTRACT (read by BridgeRouterGuardTrap.collect()):
//   executedWithdrawals()     → uint256
//   validatedInboundCredits() → uint256
//   vaultTokenBalance()       → uint256 (Vector 4 reserve reconciliation)
//
// Normal operation:
//   1. Oracle confirms source event
//   2. Validator calls registerInboundCredit()
//   3. Recipient calls executeWithdrawal() referencing validated credit
//   4. Both counters increment → mismatch = 0
//
// Exploit operation (Multichain/Orbit/Force Bridge):
//   Attacker bypasses validator entirely. Calls executeDirectWithdrawal().
//   executedWithdrawals increases. validatedInboundCredits does not.
//   Mismatch grows. Tokens physically transfer to attacker.
//   Trap reads mismatch > threshold → fires.
//
// The bridge contract is innocent. The failure is upstream in the validation layer.
// The trap detects the consequence, not the cause.
//
// PRODUCTION DEPLOYMENT NOTE:
//   This is a concept mock. Real bridge vaults must expose the exact view
//   functions above. The trap assumes minimal instrumentation: public execution
//   and validation counters, plus a readable reserve balance. No state writes
//   occur in the trap; this contract only provides the read surface and exploit
//   simulation paths for testing. In production, emergencyPause() must be
//   restricted to a guardian or Drosera response contract address.
// ─────────────────────────────────────────────────────────────────────────────
contract MockBridgeVault {
    // ─── Token ────────────────────────────────────────────────────────────────
    MockERC20 public immutable token;

    // ─── Mismatch tracking — what the trap actually reads ─────────────────────
    // executedWithdrawals:     total value that LEFT the vault (regardless of validation)
    // validatedInboundCredits: total value that was AUTHORIZED by a validated source event
    //
    // Normal operation: executedWithdrawals == validatedInboundCredits
    // Exploit:          executedWithdrawals >  validatedInboundCredits (mismatch > 0)
    uint256 public executedWithdrawals;
    uint256 public validatedInboundCredits;

    // ─── Credit registry ──────────────────────────────────────────────────────
    // Maps eventHash → Credit. Only MockMessageValidator may write here.
    // A credit must exist and be unused before executeWithdrawal() can proceed.
    struct Credit {
        uint256 amount;
        address recipient;
        bool    consumed;
    }
    mapping(bytes32 => Credit) public credits;

    // ─── Access control & safety ──────────────────────────────────────────────
    address public immutable validator;  // only address that may call registerInboundCredit()
    bool    public paused;               // named `paused` for IPausable interface compliance
    uint8   private _locked;             // minimal reentrancy guard for legitimate path

    // ─── Events ───────────────────────────────────────────────────────────────
    event CreditRegistered(bytes32 indexed eventHash, uint256 amount, address recipient);
    event WithdrawalExecuted(bytes32 indexed eventHash, address indexed recipient, uint256 amount);
    event DirectWithdrawal(address indexed recipient, uint256 amount);
    event SilentTransfer(address indexed to, uint256 amount);
    event LiquiditySeeded(uint256 amount);
    event EmergencyPaused(address by);

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor(address _token, address _validator) {
        require(_token != address(0) && _validator != address(0), "MockBridgeVault: zero address");
        token     = MockERC20(_token);
        validator = _validator;
    }

    modifier notPaused() {
        require(!paused, "MockBridgeVault: paused");
        _;
    }

    modifier onlyValidator() {
        require(msg.sender == validator, "MockBridgeVault: not validator");        _;
    }

    modifier nonReentrant() {
        require(_locked == 0, "MockBridgeVault: reentrant call");
        _locked = 1;
        _;
        _locked = 0;
    }

    // ─── Liquidity seeding (test setup) ───────────────────────────────────────
    // Called during test setUp() to fund the vault with tokens before exploit.
    // In a real bridge, this represents accumulated locked assets or TVL.
    function seedLiquidity(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        emit LiquiditySeeded(amount);
    }

    // ─── Normal operation ─────────────────────────────────────────────────────

    // Called ONLY by MockMessageValidator after confirming a source event.
    // Registers a credit that authorizes one withdrawal of `amount` to `recipient`.
    function registerInboundCredit(
        bytes32 eventHash,
        uint256 amount,
        address recipient
    ) external onlyValidator {
        require(credits[eventHash].amount == 0, "MockBridgeVault: credit already registered");
        require(amount > 0 && recipient != address(0), "MockBridgeVault: invalid credit params");

        credits[eventHash] = Credit({ amount: amount, recipient: recipient, consumed: false });
        validatedInboundCredits += amount;
        emit CreditRegistered(eventHash, amount, recipient);
    }

    // LEGITIMATE PATH: requires registered credit. CEI pattern. Reentrancy guard.
    // executedWithdrawals and validatedInboundCredits both increase → mismatch stays 0.
    function executeWithdrawal(bytes32 eventHash) external notPaused nonReentrant {
        Credit storage credit = credits[eventHash];
        require(credit.amount > 0 && !credit.consumed, "MockBridgeVault: invalid or consumed credit");
        require(credit.recipient == msg.sender || msg.sender == validator,
                "MockBridgeVault: not credit recipient");

        // Effects first
        credit.consumed = true;
        executedWithdrawals += credit.amount;

        // Interaction last
        require(token.balanceOf(address(this)) >= credit.amount, "MockBridgeVault: insufficient reserve");
        token.transfer(credit.recipient, credit.amount);        emit WithdrawalExecuted(eventHash, credit.recipient, credit.amount);
    }

    // ─── EXPLOIT PATH — compromised key simulation ────────────────────────────
    // [EXPLOIT MODEL: Multichain Jul 2023 / Orbit Chain Dec 2023 / Force Bridge Jun 2025]
    //
    // Simulates off-chain key compromise (MPC/multisig/deployer).
    // No credit check. No validator. No oracle confirmation.
    // Real bridges don't have drain(). This is the on-chain consequence of
    // privileged key seizure bypassing the validation stack.
    //
    // Effect on counters:
    //   executedWithdrawals += amount      (funds leave)
    //   validatedInboundCredits unchanged  (no credit was registered)
    //   mismatch = executedWithdrawals - validatedInboundCredits grows
    //   token.balanceOf(attacker) increases (real tokens transfer)
    //
    // → [NEUTRALIZED BY] BridgeRouterGuardTrap.shouldRespond():
    //   drainDelta = executedWithdrawals - validatedInboundCredits
    //   isCritical = drainDelta > VAULT_DRAIN_THRESHOLD
    function executeDirectWithdrawal(address recipient, uint256 amount) external notPaused {
        require(recipient != address(0) && amount > 0, "MockBridgeVault: invalid params");
        require(token.balanceOf(address(this)) >= amount, "MockBridgeVault: insufficient reserve");

        executedWithdrawals += amount;
        token.transfer(recipient, amount);
        emit DirectWithdrawal(recipient, amount);
    }

    // ─── VECTOR 4 TEST SURFACE — silent drain / counter manipulation ──────────
    // Transfers tokens out WITHOUT incrementing executedWithdrawals.
    // Used exclusively to test reserve reconciliation (Vector 4).
    // In production, this represents accounting bypass, internal transfer,
    // or secondary exit path that doesn't update the primary execution counter.
    function directTokenTransfer(address to, uint256 amount) external notPaused {
        require(to != address(0) && amount > 0, "MockBridgeVault: invalid params");
        require(token.balanceOf(address(this)) >= amount, "MockBridgeVault: insufficient reserve");
        token.transfer(to, amount);
        emit SilentTransfer(to, amount);
    }

    // ─── Read helpers for trap & tests ────────────────────────────────────────

    // Returns current ERC20 balance held in the vault.
    // Read by BridgeRouterGuardTrap.collect() for Vector 4 reserve reconciliation.
    function vaultTokenBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    // Returns the current execution/validation mismatch.   
    // Used in tests to assert exploit state before trap evaluation.
    function getMismatch() external view returns (uint256) {
    return executedWithdrawals > validatedInboundCredits
        ? executedWithdrawals - validatedInboundCredits
        : 0;
}

    // ─── Response target ──────────────────────────────────────────────────────
    // [RESPONSE TARGET] Called by BridgeRouterGuardResponse.snapFreeze()
    // In production, restrict to emergency guardian or Drosera response contract.
    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}

