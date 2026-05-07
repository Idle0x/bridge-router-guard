// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// MockLendingPool  (concept mock — concepts/ folder)
//
// Validates the claim from 010-architecture-and-extensions.md (Trap 4 concept):
// Monitors lending pool collateral composition and utilization.
// Fires when a bridge token's collateral share spikes alongside utilization —
// the signature of stolen bridge tokens being deposited as collateral to
// borrow real assets.
//
// Real-world evidence: Kelp DAO (Apr 2026, ~$292M)
//   After draining 116,500 rsETH from the bridge, the attacker deposited
//   all of it into Aave V3 as collateral. They then borrowed ~$236M WETH
//   against it. Aave was left holding worthless collateral against real debt.
//   The Aave Guardian froze rsETH markets 77 minutes after the drain —
//   after most of the borrowing was complete.
//
//   A PositionMonitorTrap watching the lending pool would have detected:
//     1. A sudden large deposit of a bridge token (rsETH) into the lending pool
//     2. Utilization spiking as that collateral was immediately borrowed against
//     3. The bridge token's share of total collateral jumping from ~0% to ~100%
//   All three signals appear within the same block as the deposit.
//
// INTERFACE CONTRACT (read by PositionMonitorTrap.collect()):
//   totalCollateralValue()   → uint256 (ETH-normalized sum of all collateral)
//   totalDebtValue()         → uint256 (ETH-normalized sum of all loans)
//   utilizationRate()        → uint256 (basis points, 10000 = 100%)
//   collateralByToken(addr)  → uint256 (per-token collateral value)
//   totalCollateralDeposits()→ uint256 (cumulative deposits for velocity)
//   collateralShare(addr)    → uint256 (basis points share of total collateral)
//
// PRODUCTION DEPLOYMENT NOTE:
//   This is a concept mock. Real lending pools must expose the exact view
//   functions above. The trap assumes minimal instrumentation: public collateral
//   accounting, utilization computation, and per-token share tracking. No state
//   writes occur in the trap; this contract only provides the read surface and
//   exploit simulation paths for testing. In production, emergencyPause() must
//   be restricted to a guardian or Drosera response contract address.
// ─────────────────────────────────────────────────────────────────────────────
contract MockLendingPool {

    // ─── Per-token collateral tracking ────────────────────────────────────────
    // Maps token address → total collateral value deposited in this token.
    // PositionMonitorTrap uses this to compute composition ratios.
    mapping(address => uint256) public collateralByToken;

    // ─── Pool-level state — what PositionMonitorTrap reads ───────────────────
    uint256 public totalCollateralValue;    // ETH-normalized sum of all collateral
    uint256 public totalDebtValue;          // ETH-normalized sum of all loans
    uint256 public totalCollateralDeposits; // cumulative deposits (for velocity)

    // utilizationRate: basis points (10000 = 100%)
    // Computed on each deposit/borrow. Read by collect().
    uint256 public utilizationRate;

    // ─── Position registry ────────────────────────────────────────────────────
    // ─── Position registry ────────────────────────────────────────────────────
    // PoC simplification: tracks only one collateral type per address.
    // Production lending pools support multiple collateral types per user.
    // Tests should use separate addresses for different collateral types.
    struct Position {
        address collateralToken;
        uint256 collateralAmount;
        uint256 debtAmount;
        address borrower;
    }
    mapping(address => Position) public positions;

    // Whitelisted collateral tokens and their LTV ratios (basis points)
    // In Aave: rsETH had an LTV, allowing it to be used as collateral.
    mapping(address => uint256) public ltvByToken;  // e.g. 8000 = 80% LTV
    mapping(address => bool)    public acceptedCollateral;

    bool    public paused;
    address public owner;

    // ─── Events ───────────────────────────────────────────────────────────────
    event CollateralDeposited(address indexed depositor, address indexed token, uint256 amount);
    event LoanTaken(address indexed borrower, uint256 amount);
    event CollateralWithdrawn(address indexed depositor, address indexed token, uint256 amount);
    event TokenAccepted(address indexed token, uint256 ltv);
    event EmergencyPaused(address by);

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "MockLendingPool: not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "MockLendingPool: paused");
        _;
    }

    // ─── Pool configuration ───────────────────────────────────────────────────
    // Accept a token as collateral with a given LTV ratio.
    // In the Kelp scenario: rsETH was accepted with a positive LTV before the exploit.
    function acceptToken(address token, uint256 ltv) external onlyOwner {        require(token != address(0), "MockLendingPool: zero token");
        require(ltv   <= 9500,       "MockLendingPool: LTV too high");  // max 95%
        acceptedCollateral[token] = true;
        ltvByToken[token]         = ltv;
        emit TokenAccepted(token, ltv);
    }

    // ─── Normal operation ─────────────────────────────────────────────────────

    // depositCollateral(): user deposits tokens as collateral.
    // In the Kelp exploit, the attacker deposited 116,500 rsETH here.
    // PositionMonitorTrap detects the composition shift this causes.
    //
    // `valueInEth`: caller provides the ETH-equivalent value of the deposit.
    // In production: oracle-derived. Here: test-provided for simplicity.
    function depositCollateral(
        address token,
        uint256 amount,
        uint256 valueInEth
    ) external notPaused {
        require(acceptedCollateral[token], "MockLendingPool: token not accepted");
        require(amount     > 0,            "MockLendingPool: zero amount");
        require(valueInEth > 0,            "MockLendingPool: zero value");

        // Update position
        Position storage pos = positions[msg.sender];
        pos.collateralToken  = token;   // simplified: one collateral type per address
        pos.collateralAmount += amount;
        pos.borrower          = msg.sender;

        // Update pool state
        collateralByToken[token]  += valueInEth;
        totalCollateralValue      += valueInEth;
        totalCollateralDeposits   += valueInEth;

        _updateUtilizationRate();

        emit CollateralDeposited(msg.sender, token, amount);
    }

    // borrow(): user takes a loan against their collateral.
    // In the Kelp exploit, the attacker borrowed ~$236M WETH against rsETH collateral.
    // PositionMonitorTrap detects the utilization spike this causes.
    //
    // `amount`: ETH-equivalent borrow amount.
    function borrow(uint256 amount) external notPaused {
        Position storage pos = positions[msg.sender];
        require(pos.collateralAmount > 0, "MockLendingPool: no collateral deposited");

        // LTV check: borrow must not exceed LTV of collateral
        uint256 ltv             = ltvByToken[pos.collateralToken];
        uint256 collateralValue = collateralByToken[pos.collateralToken];
        uint256 maxBorrow       = (collateralValue * ltv) / 10000;

        require(pos.debtAmount + amount <= maxBorrow, "MockLendingPool: exceeds LTV");

        pos.debtAmount    += amount;
        totalDebtValue    += amount;

        _updateUtilizationRate();

        emit LoanTaken(msg.sender, amount);
    }

    // ─── Internal: utilization update ─────────────────────────────────────────
    function _updateUtilizationRate() internal {
        if (totalCollateralValue == 0) {
            utilizationRate = 0;
        } else {
            utilizationRate = (totalDebtValue * 10000) / totalCollateralValue;
        }
    }

    // ─── Read helpers for PositionMonitorTrap.collect() ──────────────────────

    // Returns the share (basis points) of total collateral held in `token`.
    // Kelp scenario: rsETH share jumps from 0 → ~10000 (100%) in one block.
    function collateralShare(address token) external view returns (uint256) {
        if (totalCollateralValue == 0) return 0;
        return (collateralByToken[token] * 10000) / totalCollateralValue;
    }

    // Returns true if the lending pool is in a high-risk state:
    // (a) a single token dominates collateral AND (b) utilization is high.
    // This is the combined signal PositionMonitorTrap fires on.
    function isHighRiskState(address token, uint256 compositionThreshold, uint256 utilizationThreshold)
        external view returns (bool)
    {
        uint256 share = totalCollateralValue == 0
            ? 0
            : (collateralByToken[token] * 10000) / totalCollateralValue;

        return share >= compositionThreshold && utilizationRate >= utilizationThreshold;
    }

    // ─── Response target ──────────────────────────────────────────────────────
    // In the Kelp scenario: Aave Guardian froze rsETH markets 77 minutes after drain.
    // PositionMonitorTrap fires within 12 seconds of the collateral deposit.
    // Called by concept response contracts or Drosera operator network.
    function emergencyPause() external {        paused = true;
        emit EmergencyPaused(msg.sender);
    }

    // Freeze a specific token's collateral (mirrors Aave's freezeReserve).
    // More surgical than full pause — only prevents new deposits/borrows of `token`.
    // Simplified to full pause for this mock to match emergencyPause() surface.
    function freezeToken(address /*token*/) external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}
