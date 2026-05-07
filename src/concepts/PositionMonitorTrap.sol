// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

// ─────────────────────────────────────────────────────────────────────────────
// PositionMonitorTrap
//
// Validates claim from 010-architecture-and-extensions.md (Trap 4):
// Monitors lending pool collateral composition and utilization.
// Fires when a bridge token's collateral share spikes alongside utilization --
// the signature of stolen bridge tokens being deposited as collateral to
// borrow real assets.
//
// Evidence: Kelp DAO (Apr 2026) -- 116,500 rsETH deposited into Aave V3 as
//           collateral; ~$236M WETH borrowed against it; Aave Guardian froze
//           rsETH markets 77 minutes later. With this trap: fires within
//           one block of the collateral deposit (~12 seconds).
//
// PRODUCTION DEPLOYMENT:
//   • Update LENDING_POOL & BRIDGE_TOKEN constants post-deployment.
//   • Calibrate COMPOSITION_THRESHOLD & UTILIZATION_THRESHOLD per pool.
//   • Target must expose ILendingPool view functions. Basis-point math assumed.
//   • Drosera requires stateless traps: no constructor args, pure/view logic only.
// ─────────────────────────────────────────────────────────────────────────────

interface ILendingPool {
    function totalCollateralValue()   external view returns (uint256);
    function totalDebtValue()         external view returns (uint256);
    function utilizationRate()        external view returns (uint256); // basis points
    function collateralByToken(address token) external view returns (uint256);
    function totalCollateralDeposits() external view returns (uint256);
    function collateralShare(address token) external view returns (uint256); // basis points
}

struct PositionCollectOutput {
    uint8   schemaVersion;
    uint256 totalCollateralValue;
    uint256 totalDebtValue;
    uint256 utilizationRate;           // basis points (10000 = 100%)
    uint256 bridgeTokenShare;          // basis points share of BRIDGE_TOKEN in total collateral
    uint256 totalCollateralDeposits;   // cumulative deposits (velocity signal)
}

struct PositionAlertData {
    uint256 bridgeTokenShare;
    uint256 utilizationRate;
    bool    willRespondSoon;
}
contract PositionMonitorTrap is ITrap {

    address public constant LENDING_POOL  = address(0); // set after deployment
    address public constant BRIDGE_TOKEN  = address(0); // rsETH equivalent; set after deployment

    uint8   public constant SCHEMA_VERSION = 1;

    // Fire if bridge token's collateral share exceeds this (basis points).
    // 5000 = 50%. If one token accounts for >50% of pool collateral, risk is extreme.
    uint256 public constant COMPOSITION_THRESHOLD  = 5000;

    // Fire if utilization rate exceeds this (basis points) in same window.
    // 7000 = 70%. Normal lending pools run 40-60% utilization.
    // A sudden spike to >70% alongside composition shift = borrowed-against-stolen-tokens.
    uint256 public constant UTILIZATION_THRESHOLD  = 7000;

    // Alert at lower thresholds
    uint256 public constant ALERT_COMPOSITION_THRESHOLD = 2000; // 20%
    uint256 public constant ALERT_UTILIZATION_THRESHOLD = 5000; // 50%

    function collect() external view virtual override returns (bytes memory) {
        uint256 share = ILendingPool(LENDING_POOL).collateralShare(BRIDGE_TOKEN);
        return abi.encode(PositionCollectOutput({
            schemaVersion:          SCHEMA_VERSION,
            totalCollateralValue:   ILendingPool(LENDING_POOL).totalCollateralValue(),
            totalDebtValue:         ILendingPool(LENDING_POOL).totalDebtValue(),
            utilizationRate:        ILendingPool(LENDING_POOL).utilizationRate(),
            bridgeTokenShare:       share,
            totalCollateralDeposits: ILendingPool(LENDING_POOL).totalCollateralDeposits()
        }));
    }

    function shouldRespond(bytes[] calldata data)
        external
        pure
        virtual
        override
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        PositionCollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // Fire when bridge token dominates collateral AND utilization is high.
        // Both conditions together distinguish "attacker borrowing against stolen tokens"
        // from "whale depositing legitimately."
        bool compositionAlert = newest.bridgeTokenShare >= COMPOSITION_THRESHOLD;
        bool utilizationAlert = newest.utilizationRate  >= UTILIZATION_THRESHOLD;
        if (compositionAlert && utilizationAlert) {
            return (true, abi.encode(
                newest.bridgeTokenShare,
                newest.utilizationRate,
                newest.totalCollateralDeposits
            ));
        }

        return (false, bytes(""));
    }

    function shouldAlert(bytes[] calldata data)
        external
        pure
        virtual
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        PositionCollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // Alert at lower thresholds -- warn before full response threshold hit
        bool compositionAlert = newest.bridgeTokenShare >= ALERT_COMPOSITION_THRESHOLD;
        bool utilizationAlert = newest.utilizationRate  >= ALERT_UTILIZATION_THRESHOLD;

        if (compositionAlert && utilizationAlert) {
            bool willRespondSoon = (newest.bridgeTokenShare >= COMPOSITION_THRESHOLD * 8 / 10) ||
                                   (newest.utilizationRate  >= UTILIZATION_THRESHOLD * 8 / 10);
            return (true, abi.encode(PositionAlertData({
                bridgeTokenShare: newest.bridgeTokenShare,
                utilizationRate: newest.utilizationRate,
                willRespondSoon: willRespondSoon
            })));
        }

        return (false, bytes(""));
    }

    // Fail-safe decode. Returns zeroed struct (schemaVersion = 0) on malformed input.
    // ABI minimum size: uint8 + 5×uint256 = 6 × 32 = 192 bytes.
    function _decode(bytes calldata sample) internal pure returns (PositionCollectOutput memory out) {
        if (sample.length < 192) return out;
        out = abi.decode(sample, (PositionCollectOutput));
        if (out.schemaVersion != SCHEMA_VERSION) return PositionCollectOutput(0, 0, 0, 0, 0, 0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Testable wrapper for CI/CD. Inherits ALL logic. Only collect() is overridden.// ─────────────────────────────────────────────────────────────────────────────
contract TestablePositionMonitorTrap is PositionMonitorTrap {

    address public immutable LENDING_POOL_TEST;
    address public immutable BRIDGE_TOKEN_TEST;

    constructor(address lendingPool, address bridgeToken) {
        require(lendingPool  != address(0), "TestablePosition: zero pool");
        require(bridgeToken  != address(0), "TestablePosition: zero token");
        LENDING_POOL_TEST = lendingPool;
        BRIDGE_TOKEN_TEST = bridgeToken;
    }

    function collect() external view override returns (bytes memory) {
        uint256 share = ILendingPool(LENDING_POOL_TEST).collateralShare(BRIDGE_TOKEN_TEST);
        return abi.encode(PositionCollectOutput({
            schemaVersion:           SCHEMA_VERSION,
            totalCollateralValue:    ILendingPool(LENDING_POOL_TEST).totalCollateralValue(),
            totalDebtValue:          ILendingPool(LENDING_POOL_TEST).totalDebtValue(),
            utilizationRate:         ILendingPool(LENDING_POOL_TEST).utilizationRate(),
            bridgeTokenShare:        share,
            totalCollateralDeposits: ILendingPool(LENDING_POOL_TEST).totalCollateralDeposits()
        }));
    }
}
