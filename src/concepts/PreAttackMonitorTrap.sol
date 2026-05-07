// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

// ─────────────────────────────────────────────────────────────────────────────
// PreAttackMonitorTrap
//
// Validates claim from 010-architecture-and-extensions.md (Trap 3):
// Monitors failed privileged function calls to detect attacker preparation
// BEFORE any funds move.
//
// Evidence: Force Bridge (Jun 2025) -- 6-hour failed attempt window before drain.
//           Orbit Chain (Dec 2023)  -- 4-hour probe window before bulk drain.
//
// collect() reads: failedAttemptCount, lastUnauthorizedCaller from bridge.
// shouldRespond(): fires if failedAttemptCount exceeds ATTEMPT_THRESHOLD within
//                  WINDOW_BLOCKS of recent blocks.
//
// PRODUCTION DEPLOYMENT:
//   • Update BRIDGE constant post-deployment.
//   • Calibrate ATTEMPT_THRESHOLD & WINDOW_BLOCKS against 30-day baseline.
//   • Target must expose IPrivilegedBridge view functions. Minimal instrumentation required.
//   • Drosera requires stateless traps: no constructor args, pure/view logic only.
// ─────────────────────────────────────────────────────────────────────────────

interface IPrivilegedBridge {
    function failedAttemptCount()      external view returns (uint256);
    function lastUnauthorizedCaller()  external view returns (address);
    function failedAttemptsInWindow(uint256 windowBlocks) external view returns (uint256);
    function lockedReserve()           external view returns (uint256);
}

struct PreAttackCollectOutput {
    uint8   schemaVersion;
    uint256 failedAttemptCount;     // cumulative failed privileged calls
    uint256 attemptsInWindow;       // failed calls within WINDOW_BLOCKS
    address lastUnauthorizedCaller;
    uint256 lockedReserve;          // reserve value (unchanged during failed attempts)
}

struct PreAttackAlertData {
    uint256 failedAttemptCount;
    address lastUnauthorizedCaller;
    bool    willRespondSoon; // true if attemptsInWindow >= ATTEMPT_THRESHOLD - 1
}

contract PreAttackMonitorTrap is ITrap {

    address public constant BRIDGE = address(0); // set after deployment
    uint8   public constant SCHEMA_VERSION   = 1;
    uint256 public constant ATTEMPT_THRESHOLD = 3;   // N failed calls -> fire
    uint256 public constant WINDOW_BLOCKS     = 500;  // within M blocks (~100 min at 12s)

    function collect() external view virtual override returns (bytes memory) {
        return abi.encode(PreAttackCollectOutput({
            schemaVersion:          SCHEMA_VERSION,
            failedAttemptCount:     IPrivilegedBridge(BRIDGE).failedAttemptCount(),
            attemptsInWindow:       IPrivilegedBridge(BRIDGE).failedAttemptsInWindow(WINDOW_BLOCKS),
            lastUnauthorizedCaller: IPrivilegedBridge(BRIDGE).lastUnauthorizedCaller(),
            lockedReserve:          IPrivilegedBridge(BRIDGE).lockedReserve()
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

        PreAttackCollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // Fire if N or more failed privileged calls occurred within the window.
        // lockedReserve is NOT checked here -- this fires BEFORE any drain.
        // That is the entire point: detect the preparation, not the consequence.
        if (newest.attemptsInWindow >= ATTEMPT_THRESHOLD) {
            return (true, abi.encode(newest.failedAttemptCount, newest.lastUnauthorizedCaller));
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
        PreAttackCollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // Alert on first failed attempt -- lower bar than full response.
        if (newest.attemptsInWindow >= 1) {
            bool willRespondSoon = newest.attemptsInWindow >= ATTEMPT_THRESHOLD - 1;            return (true, abi.encode(PreAttackAlertData({
                failedAttemptCount: newest.failedAttemptCount,
                lastUnauthorizedCaller: newest.lastUnauthorizedCaller,
                willRespondSoon: willRespondSoon
            })));
        }
        return (false, bytes(""));
    }

    // Fail-safe decode. Returns zeroed struct (schemaVersion = 0) on malformed input.
    // A zeroed struct is treated as no signal in all callers -- never triggers.
    // ABI minimum size: uint8 + 4×32 bytes = 160 bytes. Length check prevents undersized revert.
    // Schema mismatch returns zeroed struct. Correctly-sized but ABI-malformed payloads may
    // still revert. Production deployments with untrusted relays should wrap in try/catch.
    function _decode(bytes calldata sample) internal pure returns (PreAttackCollectOutput memory out) {
        if (sample.length < 160) return out;
        out = abi.decode(sample, (PreAttackCollectOutput));
        if (out.schemaVersion != SCHEMA_VERSION) return PreAttackCollectOutput(0, 0, 0, address(0), 0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Testable wrapper for CI/CD. Inherits ALL logic. Only collect() is overridden.
// ─────────────────────────────────────────────────────────────────────────────
contract TestablePreAttackMonitorTrap is PreAttackMonitorTrap {

    address public immutable BRIDGE_TEST;

    constructor(address bridge) {
        require(bridge != address(0), "TestablePreAttack: zero bridge");
        BRIDGE_TEST = bridge;
    }

    function collect() external view override returns (bytes memory) {
        return abi.encode(PreAttackCollectOutput({
            schemaVersion:          SCHEMA_VERSION,
            failedAttemptCount:     IPrivilegedBridge(BRIDGE_TEST).failedAttemptCount(),
            attemptsInWindow:       IPrivilegedBridge(BRIDGE_TEST).failedAttemptsInWindow(WINDOW_BLOCKS),
            lastUnauthorizedCaller: IPrivilegedBridge(BRIDGE_TEST).lastUnauthorizedCaller(),
            lockedReserve:          IPrivilegedBridge(BRIDGE_TEST).lockedReserve()
        }));
    }
}
