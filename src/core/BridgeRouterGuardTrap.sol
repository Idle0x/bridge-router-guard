// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

// ─── External interfaces ──────────────────────────────────────────────────────
// Read-only interfaces for collect(). The trap never writes to these contracts.
// These are the exact state variables the trap reads to compute mismatch deltas.
interface IVault {
    function executedWithdrawals() external view returns (uint256);
    function validatedInboundCredits() external view returns (uint256);
    function vaultTokenBalance() external view returns (uint256); // NEW: Vector 4
}

interface IGateway {
    function cumulativeMinted() external view returns (uint256);
    function validatedMintAuthorizations() external view returns (uint256);
    function gatewayTokenSupply() external view returns (uint256); // NEW: Vector 4
}

interface IRouter {
    function executedMessages() external view returns (uint256);
    function gatewayValidatedMessages() external view returns (uint256);
}

// ─────────────────────────────────────────────────────────────────────────────
// CollectOutput -- versioned snapshot of all monitored mismatches + reserve state.
//
// ARCHITECTURAL CHANGE FROM v2:
//   v2 tracked: executed vs validated counters for Vectors 1-3
//   v3 adds:   vaultTokenBalance, gatewayTokenSupply for Vector 4 (reserve reconciliation)
//
// The invariant enforced:
//   executedWithdrawals     == validatedInboundCredits     (Vector 1)
//   cumulativeMinted        == validatedMintAuthorizations (Vector 2)
//   executedMessages        == gatewayValidatedMessages    (Vector 3)
//   vaultTokenBalance       >= executedWithdrawals         (Vector 4: reserve sanity)
//
// Any nonzero gap in Vectors 1-3 = execution occurred without validation = trigger.
// Vector 4 fires when tokens left the vault but counters didn't move (silent drain).
// ─────────────────────────────────────────────────────────────────────────────
struct CollectOutput {
    uint8 schemaVersion;
    // Vector 1 -- Vault (Multichain, Orbit Chain, Force Bridge)
    uint256 executedWithdrawals;
    uint256 validatedInboundCredits;
    // Vector 2 -- Gateway (IoTeX ioTube, Hyperbridge)
    uint256 cumulativeMinted;
    uint256 validatedMintAuthorizations;
    // Vector 3 -- Router (CrossCurve, Socket Protocol, Kelp DAO)
    uint256 executedMessages;
    uint256 gatewayValidatedMessages;
    // Vector 4 -- Reserve reconciliation (NEW in v3)
    // Detects when tokens leave vault but counters don't move (counter manipulation, direct transfer)
    uint256 vaultTokenBalance;
    uint256 gatewayTokenSupply;
}

// AlertData: decoded output for shouldAlert() routing to Slack/webhook
// Includes willRespondSoon flag for proximity-to-cliff signaling
struct AlertData {
    uint256 unmatchedDrain;        // Vector 1: executedWithdrawals - validatedInboundCredits
    uint256 unbackedMinted;        // Vector 2: cumulativeMinted - validatedMintAuthorizations
    uint256 unauthorizedExecs;     // Vector 3: executedMessages - gatewayValidatedMessages
    uint256 reserveDrain;          // Vector 4: vaultTokenBalance drop not reflected in counters
    bool    willRespondSoon;       // Proximity flag: true if within 20% of response threshold
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeRouterGuardTrap  (v3)
//
// A mismatch-tracking, multi-vector circuit breaker for cross-chain bridge
// infrastructure. Enforces a single invariant:
//
//   No execution may occur without a validated inbound event.
//
// Four detection vectors -- all based on the GAP between expected and actual state:
//
//   Vector 1 -- Vault drain mismatch (Velocity-Based Window)
//     executedWithdrawals - validatedInboundCredits > VAULT_DRAIN_THRESHOLD
//     References: Multichain Jul 2023, Orbit Chain Dec 2023, Force Bridge Jun 2025
//
//   Vector 2 -- Gateway phantom mint mismatch (Velocity-Based Window)
//     cumulativeMinted - validatedMintAuthorizations > PHANTOM_MINT_THRESHOLD
//     References: IoTeX ioTube Feb 2026, Hyperbridge Apr 2026
//
//   Vector 3 -- Router unauthorized execution (Hard Invariant, no history needed)
//     executedMessages - gatewayValidatedMessages > 0
//     References: CrossCurve Feb 2026, Socket Protocol Jan 2024, Kelp DAO Apr 2026
//     Note on Kelp DAO: poisoned DVN path makes router counters appear balanced;
//     Vector 1 fires instead on vault drain mismatch. See case-studies/008.
//
//   Vector 4 -- Reserve reconciliation (NEW in v3)
//     vaultTokenBalance drop not reflected in executedWithdrawals
//     Detects silent drains, counter manipulation, direct token transfers
//     References: Theoretical extension grounded in accounting reconciliation best practices
//
// Burst detection (consecutive, not cumulative):
//   v1 counted any N intervals above threshold regardless of gaps between them.
//   v2/v3 uses a streak counter that resets on any non-burst interval.//   Two CONSECUTIVE intervals above burst threshold required. Not two any-interval.//
// Alert thresholds vs response thresholds:
//   shouldAlert() fires at ALERT_THRESHOLD (lower) -- generates a notification
//   without triggering snapFreeze(). Catches Hyperbridge Phase 1 (245 ETH sub-
//   threshold drain) during the gap before Phase 2. shouldRespond() fires at
//   RESPONSE_THRESHOLD (higher) -- triggers the actual freeze.
//
// Drosera stateless trap requirements (unchanged from v1):
//   • collect() is view -- no state writes, ever
//   • shouldRespond() is pure -- deterministic, no external calls
//   • shouldAlert() is pure -- same constraint
//   • Addresses are constant -- Drosera requires no constructor args on trap contracts
// ─────────────────────────────────────────────────────────────────────────────
contract BridgeRouterGuardTrap is ITrap {

    // Hoodi Testnet addresses -- update after redeployment of rebuilt mocks.
    // [!] UPDATE THESE WITH YOUR NEW DEPLOYMENT ADDRESSES [!]
    address public constant VAULT   = 0x9C208438181976d9a1B6d86343fd6C6b74BF7F69;
    address public constant GATEWAY = 0x2BF916e3624E511d30F413661cA8817412F71d2D;
    address public constant ROUTER = 0xda79d08C267bCd0d2D2bc34463CEbbD571BC35B9;

    // ─── Response thresholds (shouldRespond / snapFreeze) ─────────────────────
    // A mismatch exceeding these thresholds triggers snapFreeze().
    // Unit: ETH-equivalent (or token-normalized equivalent in production).
    // TODO(production): oracle-backed asset normalization per token.
    uint256 public constant VAULT_DRAIN_THRESHOLD    = 1_000 ether;
    uint256 public constant PHANTOM_MINT_THRESHOLD   = 10_000 ether;

    // Per-block burst thresholds (40% of window threshold).
    // Two CONSECUTIVE intervals must exceed these to trigger burst detection.
    uint256 public constant BURST_THRESHOLD_VAULT    = 400 ether;
    uint256 public constant BURST_THRESHOLD_PHANTOM  = 4_000 ether;
    uint256 public constant BURST_COUNT_TRIGGER      = 2;    // consecutive, not cumulative

    // ─── Alert thresholds (shouldAlert only, lower than response) ─────────────
    // shouldAlert() fires at these lower thresholds to generate a warning
    // notification before the mismatch reaches snapFreeze levels.
    // This catches Hyperbridge Phase 1 (245 ETH) during the ~1-hour gap
    // before Phase 2's 1B DOT phantom mint.
    // The alert does not trigger snapFreeze -- it routes to Slack/webhook only.
    uint256 public constant ALERT_THRESHOLD_VAULT    = 200 ether;
    uint256 public constant ALERT_THRESHOLD_PHANTOM  = 2_000 ether;
    uint256 public constant ALERT_THRESHOLD_ROUTER   = 1;    // any unauthorized execution

    uint8 public constant SCHEMA_VERSION = 3;

    // ─── Stateless dynamic threshold parameters (v3) ──────────────────────────
    // Dynamic thresholds computed purely from window data (no persistent state).
    // Mean + 2σ band with floor to prevent micro-drain evasion.    // Falls back to static thresholds if insufficient samples.
    uint256 private constant MIN_SAMPLES_FOR_DYNAMIC = 3;    uint256 private constant SIGMA_MULTIPLIER = 2;      // ~95% confidence interval
    uint256 private constant DYNAMIC_FLOOR = 100 ether; // prevent zero-baseline gaming

    // ─── collect() ────────────────────────────────────────────────────────────
    // Called by every shadow operator on every new block.
    // Reads both counters for each vector + reserve balances for Vector 4.
    // The mismatch is computed in shouldRespond().
    function collect() external view virtual override returns (bytes memory) {
        return abi.encode(CollectOutput({
            schemaVersion:              SCHEMA_VERSION,
            executedWithdrawals:        IVault(VAULT).executedWithdrawals(),
            validatedInboundCredits:    IVault(VAULT).validatedInboundCredits(),
            cumulativeMinted:           IGateway(GATEWAY).cumulativeMinted(),
            validatedMintAuthorizations: IGateway(GATEWAY).validatedMintAuthorizations(),
            executedMessages:           IRouter(ROUTER).executedMessages(),
            gatewayValidatedMessages:   IRouter(ROUTER).gatewayValidatedMessages(),
            vaultTokenBalance:          IVault(VAULT).vaultTokenBalance(),
            gatewayTokenSupply:         IGateway(GATEWAY).gatewayTokenSupply()
        }));
    }

    // ─── shouldRespond() ──────────────────────────────────────────────────────
    // Pure. Evaluated by operators to decide whether to call snapFreeze().
    //
    // Bootstrap safety (unchanged from v1):
    //   Vector 3 (hard boolean) fires immediately with one sample.
    //   Vectors 1, 2, 4 require >= 2 valid samples to compute a mismatch delta.
    //   Without history, a bridge with large existing lifetime mismatch (e.g.
    //   after a cold start or operator restart) would false-trigger on deployment.
    //
    // VELOCITY FIX (reviewer finding #3):
    //   v1 returned newest.cumulativeWithdrawals as "vaultVelocity" in the payload.
    //   This sent cumulative totals to an event named AttackPrevented(vaultVelocity).
    //   v2/v3 returns the actual computed mismatch delta -- the gap, not the total.
    //   The event telemetry now matches what it says it is.
    function shouldRespond(bytes[] calldata data)
        external
        pure
        virtual
        override
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        CollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // ── Vector 3 -- Unauthorized router execution (hard invariant) ─────────        // Fires immediately. No history needed. One unauthorized execution = trigger.
        // [MITIGATION: CrossCurve Feb 2026 / Socket Protocol Jan 2024 / Kelp DAO Apr 2026]
        // Note: in Kelp's poisoned-DVN path, this may NOT fire (router counters        // appear balanced because the poisoned validator registered the message).
        // Vector 1 fires instead on the vault drain mismatch.
        uint256 unauthorizedExecs = _routerMismatch(newest);
        if (unauthorizedExecs > 0) {
            return (true, abi.encode(uint256(0), uint256(0), unauthorizedExecs, uint256(0)));
        }

        // Bootstrap guard for velocity-based vectors
        if (data.length < 2 || data[data.length - 1].length == 0) {
            return (false, bytes(""));
        }

        CollectOutput memory oldest = _decode(data[data.length - 1]);
        if (oldest.schemaVersion == 0) return (false, bytes(""));

        (bool isCritical, uint256 drainDelta, uint256 mintDelta, uint256 reserveDrain) =
            _evaluateMismatches(newest, oldest, data);

        if (isCritical) {
            // VELOCITY FIX: return actual deltas, not cumulative totals.
            return (true, abi.encode(drainDelta, mintDelta, uint256(0), reserveDrain));
        }

        // ── Consecutive burst detection (CONSECUTIVENESS FIX) ─────────────────
        // v1 counted any N intervals above burst threshold regardless of gaps.
        // v2/v3 requires N CONSECUTIVE intervals. Streak resets on non-burst.
        (uint256 vaultBursts, uint256 phantomBursts) = _countConsecutiveBursts(data);
        if (vaultBursts >= BURST_COUNT_TRIGGER || phantomBursts >= BURST_COUNT_TRIGGER) {
            // Compute the burst magnitude for telemetry
            CollectOutput memory mid = data.length >= 2 ? _decode(data[1]) : newest;
            uint256 burstDrain  = newest.executedWithdrawals > mid.executedWithdrawals
                ? newest.executedWithdrawals - mid.executedWithdrawals : 0;
            uint256 burstMint   = newest.cumulativeMinted > mid.cumulativeMinted
                ? newest.cumulativeMinted - mid.cumulativeMinted : 0;
            return (true, abi.encode(burstDrain, burstMint, uint256(0), uint256(0)));
        }

        return (false, bytes(""));
    }

    // ─── shouldAlert() ────────────────────────────────────────────────────────
    // Pure. Returns AlertData for the Drosera alert server.
    // Fires at ALERT_THRESHOLD -- lower than RESPONSE_THRESHOLD.
    // Does not trigger snapFreeze. Routes to Slack/webhook only.
    //
    // KEY UPGRADE from v1:
    //   v1: shouldAlert() fired on identical thresholds as shouldRespond().    //       A lower alert threshold was described in the Hyperbridge case study
    //       but never implemented.
    //   v2/v3: ALERT_THRESHOLD_VAULT = 200 ETH (vs RESPONSE = 1000 ETH).
    //       This would have fired on Hyperbridge Phase 1 (245 ETH) during the    //       ~1-hour gap before Phase 2's massive phantom mint.
    //       Operators get a warning. They can investigate. snapFreeze not yet fired.
    function shouldAlert(bytes[] calldata data)
        external
        pure
        virtual
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        CollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // Vector 3 alert -- immediate, no history needed
        uint256 unauthorizedExecs = _routerMismatch(newest);
        if (unauthorizedExecs >= ALERT_THRESHOLD_ROUTER) {
            return (true, abi.encode(AlertData({
                unmatchedDrain:    0,
                unbackedMinted:    0,
                unauthorizedExecs: unauthorizedExecs,
                reserveDrain:      0,
                willRespondSoon:   false
            })));
        }

        if (data.length < 2 || data[data.length - 1].length == 0) {
            return (false, bytes(""));
        }

        CollectOutput memory oldest = _decode(data[data.length - 1]);
        if (oldest.schemaVersion == 0) return (false, bytes(""));

        // Compute actual mismatch deltas across the window
        (, uint256 drainDelta, uint256 mintDelta, uint256 reserveDrain) =
            _evaluateMismatches(newest, oldest, data);

        bool alertable = (drainDelta > ALERT_THRESHOLD_VAULT) ||
                         (mintDelta  > ALERT_THRESHOLD_PHANTOM) ||
                         (reserveDrain > ALERT_THRESHOLD_VAULT);

        bool willRespondSoon = (drainDelta > VAULT_DRAIN_THRESHOLD * 8 / 10) ||
                               (mintDelta  > PHANTOM_MINT_THRESHOLD * 8 / 10);

        if (alertable) {
            return (true, abi.encode(AlertData({
                unmatchedDrain:    drainDelta,                unbackedMinted:    mintDelta,
                unauthorizedExecs: 0,
                reserveDrain:      reserveDrain,
                willRespondSoon:   willRespondSoon
            })));        }

        return (false, bytes(""));
    }

    // Public decoder for alert-server.js to parse AlertData from bytes
    function decodeAlertOutput(bytes calldata data) public pure returns (AlertData memory) {
        return abi.decode(data, (AlertData));
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    // Compute router mismatch from a single sample (no history needed).
    function _routerMismatch(CollectOutput memory sample) internal pure returns (uint256) {
        return sample.executedMessages > sample.gatewayValidatedMessages
            ? sample.executedMessages - sample.gatewayValidatedMessages
            : 0;
    }

    // Evaluate Vectors 1, 2, and 4 across the window.
    // Returns the MISMATCH DELTA across the window, not absolute totals.
    //
    // Why mismatch delta vs absolute mismatch:
    //   The absolute mismatch (newest.executedWithdrawals - newest.validatedInboundCredits)
    //   would false-trigger after any protocol incident that was paused and restarted --
    //   historical mismatch from before deployment would persist.
    //   The delta (how much the mismatch GREW in this window) is the relevant signal:
    //   it measures new unauthorized activity in the observation window.
    function _evaluateMismatches(CollectOutput memory newest, CollectOutput memory oldest, bytes[] calldata data)
        internal
        pure
        returns (bool isCritical, uint256 drainDelta, uint256 mintDelta, uint256 reserveDrain)
    {
        // Vector 1: how much did the drain mismatch GROW in this window?
        // If executedWithdrawals grew faster than validatedInboundCredits -> mismatch grew
        uint256 execGrowth  = newest.executedWithdrawals > oldest.executedWithdrawals
            ? newest.executedWithdrawals - oldest.executedWithdrawals : 0;
        uint256 creditGrowth = newest.validatedInboundCredits > oldest.validatedInboundCredits
            ? newest.validatedInboundCredits - oldest.validatedInboundCredits : 0;

        // Vector 2: how much did the mint mismatch GROW in this window?
        uint256 mintGrowth  = newest.cumulativeMinted > oldest.cumulativeMinted
            ? newest.cumulativeMinted - oldest.cumulativeMinted : 0;
        uint256 authGrowth  = newest.validatedMintAuthorizations > oldest.validatedMintAuthorizations            ? newest.validatedMintAuthorizations - oldest.validatedMintAuthorizations : 0;

        // ZERO-BACKING HARD TRIGGER: execution with NO validation backing at all.
        // No threshold. No tolerance. Any execution against zero validation = critical.
        // This is the absolute invariant: execution MUST be preceded by validation.
        if (execGrowth > 0 && creditGrowth == 0) {
            return (true, execGrowth, 0, 0);        }
        if (mintGrowth > 0 && authGrowth == 0) {
            return (true, 0, mintGrowth, 0);
        }

        drainDelta = execGrowth > creditGrowth ? execGrowth - creditGrowth : 0;
        mintDelta = mintGrowth > authGrowth ? mintGrowth - authGrowth : 0;

        // Vector 4: Reserve reconciliation -- did tokens leave without counter movement?
        // If vault balance dropped more than executedWithdrawals grew, tokens left silently
        uint256 reserveDrop = oldest.vaultTokenBalance > newest.vaultTokenBalance
            ? oldest.vaultTokenBalance - newest.vaultTokenBalance : 0;
        reserveDrain = reserveDrop > drainDelta ? reserveDrop - drainDelta : 0;

        // Dynamic thresholds computed purely from window data (stateless)
        uint256 vaultThreshold = _dynamicThreshold(data, true);
        uint256 mintThreshold = _dynamicThreshold(data, false);

        isCritical = (drainDelta > vaultThreshold) ||
                     (mintDelta > mintThreshold) ||
                     (reserveDrain > vaultThreshold);
    }

    // Stateless dynamic threshold: mean + 2σ computed from window deltas
    // Falls back to static threshold if insufficient samples or dynamic < static
    function _dynamicThreshold(bytes[] calldata data, bool isVault) internal pure returns (uint256) {
        if (data.length < MIN_SAMPLES_FOR_DYNAMIC) {
            return isVault ? VAULT_DRAIN_THRESHOLD : PHANTOM_MINT_THRESHOLD;
        }

        // Compute deltas for each adjacent pair in the window
        uint256[] memory deltas = new uint256[](data.length - 1);
        for (uint256 i = 0; i + 1 < data.length; i++) {
            CollectOutput memory newer = _decode(data[i]);
            CollectOutput memory older = _decode(data[i + 1]);
            if (newer.schemaVersion == 0 || older.schemaVersion == 0) {
                deltas[i] = 0;
                continue;
            }
            if (isVault) {
                uint256 e = newer.executedWithdrawals > older.executedWithdrawals ? newer.executedWithdrawals - older.executedWithdrawals : 0;
                uint256 c = newer.validatedInboundCredits > older.validatedInboundCredits ? newer.validatedInboundCredits - older.validatedInboundCredits : 0;
                deltas[i] = e > c ? e - c : 0;
            } else {
                uint256 m = newer.cumulativeMinted > older.cumulativeMinted ? newer.cumulativeMinted - older.cumulativeMinted : 0;                uint256 a = newer.validatedMintAuthorizations > older.validatedMintAuthorizations ? newer.validatedMintAuthorizations - older.validatedMintAuthorizations : 0;
                deltas[i] = m > a ? m - a : 0;
            }
        }

        // Compute mean
        uint256 sum;
        for (uint256 i = 0; i < deltas.length; i++) sum += deltas[i];
        uint256 mean = sum / deltas.length;

        // Compute variance and standard deviation
        uint256 varSum;
        for (uint256 i = 0; i < deltas.length; i++) {
            uint256 diff = deltas[i] > mean ? deltas[i] - mean : mean - deltas[i];
            // OVERFLOW GUARD: cap diff before squaring to prevent uint256 revert
            if (diff > type(uint128).max) diff = type(uint128).max;
            varSum += diff * diff;
        }
        uint256 stdDev = _sqrt(varSum / deltas.length);

        // Dynamic threshold = mean + 2σ + floor (prevent zero-baseline gaming)
        uint256 dynamic = mean + (stdDev * SIGMA_MULTIPLIER) + DYNAMIC_FLOOR;

        // Fallback to static if dynamic is lower (conservative)
        uint256 staticFallback = isVault ? VAULT_DRAIN_THRESHOLD : PHANTOM_MINT_THRESHOLD;
        return dynamic < staticFallback ? staticFallback : dynamic;
    }

    // Integer square root via Newton's method (bounded iterations for gas safety)
    // Note: 8 iterations is approximate for inputs near type(uint256).max.
    // Sufficient for threshold computation where precision beyond ~1e38 is irrelevant.
    function _sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        for (uint256 i = 0; i < 8; i++) {
            if (z >= y) break;
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }

    // Count CONSECUTIVE block-to-block intervals where the mismatch delta
    // exceeded the burst threshold. Streak resets on any non-burst interval.
    //
    // CONSECUTIVENESS FIX (reviewer finding #4):
    //   v1: any N above-threshold intervals counted, regardless of gaps.
    //   v2/v3: streak counter resets on non-burst interval.
    //       Block 7->6: 450 ETH burst. Block 6->5: 0 ETH (streak resets).    //       Block 5->4: 450 ETH burst. streak = 1, not 2. Does not trigger.
    //       This matches what the README says: "two CONSECUTIVE" intervals.
    //
    // Schema guard (v1 TODO now implemented):
    //   If either adjacent sample has schemaVersion == 0 (failed decode),
    //   skip that interval entirely rather than computing an inflated delta
    //   from a zeroed older sample. This eliminates the edge case where a    //   decode failure produces a false burst signal.
    function _countConsecutiveBursts(bytes[] calldata data)
        internal
        pure
        returns (uint256 maxVaultStreak, uint256 maxPhantomStreak)
    {
        uint256 vaultStreak   = 0;
        uint256 phantomStreak = 0;

        for (uint256 i = 0; i + 1 < data.length; i++) {
            if (data[i].length == 0 || data[i + 1].length == 0) {
                vaultStreak   = 0;
                phantomStreak = 0;
                continue;
            }

            CollectOutput memory newer = _decode(data[i]);
            CollectOutput memory older = _decode(data[i + 1]);

            // SCHEMA GUARD (v1 TODO now resolved):
            // Skip interval if either sample failed schema validation.
            if (newer.schemaVersion == 0 || older.schemaVersion == 0) {
                vaultStreak   = 0;
                phantomStreak = 0;
                continue;
            }

            // Compute mismatch delta for this single interval
            uint256 execStep   = newer.executedWithdrawals > older.executedWithdrawals
                ? newer.executedWithdrawals - older.executedWithdrawals : 0;
            uint256 creditStep = newer.validatedInboundCredits > older.validatedInboundCredits
                ? newer.validatedInboundCredits - older.validatedInboundCredits : 0;
            uint256 drainMismatchStep = execStep > creditStep ? execStep - creditStep : 0;

            uint256 mintStep = newer.cumulativeMinted > older.cumulativeMinted
                ? newer.cumulativeMinted - older.cumulativeMinted : 0;
            uint256 authStep  = newer.validatedMintAuthorizations > older.validatedMintAuthorizations
                ? newer.validatedMintAuthorizations - older.validatedMintAuthorizations : 0;
            uint256 mintMismatchStep = mintStep > authStep ? mintStep - authStep : 0;

            // Update streaks -- reset on non-burst
            if (drainMismatchStep > BURST_THRESHOLD_VAULT) {
                vaultStreak++;
                if (vaultStreak > maxVaultStreak) maxVaultStreak = vaultStreak;
            } else {
                vaultStreak = 0;
            }

            if (mintMismatchStep > BURST_THRESHOLD_PHANTOM) {
                phantomStreak++;                if (phantomStreak > maxPhantomStreak) maxPhantomStreak = phantomStreak;
            } else {
                phantomStreak = 0;
            }
        }
    }

    // Fail-safe decode. Returns zeroed struct (schemaVersion = 0) on malformed input.
    // A zeroed struct is treated as no signal in all callers -- never triggers.
    // ABI minimum size for CollectOutput (uint8 + 8×uint256) = 9 × 32 bytes = 288 bytes.
    // Length check prevents undersized revert. Schema mismatch returns zeroed struct.
    // Note: correctly-sized but ABI-malformed payloads may still revert. Production
    // deployments with untrusted relays should wrap abi.decode in try/catch.
    function _decode(bytes calldata sample) internal pure returns (CollectOutput memory out) {
        if (sample.length < 288) return out;  // schemaVersion = 0 -> treated as failed
        out = abi.decode(sample, (CollectOutput));
        if (out.schemaVersion != SCHEMA_VERSION) {
            return CollectOutput(0,0,0,0,0,0,0,0,0);  // schema mismatch -> zeroed
        }
    }
}
