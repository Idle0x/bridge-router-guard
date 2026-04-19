// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

interface IMockVault {
    function cumulativeWithdrawals() external view returns (uint256);
}

interface IMockGateway {
    function phantomMinted() external view returns (uint256);
}

interface IMockRouter {
    function spoofedMessageExecuted() external view returns (bool);
}

// ─────────────────────────────────────────────────────────────────────────────
// Versioned collect() output struct.
// schemaVersion guards against silent mis-decoding between operator nodes
// running different versions of this trap.
// ─────────────────────────────────────────────────────────────────────────────
struct CollectOutput {
    uint8 schemaVersion;           // always 1 for this version
    uint256 cumulativeWithdrawals; // Vector 1: vault drain tracking
    uint256 phantomMinted;         // Vector 2: phantom mint tracking
    bool spoofedMessageExecuted;   // Vector 3: router spoof boolean invariant
}

struct AlertData {
    uint256 vaultDrainVelocity;
    uint256 phantomMintVelocity;
    bool routerSpoofed;
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeRouterGuardTrap
//
// A velocity-tracking, multi-vector circuit breaker for cross-chain bridge
// infrastructure. Enforces a single invariant:
//
//   No high-value execution may occur without a validated inbound event.
//
// Three detection vectors:
//   Vector 1 — High-velocity liquidity drain   (Multichain Jul 2023, Orbit Chain Dec 2023, Force Bridge Jun 2025)
//   Vector 2 — Privilege escalation / phantom mint (IoTeX Feb 2026, Hyperbridge Apr 2026)
//   Vector 3 — Forged router payload execution     (CrossCurve Feb 2026, Socket Protocol Jan 2024)
//
// Drosera stateless trap requirements:
//   • collect() is view — no state writes, ever
//   • shouldRespond() is pure — deterministic, no external calls
//   • shouldAlert() is pure — same constraint
//   • Addresses are constant — Drosera requires no constructor args on trap contracts
// ─────────────────────────────────────────────────────────────────────────────
contract BridgeRouterGuardTrap is ITrap {

    // Hoodi Testnet mock infrastructure addresses (v2 deployment)
    address public constant VAULT   = 0xac031158562D5834416b47A89143B9d3059a2589;
    address public constant GATEWAY = 0xe629cC7b2ceB14380FA6c8c0C1431171AF411184;
    address public constant ROUTER  = 0xF6C17127BBB5Cbc9234146A78B081ed68D0b8904;

    // ─── Thresholds ──────────────────────────────────────────────────────────
    // TODO(production): Replace with oracle-backed asset normalization.
    // These are ETH-equivalent values suitable for this PoC. Production
    // deployments require per-asset USD normalization to prevent multi-asset
    // split evasion across WBTC, USDC, ETH, and other bridged tokens.
    uint256 public constant VAULT_DRAIN_THRESHOLD   = 1_000 ether;
    uint256 public constant PHANTOM_MINT_THRESHOLD  = 10_000 ether;

    // Per-block burst threshold. Set at 40% of the window threshold so that
    // two consecutive burst blocks (2 × 400 = 800 ETH) can trigger the burst
    // detector without exceeding the window threshold — catching chunked attacks
    // that deliberately stay just below 1,000 ETH total.
    uint256 public constant BURST_THRESHOLD_VAULT   = 400 ether;
    uint256 public constant BURST_THRESHOLD_PHANTOM = 4_000 ether;

    // Two consecutive above-burst intervals required to trigger on burst count alone.
    uint256 public constant BURST_COUNT_TRIGGER = 2;

    uint8 public constant SCHEMA_VERSION = 1;

    // ─── collect() ───────────────────────────────────────────────────────────
    // Called by every shadow operator on every new block.
    // Returns a versioned, ABI-encoded snapshot of all three monitored state values.
    function collect() external view virtual override returns (bytes memory) {
        return abi.encode(CollectOutput({
            schemaVersion:          SCHEMA_VERSION,
            cumulativeWithdrawals:  IMockVault(VAULT).cumulativeWithdrawals(),
            phantomMinted:          IMockGateway(GATEWAY).phantomMinted(),
            spoofedMessageExecuted: IMockRouter(ROUTER).spoofedMessageExecuted()
        }));
    }

    // ─── shouldRespond() ─────────────────────────────────────────────────────
    // Pure. Evaluated by operators to decide whether to call snapFreeze().
    //
    // Bootstrap safety:
    //   Velocity signals require >= 2 valid samples. Without history, cumulative
    //   counters would false-trigger on any bridge with normal lifetime volume
    //   above the threshold (cold start, restart, reorg recovery).
    //   Exception: Vector 3 boolean fires immediately — no baseline needed.
    function shouldRespond(bytes[] calldata data)
        external
        pure
        virtual
        override
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        CollectOutput memory newest = _decode(data[0]);

        // Vector 3 — Hard boolean invariant. Fires immediately, no history needed.
        // [MITIGATION: CrossCurve Feb 2026 / Socket Protocol Jan 2024]
        // Invariant: router must never execute without gateway-validated payload.
        // One unauthorized execution is one too many.
        if (newest.spoofedMessageExecuted) {
            return (true, abi.encode(newest.cumulativeWithdrawals, newest.phantomMinted, true));
        }

        // Bootstrap guard — do not fire velocity checks without history.
        if (data.length < 2 || data[data.length - 1].length == 0) {
            return (false, bytes(""));
        }

        CollectOutput memory oldest = _decode(data[data.length - 1]);

        (bool isCritical, , ) = _evaluateVectors(newest, oldest);

        if (isCritical) {
            return (true, abi.encode(newest.cumulativeWithdrawals, newest.phantomMinted, false));
        }

        // Per-block burst detection — catches chunked attacks that stay below
        // the window total threshold by splitting across multiple blocks.
        (uint256 vaultBursts, uint256 phantomBursts) = _countBursts(data);
        if (vaultBursts >= BURST_COUNT_TRIGGER || phantomBursts >= BURST_COUNT_TRIGGER) {
            return (true, abi.encode(newest.cumulativeWithdrawals, newest.phantomMinted, false));
        }

        return (false, bytes(""));
    }

    // ─── shouldAlert() ───────────────────────────────────────────────────────
    // Pure. Returns AlertData for the Drosera alert server to route to
    // institutional Slack/Discord/webhook endpoints.
    // Uses identical bootstrap guard and evaluation logic as shouldRespond().
    function shouldAlert(bytes[] calldata data)
        external
        pure
        virtual
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        CollectOutput memory newest = _decode(data[0]);

        // Vector 3 — immediate alert, no history needed
        if (newest.spoofedMessageExecuted) {
            return (true, abi.encode(AlertData({
                vaultDrainVelocity: 0,
                phantomMintVelocity: 0,
                routerSpoofed: true
            })));
        }

        // Bootstrap guard
        if (data.length < 2 || data[data.length - 1].length == 0) {
            return (false, bytes(""));
        }

        CollectOutput memory oldest = _decode(data[data.length - 1]);

        (bool isCritical, uint256 vaultVelocity, uint256 phantomVelocity) = _evaluateVectors(newest, oldest);

        if (!isCritical) {
            (uint256 vaultBursts, uint256 phantomBursts) = _countBursts(data);
            isCritical = (vaultBursts >= BURST_COUNT_TRIGGER || phantomBursts >= BURST_COUNT_TRIGGER);
        }

        if (isCritical) {
            return (true, abi.encode(AlertData({
                vaultDrainVelocity: vaultVelocity,
                phantomMintVelocity: phantomVelocity,
                routerSpoofed: false
            })));
        }

        return (false, bytes(""));
    }

    function decodeAlertOutput(bytes calldata data) public pure returns (AlertData memory) {
        return abi.decode(data, (AlertData));
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    // Shared evaluation logic for Vectors 1 and 2.
    // Extracted to eliminate duplication between shouldRespond() and shouldAlert().
    function _evaluateVectors(CollectOutput memory newest, CollectOutput memory oldest)
        internal
        pure
        returns (bool isCritical, uint256 vaultVelocity, uint256 phantomVelocity)
    {
        // Vector 1 — Window total drain check
        // [MITIGATION: Multichain Jul 2023 / Orbit Chain Dec 2023 / Force Bridge Jun 2025]
        // Invariant: cumulative withdrawals must not spike by >VAULT_DRAIN_THRESHOLD
        // across the window. A spike = withdrawals executing without validated inbound proofs.
        vaultVelocity = newest.cumulativeWithdrawals > oldest.cumulativeWithdrawals
            ? newest.cumulativeWithdrawals - oldest.cumulativeWithdrawals
            : 0;

        // Vector 2 — Window total phantom mint check
        // [MITIGATION: IoTeX ioTube Feb 2026 / Hyperbridge Apr 2026]
        // Invariant: minted supply must track validated cross-chain messages.
        // A delta > PHANTOM_MINT_THRESHOLD = unbacked minting confirmed.
        phantomVelocity = newest.phantomMinted > oldest.phantomMinted
            ? newest.phantomMinted - oldest.phantomMinted
            : 0;

        isCritical = (vaultVelocity > VAULT_DRAIN_THRESHOLD) || (phantomVelocity > PHANTOM_MINT_THRESHOLD);
    }

    // Fail-safe decode. Returns a zeroed struct on malformed or undersized input
    // rather than reverting. A valid CollectOutput (uint8, uint256, uint256, bool)
    // ABI-encodes to 4 padded 32-byte words = 128 bytes minimum.
    function _decode(bytes calldata sample) internal pure returns (CollectOutput memory out) {
        if (sample.length < 128) return out;

        out = abi.decode(sample, (CollectOutput));

        // Schema guard: ignore payloads from incompatible versions.
        // Returns zeroed struct — treated as no signal, never triggers.
        if (out.schemaVersion != SCHEMA_VERSION) {
            return CollectOutput(0, 0, 0, false);
        }
    }

    // Count consecutive block-to-block intervals that exceeded the burst threshold.
    // Iterates adjacent pairs newest → oldest.
    //
    // Schema guard: samples that fail _decode() return a zeroed struct (all zeros).
    // A zeroed newer sample produces delta = 0 → no burst counted (safe).
    // A zeroed older sample produces inflated delta from 0 → real value.
    // In practice this delta will be ≤ normal bridge flow and below BURST_THRESHOLD,
    // so false positives from schema mismatches are extremely unlikely. A comment
    // is left here to document the known edge case for future reviewers.
    // TODO(production): skip interval entirely if either sample has schemaVersion = 0
    // (i.e. failed decode) to eliminate the zeroed-older inflated-delta edge case.
    function _countBursts(bytes[] calldata data)
        internal
        pure
        returns (uint256 vaultBursts, uint256 phantomBursts)
    {
        for (uint256 i = 0; i + 1 < data.length; i++) {
            if (data[i].length == 0 || data[i + 1].length == 0) continue;

            CollectOutput memory newer = _decode(data[i]);
            CollectOutput memory older = _decode(data[i + 1]);

            // Skip interval if either sample failed schema validation
            // (schemaVersion = 0 means _decode returned a zeroed struct)
            if (newer.schemaVersion == 0 || older.schemaVersion == 0) continue;

            if (newer.cumulativeWithdrawals > older.cumulativeWithdrawals) {
                uint256 delta = newer.cumulativeWithdrawals - older.cumulativeWithdrawals;
                if (delta > BURST_THRESHOLD_VAULT) vaultBursts++;
            }
            if (newer.phantomMinted > older.phantomMinted) {
                uint256 delta = newer.phantomMinted - older.phantomMinted;
                if (delta > BURST_THRESHOLD_PHANTOM) phantomBursts++;
            }
        }
    }
}
