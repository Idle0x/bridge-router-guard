# 009 — What This Work Revealed

This file does not introduce new case studies. It documents the architectural decisions made during the v3 rebuild, the mechanical corrections identified during implementation and testing, and the cross-case patterns that only become visible when reading the eight incidents as a set.

For the architectural implications beyond BridgeRouterGuard — what adjacent trap designs address the documented gaps, how the four concept traps were built and tested, and what the campaign demonstrated about their scope — see [010 — Architecture and Extensions](./010-architecture-and-extensions.md).

---

## Invariant Evolution: Velocity vs. Accounting Mismatch

The initial design monitored raw withdrawal velocity: how fast funds left the vault across a 7-block window. If the rate exceeded a threshold, the trap fired. This approach treats legitimate high-volume bridge activity and unauthorized low-volume drains identically if both cross the threshold. A bridge processing normal volume above the threshold would produce continuous false positives. An attacker operating below the threshold could drain a vault progressively without triggering detection.

The correct invariant measures the gap between executed outflow and validated inbound credit. A 2,000 ETH withdrawal with 2,000 ETH of validated credit produces zero mismatch. A 50 ETH withdrawal with zero validated credit produces a 50 ETH mismatch. The trap monitors authorization gaps, not absolute volume. This distinction defines the v3 architecture.

---

## Architectural Changes in v3

The v3 rebuild replaced absolute velocity tracking with interval delta reconciliation across three bridge layers.

`MockSourceChainOracle` registers source-chain lock events with status tracking (PENDING → CONFIRMED → CONSUMED). This provides the ground-truth layer required to measure whether destination-chain execution is authorized.

`MockMessageValidator` reads from the oracle and produces attestations. It consumes oracle events when registering credits. Only consumed events generate `validatedInboundCredits`. Only validated oracle events generate `validatedMintAuthorizations`.

The bridge layer mocks were rebuilt to expose separate counters for execution and validation. The vault tracks `executedWithdrawals` and `validatedInboundCredits` independently. The gateway tracks `cumulativeMinted` and `validatedMintAuthorizations` independently. The router tracks `executedMessages` and `gatewayValidatedMessages` independently. In normal operation, both counters in each pair move together. In exploit scenarios, the execution counter moves while the validation counter remains static. The trap reads that divergence.

The `CollectOutput` struct expanded from three fields to eight, capturing both sides of each accounting pair plus the vault's actual token balance:

```solidity
struct CollectOutput {
    uint8 schemaVersion;
    uint256 executedWithdrawals;
    uint256 validatedInboundCredits;
    uint256 cumulativeMinted;
    uint256 validatedMintAuthorizations;
    uint256 executedMessages;
    uint256 gatewayValidatedMessages;
    uint256 vaultTokenBalance;
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

`shouldRespond()` was rewritten around three mismatch computations and one reserve backstop:

```solidity
uint256 execGrowth   = newest.executedWithdrawals - oldest.executedWithdrawals;
uint256 creditGrowth = newest.validatedInboundCredits - oldest.validatedInboundCredits;

// Zero-backing hard trigger: any execution with zero validation backing
// fires immediately, regardless of amount.
if (execGrowth > 0 && creditGrowth == 0) { return (true, ...); }

// Threshold path: partial backing is allowed up to the threshold.
uint256 drainDelta = execGrowth > creditGrowth ? execGrowth - creditGrowth : 0;
if (drainDelta > VAULT_DRAIN_THRESHOLD) { return (true, ...); }
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

The previous version computed `vaultVelocity = newestWithdrawals - oldestWithdrawals` and compared it to a threshold. The v3 implementation computes `execGrowth - creditGrowth` and fires on any positive value against zero credit. A 1,500 ETH withdrawal with 1,500 ETH of validated credit produces `drainDelta = 0` and returns false. A 50 ETH withdrawal with zero credit produces `execGrowth > 0, creditGrowth == 0` and fires immediately.

---

## Vector 4: Counter-Bypass Detection

Vector 4 was added to address a specific evasion path: an attacker moving tokens through a function that does not update execution counters.

`MockBridgeVault` exposes two withdrawal paths. `executeWithdrawal()` is the legitimate path — it updates `executedWithdrawals` and requires validator proof. `directTokenTransfer()` moves ERC20 tokens directly without touching any counter. An attacker using only `directTokenTransfer()` produces zero `execGrowth`, zero `creditGrowth`, and zero mismatch across all three accounting pairs. Vectors 1, 2, and 3 return false.

Vector 4 monitors `vaultTokenBalance` directly:

```solidity
uint256 balanceDrop = oldest.vaultTokenBalance > newest.vaultTokenBalance
    ? oldest.vaultTokenBalance - newest.vaultTokenBalance : 0;
uint256 reserveDrain = balanceDrop > execGrowth ? balanceDrop - execGrowth : 0;
if (reserveDrain > VAULT_DRAIN_THRESHOLD) { return (true, ...); }
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

If the vault's actual token balance drops by more than the execution counter grows, funds moved without an accounting record. The `silentDrainCampaign` at block 2801682 validated this path on-chain: a 1,200 ETH silent drain triggered `shouldRespond = true`, and the operator network executed `snapFreeze()` at block 2801685.

A monitoring system that only reads accounting counters can be evaded by any path that avoids those counters. Vector 4 is the backstop for counter-bypass drains.

---

## Burst Detection Correction

The initial burst detection counted any two intervals above the burst threshold, regardless of adjacency. A burst at blocks 7→6, a quiet block at 6→5, and another burst at 5→4 would count as two bursts and trigger, despite the activity not being continuous.

The v3 implementation tracks consecutive streaks. A non-burst interval resets the counter:

```solidity
if (vaultDelta > BURST_THRESHOLD_VAULT) {
    vaultStreak++;
    if (vaultStreak >= BURST_COUNT_TRIGGER) vaultBursts = vaultStreak;
} else {
    vaultStreak = 0; // Reset on non-burst interval.
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

The code now enforces consecutive interval detection as originally specified.

---

## Response Payload Correction

The initial `snapFreeze(uint256 vaultV, uint256 phantomV, bool spoof)` passed `newest.cumulativeWithdrawals` as `vaultV` — a running total, not a window delta. The emitted `AttackPrevented` event labeled fields as `vaultVelocity` and `phantomVelocity`, but the values were cumulative totals.

The v3 response payload passes actual computed deltas:

```solidity
// snapFreeze(uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain)
return (true, abi.encode(drainDelta, mintDelta, unauthorizedExecs, reserveDrain));
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

Event fields now match the values they contain. Telemetry accuracy is required for incident response routing.

---

## Campaign Validation Summary

The testnet campaign demonstrated every vector under conditions requiring real on-chain execution, real block production, and real operator consensus. Edge cases and property proofs are covered by the local test suite. The campaign validates end-to-end pipeline behavior.

**Validated behaviors:**
- Every zero-backing drain (250 ETH at block 2801240, 150 ETH at blocks 2801269–2801287) fired `shouldRespond = true` immediately. The trigger mechanism is the zero-backing invariant, not threshold accumulation.
- Bypass confirmations at blocks 2801246, 2801259, and 2801264 returned `shouldRespond = false`. Partial-backed activity below threshold correctly does not trigger. Precision prevents false positives on legitimate bridge volume.
- Two confirmed on-chain `snapFreeze()` executions (operator logs: `Setting cooldown block to 2801685` and `Setting cooldown block to 2801730`) validate that the operator network reaches P2P consensus and executes the response function against live contracts.
- The `preAttackCampaign` at block 2801775 and `stolenCollateralCampaign` validate scope boundaries. BridgeRouterGuard returned false for both. `failedAttemptCount` rose for the pre-attack campaign. Lending pool risk state changed for the collateral campaign. The main trap remains silent when no accounting mismatch occurs.

**Unvalidated behavior:**
- Sub-threshold silent drain alert behavior for Vector 4 below 1,000 ETH was not observed firing. The 400 ETH silent drain at block 2801255 did not produce a visible alert trigger. The response threshold functions correctly. The sub-threshold alert timing edge case for reserve reconciliation is documented as a known boundary.

---

## Test Label Clarification (150 ETH)

Blocks 2801269–2801287 were labeled "Window Reset" in the campaign script to test whether sub-threshold activity separated by 8+ blocks would fail to accumulate. The window did reset correctly.

The trigger mechanism for these blocks was the zero-backing hard trigger, not window accumulation. 150 ETH with zero credit is `execGrowth > 0, creditGrowth == 0`, which fires unconditionally. The bypass confirmations at blocks 2801246, 2801259, and 2801264 demonstrated window reset behavior for partial-backed activity below threshold. Both results are valid and mechanically distinct.

---

## Case Study Corrections

Three architectural clarifications emerged during v3 implementation and testing:

**1. Hyperbridge Phase 1 detection.**
Initial analysis categorized Phase 1 (245 ETH drain) as below the Vector 1 threshold and therefore missed. The zero-backing hard trigger has no threshold. It fires on any `execGrowth > 0` with `creditGrowth == 0`. 245 ETH with zero credit triggers immediately. Phase 1 is caught. Case study [007](./007-hyperbridge-apr-2026.md) reflects this.

**2. Kelp DAO Vector 3 behavior.**
Initial analysis claimed Vector 3 fires for Kelp because the `lzReceive()` call was unauthorized. Vector 3 fires when `executedMessages > gatewayValidatedMessages`, which requires execution to bypass the validation layer. The poisoned DVN deceived the validator rather than bypassing it. The validator consumed the forged message and incremented `gatewayValidatedMessages` alongside `executedMessages`. The mismatch remained zero. Vector 3 does not fire. Vector 1 fires because `validatedInboundCredits` remained at zero. Case study [008](./008-kelp-dao-apr-2026.md) reflects this.

**3. 150 ETH trigger mechanism.**
As documented above, the 150 ETH tests fired via the zero-backing invariant, not window accumulation. The campaign label was mechanically inaccurate. The testnet validation section reflects the corrected framing.

---

## Cross-Case Vector Analysis

| Case | V1 | V2 | V3 | V4 | Verdict |
|---|---|---|---|---|---|
| [Multichain](./001-multichain-jul-2023.md) | ✅ | ❌ | ❌ | ✅ | `CAUGHT (pre-drain)` |
| [Orbit Chain](./002-orbit-chain-dec-2023.md) | ✅ | ❌ | ❌ | ✅ | `CAUGHT (pre-drain)` |
| [Socket Protocol](./003-socket-protocol-jan-2024.md) | — | — | — | — | `PARTIAL` |
| [Force Bridge](./004-force-bridge-jun-2025.md) | ✅ | ❌ | ❌ | ✅ | `CAUGHT (pre-drain)` |
| [CrossCurve](./005-crosscurve-feb-2026.md) | ✅ | ⚠️ | ✅ | ✅ | `CAUGHT (post-drain)` |
| [IoTeX ioTube](./006-iotex-iotube-feb-2026.md) | ✅ | ⚠️ | ❌ | ✅ | `CAUGHT (post-drain)` |
| [Hyperbridge](./007-hyperbridge-apr-2026.md) | ✅ | ✅ | ❌ | ✅ | `CAUGHT (post-drain)` |
| [Kelp DAO](./008-kelp-dao-apr-2026.md) | ✅ | ✅ | ❌ | ✅ | `CAUGHT (post-drain)` |

**Vector 3** fires only for CrossCurve, where `expressExecute()` was called directly without interacting with the validation layer. It does not fire for Kelp (poisoned validator), IoTeX (admin-layer takeover), or Hyperbridge (forged proof through verification). Vector 3 catches explicit validation bypass, not validation deception.

**Vector 1** fires for every case producing a vault-level accounting mismatch. Vault outflow is the terminal consequence of every bridge exploit. The `validatedInboundCredits` counter remains static when authorization is forged, bypassed, or stolen, because the source-chain oracle never registers a real deposit.

**Vector 2** fires when phantom minting exceeds the static threshold (Hyperbridge's 1B DOT, Kelp's 116,500 rsETH on L2s). It partially fires for CrossCurve (illiquid EYWA) and IoTeX (CIOTX below threshold at market prices). This documents the limitation of static ETH-equivalent thresholds for low-denomination tokens. Oracle-backed normalization addresses this in production.

**Socket Protocol** uses dashes rather than `❌`. Dashes indicate the vector does not apply to the attack surface. The exploit targeted distributed user approvals via an aggregator contract, not bridge reserve accounting.

---

## Aggregate Damage Assessment

| Case | Confirmed Loss | Estimated Preventable |
|---|---|---|
| [Multichain](./001-multichain-jul-2023.md) | ~$231M | ~$200M+ (multi-bridge full deployment) |
| [Orbit Chain](./002-orbit-chain-dec-2023.md) | ~$81.68M | ~$60.2M |
| [Socket Protocol](./003-socket-protocol-jan-2024.md) | ~$3.3M | $0 (wrong attack surface) |
| [Force Bridge](./004-force-bridge-jun-2025.md) | ~$3.7M | ~$2.5M+ |
| [CrossCurve](./005-crosscurve-feb-2026.md) | ~$2.76M | ~$1.28M+ (per-chain deployment) |
| [IoTeX ioTube](./006-iotex-iotube-feb-2026.md) | ~$4.4M | ~$3M–$4M |
| [Hyperbridge](./007-hyperbridge-apr-2026.md) | ~$2.5M revised | ~$1.7M (Phase 2 + incentive pools) |
| [Kelp DAO](./008-kelp-dao-apr-2026.md) | ~$292M | ~$200M (confirmed follow-on attempts) |
| **Total** | **~$621M** | **~$468M+** |

This table aggregates confirmed losses and estimated preventable amounts from each case study's damage assessment section. Every figure has a documented basis in the corresponding file. The preventable column assumes correct deployment monitoring the specific contracts exploited, with appropriate threshold configuration. Production deployment requires per-protocol instrumentation to expose the exact state variables the trap reads.

---

## Case Summary

| Case | Structural Signal | Trap Outcome |
|---|---|---|
| Multichain | MPC keys compromised; vaults drained progressively over hours | Zero-backing trigger fires before majority of funds leave |
| Orbit Chain | 4-hour probe window; five parallel asset streams | Fires on first bulk withdrawal; protects $60M+ remaining in vault |
| Socket Protocol | Distributed user approvals drained via aggregator calldata injection | Wrong attack surface; no bridge accounting mismatch produced |
| Force Bridge | 6 hours of failed privileged calls preceding successful drain | Mismatch trap fires on drain; pre-attack window requires separate monitor |
| CrossCurve | Missing access control on publicly callable execution function | Cleanest Vector 3 case; explicit validation bypass fires immediately |
| IoTeX ioTube | Single compromised key; malicious upgrade; two contracts seized | Vector 1 fires correctly; Vector 2 CIOTX mint below static threshold |
| Hyperbridge | Missing MMR bounds check; forged message grants admin | Phase 1 fires zero-backing trigger; Phase 2 produces ~51× threshold overshoot |
| Kelp DAO | 1-of-1 DVN poisoned via RPC compromise; forged `lzReceive()` | Vector 1 fires via vault mismatch; Vector 3 silent (validator deceived, not bypassed) |

---

For architectural implications beyond BridgeRouterGuard — what adjacent trap designs address the documented gaps, how the four concept traps were built and tested, and what the campaign demonstrated about their scope — see [010 — Architecture and Extensions](./010-architecture-and-extensions.md).
