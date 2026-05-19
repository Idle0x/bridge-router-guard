# 010 — Architecture and Extensions

**What BridgeRouterGuard monitors, why it is designed as it is, where it reaches its limits, and what the four concept traps demonstrate about the detection surface beyond those limits.**

This file documents the architectural decisions behind the v3 trap, the structural boundaries identified across eight case studies, and the concept traps built to address gaps outside the accounting mismatch detection surface. All concept traps described here are implemented, deployed to Hoodi testnet, and covered by dedicated test suites. Scope boundary demonstrations were executed as part of the testnet campaign.

---

## Why the Trap Is Designed the Way It Is

BridgeRouterGuard enforces four accounting invariants across three bridge contracts:

```
executedWithdrawals     == validatedInboundCredits      (Vector 1)
cumulativeMinted        == validatedMintAuthorizations   (Vector 2)
executedMessages        == gatewayValidatedMessages      (Vector 3)
vaultTokenBalance       >= executedWithdrawals           (Vector 4)
```

Every design decision follows from these invariants and from the constraint that `collect()` is a `view` function and `shouldRespond()` is `pure`. No state writes. No external calls in `shouldRespond()`. No off-chain data dependencies. The trap is stateless; the operator runtime handles all temporal mechanics.

**Why separate counters rather than a single net value:**
A single net outflow counter collapses execution and validation into one number. If the protocol adds correctly, the counter appears normal. If execution exceeds validation, the counter wraps or goes negative, producing no clean mismatch signal. Separate counters for execution and validation make the gap directly computable: `execGrowth - creditGrowth`. The gap is the invariant violation.

**Why the zero-backing path fires before the threshold path:**
The threshold path (`drainDelta > VAULT_DRAIN_THRESHOLD`) catches large partial-backing violations where some credit exists but execution outpaced it beyond configured tolerance. The zero-backing path catches any execution against zero credit, regardless of amount. A 1 wei withdrawal with zero credit is still execution without validation. The threshold path never evaluates it; the zero-backing path catches it immediately. These are two distinct failure modes requiring two distinct checks.

**Why the 7-block window lives in the operator runtime, not the contract:**
`collect()` is `view` and `shouldRespond()` is `pure`. Neither can store state between calls. The 7-block trailing window is assembled by the operator runtime and passed in as the `bytes[] calldata data` array. The contract evaluates the window but does not maintain it. The operator handles history; the contract handles logic.

**Why `snapFreeze()` uses a 33-block cooldown enforced on-chain:**
The cooldown prevents consecutive submissions during a sustained attack. An attacker continuously triggering the invariant cannot force repeated `snapFreeze()` calls that waste gas or interfere with recovery. The cooldown is enforced on-chain in `BridgeRouterGuardResponse.sol` rather than in the operator runtime, preventing bypass by misconfigured or malicious nodes. The 33-block (~396 second) duration allows human review while remaining short enough to catch a genuine second incident after expiry.

**Why Vector 4 is a balance check rather than a counter:**
The three counter-based vectors only fire when execution counters move. An attacker bypassing execution counters entirely — using a token transfer path that does not update `executedWithdrawals` — produces zero counter movement and zero mismatch across Vectors 1, 2, and 3. Vector 4 reads `vaultTokenBalance` directly from the ERC20 token and compares it against `executedWithdrawals` growth. If the balance drops more than the counter grows, funds moved without accounting. The `directTokenTransfer()` path in `MockBridgeVault` and the `silentDrainCampaign` at block 2801682 validate this detection path on-chain.

---

## Where the Trap Reaches Its Limits

Four structural limits emerge from the case studies and the campaign. These are known boundaries of an on-chain accounting monitor, not design flaws.

### 1. The trigger event is always lost
The trap fires on the block containing the invariant violation. The transaction that produced that violation is already confirmed on-chain. A reactive monitor cannot prevent the transaction that generates its own detection signal. Containment value lies in what happens after the trigger event. For progressive drains (Multichain, Orbit Chain), the trigger event is a small fraction of total losses. For single-block drains with follow-on attempts (Kelp DAO), the trigger event is the largest single loss, but subsequent attempts are fully preventable.

### 2. Sub-threshold partial-backing violations are intentional precision tradeoffs
The threshold path fires when `drainDelta > VAULT_DRAIN_THRESHOLD`. Drains below threshold with partial backing are intentionally allowed through. This is a precision-over-recall design choice: a lower threshold catches more potential violations but also flags legitimate high-volume bridge activity. Campaign bypass confirmations at blocks 2801246, 2801259, and 2801264 demonstrate this tradeoff functioning as designed. The zero-backing path is exempt from this tradeoff and fires regardless of amount.

### 3. Wrong attack surface — Socket Protocol
Approval-draining attacks targeting distributed user wallet state produce no signal in any of the four accounting vectors. The bridge reserve is untouched. No counter moves. No monitored vault balance changes. This is a scope boundary, not a calibration problem. A circuit breaker on bridge reserves cannot catch approval-draining attacks against individual user wallets.

### 4. Off-chain root causes have no precursor signal
MPC key compromise (Multichain), deployer key compromise (Force Bridge), Validator key compromise (IoTeX), RPC poisoning with binary replacement (Kelp) — all occur off-chain before any transaction reaches the chain. The trap detects the on-chain consequence. The compromise itself is invisible until funds move. Six of eight cases have off-chain root causes. In all six, the trap fires on the consequence correctly. Where on-chain precursors exist (Force Bridge's failed privileged calls, Orbit Chain's probe transactions), they require a different detection primitive.

---

## Trap 1 — DVN Attestation Liveness Monitor

**Evidence from:** [Kelp DAO (008)](./008-kelp-dao-apr-2026.md)

The Kelp attack created a ~6-hour window between DVN failover onto poisoned endpoints and the drain. During that window, the DVN operated on falsified data for every query. Whether the resulting attestation patterns are distinguishable from normal DVN maintenance events requires empirical validation against real attestation traffic.

This concept is not implemented as a contract in the current codebase. It is documented here as Trap 1 because the Kelp case provides the strongest available evidence for its value, and because the other three concept traps demonstrate that building and testing a concept is the correct evaluation methodology.

**Proposed monitoring surface:**
```
collect():        reads EndpointV2 for DVN attestation frequency,
                  latency, and source endpoint addresses per OApp pathway
shouldRespond():  fires if patterns deviate significantly from established
                  baseline in ways consistent with failover onto different
                  endpoints — unusual gaps, confirmation spikes, latency
                  changes, or source endpoint address changes
response:         pause the OFT bridge pending human review
```

**Empirical requirement:** Whether attestation pattern deviations from DVN endpoint failover are distinguishable from normal DVN maintenance operations is unknown without baseline data. The other three concept traps are grounded in observable on-chain state (`failedAttemptCount`, `owner()`, collateral composition). DVN attestation liveness requires empirical validation: collect baseline attestation data from a live LayerZero DVN deployment, measure endpoint failover signatures, and determine whether a threshold exists that separates failover from maintenance events. This is an engineering validation step, not an architectural speculation.

---

## Trap 2 — Ownership State Monitor

**Evidence from:** [IoTeX ioTube (006)](./006-iotex-iotube-feb-2026.md) and [Hyperbridge (007)](./007-hyperbridge-apr-2026.md)

Two exploits via entirely different root causes — a compromised upgrade key and a forged MMR proof — both produced the same intermediate step before any phantom minting occurred: admin control over a bridge token contract was transferred to an attacker-controlled address. This intermediate step is observable in the same block it occurs. BridgeRouterGuard fires on the phantom mint. The ownership monitor fires on the transfer, before the first mint is submitted.

**Implementation:** [`src/concepts/OwnershipMonitorTrap.sol`](../src/concepts/OwnershipMonitorTrap.sol)  
**Tests:** [`test/concepts/ConceptTraps.t.sol`](../test/concepts/ConceptTraps.t.sol)

```solidity
// OwnershipMonitorTrap.collect()
// Reads the current owner/implementation of each monitored contract.
// Fires if either changes to an address outside the known-authorized set.
struct CollectOutput {
    uint8 schemaVersion;
    address gatewayAdmin;        // MockUpgradeableGateway.owner()
    address gatewayImpl;         // MockUpgradeableGateway.implementation()
}
```
→ [`src/concepts/OwnershipMonitorTrap.sol`](../src/concepts/OwnershipMonitorTrap.sol)

`shouldRespond()` fires if either field changes to an address not in the authorized set. The response executes in the same block as the ownership change, before the attacker calls `mintPhantom()` or any equivalent function.

**Test coverage:**
- Admin change to unauthorized address → fires immediately
- Admin change to authorized address (legitimate upgrade) → no trigger
- Implementation change to unauthorized address → fires immediately
- Consecutive changes accumulate correctly
- Cold start with no prior baseline → no trigger (bootstrap safety)

**Convergence argument:** Two independent attack paths — compromised upgrade key and forged cryptographic proof — both produce the same observable intermediate state. A trap watching admin addresses is durable against both, and against any future attack that produces the same intermediate step regardless of the initial compromise vector.

**Tradeoff:** The trap must know the expected owner address. Legitimate upgrades produce a brief pause for human review. For protocols that upgrade infrequently, this tradeoff is acceptable. For protocols with frequent admin operations, a timelock-aware allowlist or governance-integrated approach is required.

---

## Trap 3 — Pre-Attack Window Monitor

**Evidence from:** [Force Bridge (004)](./004-force-bridge-jun-2025.md) and [Orbit Chain (002)](./002-orbit-chain-dec-2023.md)

Force Bridge exhibited six hours of failed privileged function calls from a non-authorized address before the first successful drain. Orbit Chain exhibited four hours of structured probe transactions confirming key access across five asset types. Both produced on-chain signals before any funds moved. BridgeRouterGuard has no mismatch to evaluate during these windows. A pre-attack window monitor is the appropriate detection primitive for this phase.

**Implementation:** [`src/concepts/PreAttackMonitorTrap.sol`](../src/concepts/PreAttackMonitorTrap.sol)  
**Tests:** [`test/concepts/ConceptTraps.t.sol`](../test/concepts/ConceptTraps.t.sol)

```solidity
// PreAttackMonitorTrap.collect()
// Reads the count of failed privileged calls and the most recent
// unauthorized caller from MockPrivilegedBridge.
struct CollectOutput {
    uint8 schemaVersion;
    uint256 failedAttemptCount;
    address lastUnauthorizedCaller;
    uint256 lastAttemptBlock;
}
```
→ [`src/concepts/PreAttackMonitorTrap.sol`](../src/concepts/PreAttackMonitorTrap.sol)

`shouldRespond()` fires if `failedAttemptCount` growth exceeds a configured threshold within the observation window, originating from an address outside the authorized signer set.

**Test coverage:**
- N failed attempts within M blocks from unauthorized address → fires
- Failed attempts below threshold → no trigger
- Authorized calls do not increment `failedAttemptCount`
- Ring buffer correctness for window-based rate detection
- Cold start with no prior baseline → no trigger

**Campaign demonstration (block 2801775):**
```
preAttackCampaign($PRIVILEGED_BRIDGE, 5)

Transaction hashes (3 txs in same block):
0x666910091398ac83a1e32f0f0e118df11bff10518b063024ad6466f0e47a9865
0x9d0882e1ac7e6a0cddedb6459b01e21433cb6a50bd603a26ec72bc9c078ab71d
0x6ae6ace20863d1687f79898a4bfd1004738c2cde51c71378adac23632a8bb085

BridgeRouterGuard: shouldRespond = false (correct — no mismatch)
MockPrivilegedBridge.failedAttemptCount: 0 → 5
PreAttackMonitorTrap: fires (failedAttemptCount growth = 5 > threshold)
```
The scope boundary between BridgeRouterGuard and PreAttackMonitorTrap is validated on-chain.

**Force Bridge quantification:** If deployed on Force Bridge, this trap would have fired approximately six hours before the successful drain, with zero dollars at risk. The entire $3.7M loss is preventable if containment executes during the failed-attempt window.

**Implementation constraint:** Most bridge contracts revert silently on unauthorized calls rather than exposing a `failedAttemptCount` state variable. `MockPrivilegedBridge` exposes it by design. A production deployment requires the bridge contract to expose this counter, or an event-log indexer that feeds the counter to a readable on-chain variable. This is a protocol-side instrumentation requirement.

---

## Trap 4 — Position Monitor

**Evidence from:** [Kelp DAO (008)](./008-kelp-dao-apr-2026.md)

After the Kelp drain, the attacker deposited 116,500 stolen rsETH into Aave V3 as collateral and borrowed ~$236M WETH. This produced a detectable downstream signal in the lending protocol: a sudden large collateral deposit of a bridge token alongside a utilization spike. BridgeRouterGuard monitors bridge contracts and has no visibility into lending pool collateral composition. A position monitor watching the lending pool catches the downstream consequence of the bridge exploit.

**Implementation:** [`src/concepts/PositionMonitorTrap.sol`](../src/concepts/PositionMonitorTrap.sol)  
**Tests:** [`test/concepts/ConceptTraps.t.sol`](../test/concepts/ConceptTraps.t.sol)

```solidity
// PositionMonitorTrap.collect()
// Reads collateral composition and utilization from MockLendingPool.
struct CollectOutput {
    uint8 schemaVersion;
    uint256 bridgeTokenCollateralValue;
    uint256 totalCollateralValue;
    uint256 utilizationRate;       // basis points: 10000 = 100%
    bool isHighRiskState;
}
```
→ [`src/concepts/PositionMonitorTrap.sol`](../src/concepts/PositionMonitorTrap.sol)

`shouldRespond()` fires if bridge token collateral concentration exceeds a configured threshold alongside a utilization spike — the specific pattern produced by a large stolen-collateral deposit.

**Test coverage:**
- High bridge-token collateral concentration → fires
- Utilization spike alone → fires (separate threshold)
- Combined concentration + utilization spike → fires
- Safe utilization with diversified collateral → no trigger
- Cold start → no trigger

**Campaign demonstration (`stolenCollateralCampaign`):**
The campaign deposited stolen mock tokens into `MockLendingPool` after a bridge drain. BridgeRouterGuard returned false — correctly, since the bridge accounting mismatch was already established and `snapFreeze()` was active. `MockLendingPool.isHighRiskState()` returned true. `PositionMonitorTrap.shouldRespond()` fires on this state. BridgeRouterGuard covers the bridge layer. The position monitor covers the lending layer. They are complementary.

**Kelp-specific framing:** Aave's Guardian froze rsETH markets 77 minutes after the Kelp drain. A position monitor watching Aave's collateral composition for sudden large bridge-token deposits would have flagged the risk within blocks of the collateral deposit. The monitor does not prevent the bridge drain; it limits downstream protocol damage.

---

## How These Traps Relate to Each Other

Each trap monitors a different point in the attack chain:

```
Off-chain preparation
  → Trap 1 (DVN attestation) — if the signal is distinguishable

Admin takeover / ownership change
  → Trap 2 (Ownership state monitor) — fires before first phantom mint

Pre-attack privileged function attempts
  → Trap 3 (Pre-attack window monitor) — fires before first successful drain

First on-chain accounting violation
  → BridgeRouterGuard — always the backstop, fires on consequence

Downstream protocol exploitation
  → Trap 4 (Position monitor) — fires on lending pool impact
```

BridgeRouterGuard catches every case that produces an accounting mismatch. It is sufficient for six of the eight exploits in this set. The three implemented concept traps cover the documented gaps: the ownership change that precedes the mint (Trap 2), the failed-attempt window before the drain (Trap 3), and the downstream lending protocol impact after the drain (Trap 4).

None of these traps are alternatives to BridgeRouterGuard. They are complementary monitors watching different parts of the same attack surface. The Drosera model — same operator network, same consensus mechanism, independent `collect()` and `shouldRespond()` per trap — makes deploying all of them simultaneously straightforward. What changes per deployment is which on-chain state `collect()` reads and what invariant `shouldRespond()` evaluates. The operator infrastructure is shared.

---

## The Composability Point

Every trap in the Drosera model shares the same structure:

- `collect()` — reads specific on-chain state (view, no side effects)
- `shouldRespond()` — evaluates invariants against that state (pure, deterministic)
- A response contract — executes on operator consensus

BridgeRouterGuard is one instantiation. The four concept traps are four more. They share a deployment environment, an operator network, and a governance model. They do not share state or logic. Each is independently deployable and independently configurable.

The eight case studies and the testnet campaign establish that for cross-chain bridge accounting violations, three vectors plus a reserve reconciliation backstop cover the detectable signal surface reliably. For the attack surface that precedes and follows the accounting violation — ownership changes, failed-attempt windows, downstream lending protocol impact — purpose-built monitors addressing those specific signals are the correct architectural extension.
