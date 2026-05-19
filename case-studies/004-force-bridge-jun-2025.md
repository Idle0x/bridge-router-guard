# Force Bridge — June 2025

**Loss:** ~$3.7M confirmed (~$3.1M on Ethereum, ~$600K on BNB Chain)  
**Date:** June 1–2, 2025; failed attempts beginning ~01:36 UTC June 1; successful drain at 07:36 UTC June 2  
**Root Cause:** Compromised deployer key; privileged access control failure  
**Primary Vector:** Vector 1 — Vault drain mismatch (`executedWithdrawals - validatedInboundCredits`)  
**Trap verdict:** `CAUGHT (pre-drain)`

The drain unfolded across multiple transactions over ~30–60 minutes after the first successful execution — the same progressive multi-block signal profile as Multichain and Orbit Chain. The zero-backing hard trigger fires on the first Ethereum-side withdrawal. What makes this case distinct is not how the drain was caught, but what preceded it: six hours of observable failed privileged function calls on-chain before any funds moved. BridgeRouterGuard fires on the consequence. A different trap class fires on the precursor.

---

## 1. Incident Summary

Force Bridge is a cross-chain bridge connecting the Nervos Network (CKB) to Ethereum and BNB Chain, operated by Magickbase. It uses a multi-signature wallet protecting locked asset reserves on both chains. The day before the attack, Nervos announced it would sunset Force Bridge by November 2025, giving users a withdrawal window.

On June 1–2, 2025, an attacker with access to privileged deployer keys made multiple failed attempts to drain Force Bridge over approximately six hours before successfully executing the exploit. The first successful drain began at 07:36 UTC on June 2 on BNB Chain, followed by Ethereum. Total losses: ~$3.7M. Assets drained: 257,800 USDT, 539 ETH (~$1.35M), 898,300 USDC, 60,400 DAI, and 0.79 WBTC (~$83K). All assets were converted to ETH and routed through Tornado Cash and FixedFloat.

Magickbase detected abnormal activity at 03:12 UTC and paused services as a precaution — during the failed-attempt window, before any successful drain. The attacker still succeeded approximately four hours later, suggesting the pause was incomplete or lifted.

Attribution: Unconfirmed. The sunset announcement timing — attack occurring one day after the wind-down announcement — raises the possibility of an insider with advance knowledge. Halborn noted this directly without concluding either way.

---

## 2. Technical Root Cause

**The vulnerability:** Access control failure via compromised deployer key. The attacker gained access to privileged accounts controlling protected functions within Force Bridge's smart contracts — allowing direct calls to `unlock()` and `release()` without providing valid cross-chain proof of corresponding locked assets.

The bridge contracts functioned exactly as designed. The failure was entirely in key management.

**Attack sequence (confirmed on-chain):**

1. **~01:36 UTC, June 1** — First failed attempt. Extractor Web3 confirmed a failed exploit attempt approximately six hours before the successful drain.
2. **~03:12 UTC, June 2** — Magickbase detects abnormal activity. Pauses Force Bridge services.
3. **Multiple failed attempts** across ~6 hours before successful calibration.
4. **07:36 UTC, June 2** — First successful drain — 874 BNB (~$572K) on BNB Chain.
5. **~07:40–08:00 UTC** — Ethereum-side assets drained across multiple transactions: 257,800 USDT, 539 ETH, 898,300 USDC, 60,400 DAI, 0.79 WBTC. Ethereum total: ~$3.1M.
6. **Post-drain** — All assets converted to ETH, routed through Tornado Cash and FixedFloat.

The drain unfolded across multiple transactions over ~30–60 minutes — structurally identical to Multichain ([001](./001-multichain-jul-2023.md)) and Orbit Chain ([002](./002-orbit-chain-dec-2023.md)) at a smaller scale.

---

## 3. On-Chain Signal Profile

This exploit exhibits two distinct observable phases with fundamentally different signal properties.

**Phase 1 — Failed attempt window (~01:36 – ~07:36 UTC):**

Failed transactions calling privileged bridge functions are on-chain events. They produce no withdrawal velocity and no mismatch — `executedWithdrawals` does not change when a transaction reverts. What they produce is a pattern: unauthorized addresses calling restricted functions, transactions reverting, the same functions being retried. This is observable in transaction history, but it produces no signal in any of the four mismatch invariants the trap monitors.

`collect()` throughout Phase 1:
- `executedWithdrawals` — unchanged
- `validatedInboundCredits` — unchanged
- All other fields — unchanged

BridgeRouterGuard has no mismatch to evaluate during Phase 1.

**Phase 2 — Successful drain (~07:36 UTC onward):**

| Time UTC | Event | executedWithdrawals growth | validatedInboundCredits |
|---|---|---|---|
| 07:36 | BNB Chain: 874 BNB | +~$572K (separate chain) | 0 — unchanged |
| ~07:40 | ETH: first Ethereum txs | +growing | 0 — unchanged |
| ~07:40–08:00 | USDT, USDC, DAI, WBTC, ETH | +~$3.1M cumulative | 0 — unchanged |

Every Ethereum-side withdrawal executes against zero validated inbound credit. The zero-backing hard trigger fires on the first Ethereum withdrawal with any meaningful `execGrowth`.

**BNB Chain note:** The 874 BNB drain occurs first and on a separate chain. A single Ethereum-side deployment cannot read BNB Chain state. Full BNB Chain coverage requires a separate trap deployment on BNB Chain.

---

## 4. Design Envelope Assessment

This incident matches the primary design target of the trap. Force Bridge operates as a lock-and-release bridge with asset reserves on Ethereum and BNB Chain, controlled by an off-chain authorization mechanism. The attack pattern — unauthorized withdrawal execution with zero validated inbound credit — is exactly what Vector 1 detects. The key compromise occurred off-chain; the trap detects the downstream accounting consequence.

```solidity
// Zero-backing hard trigger — fires on any execution with zero credit backing,
// regardless of amount.
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](../src/core/BridgeRouterGuardTrap.sol)

The sequential multi-transaction drain across ~30–60 minutes produces a persistent mismatch from the first Ethereum withdrawal. The zero-backing hard trigger fires on the first sample capturing `execGrowth > 0`. Phase 1 produces no mismatch signal. This is a structural boundary: the most valuable potential intervention window — six hours of observable on-chain failed attempts — is not covered by a mismatch accounting trap. Any lock-and-release bridge where a reserve of locked assets exists on-chain and the release mechanism is controlled by a compromisable off-chain key set produces this identical zero-backing signal. The sunsetting context is architecturally relevant: a bridge in wind-down mode processes minimal flow. Static thresholds calibrated for normal operation become conservative as baseline activity drops. The zero-backing trigger is unaffected by volume, but the threshold path benefits from dynamic calibration against current baseline flow.

---

## 5. Trap Vector Mapping

| Vector | Status | Signal |
|---|---|---|
| Vector 1 — Vault drain mismatch | ✅ Fires within first above-signal Ethereum withdrawal | `execGrowth > 0`, `creditGrowth == 0` → zero-backing trigger |
| Vector 2 — Gateway phantom mint mismatch | ❌ No signal | No tokens minted; assets withdrawn from existing locked reserves |
| Vector 3 — Router unauthorized execution | ❌ No signal | Privileged function calls using valid (compromised) keys; no cross-chain message executed |
| Vector 4 — Reserve reconciliation | ✅ Fires (secondary confirmation) | `vaultTokenBalance` drops without counter movement |

**Vector 1 — zero-backing hard trigger:**

```solidity
uint256 execGrowth  = newest.executedWithdrawals > oldest.executedWithdrawals
    ? newest.executedWithdrawals - oldest.executedWithdrawals : 0;
uint256 creditGrowth = newest.validatedInboundCredits > oldest.validatedInboundCredits
    ? newest.validatedInboundCredits - oldest.validatedInboundCredits : 0;

// Zero-backing: any execution growth against zero credit growth = immediate response.
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](../src/core/BridgeRouterGuardTrap.sol)

The failed privileged function calls during Phase 1 leave `executedWithdrawals` unchanged. Failed transactions that revert produce no counter movement. The trap has no signal to evaluate. Vector 4 serves as the backstop for counter-bypass variants where balance drops occur without corresponding execution counter increments.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price June 2025: ~$2,500.

```
~01:36 UTC, June 1
                     FIRST FAILED ATTEMPT. Privileged function call reverts.
                     collect(): executedWithdrawals unchanged.
                     [TRAP: No signal. Zero mismatch.]

~03:12 UTC, June 2   Magickbase detects abnormal activity. Pauses service.
                     [MANUAL DETECTION: 1h 36min after first failed attempt.
                      Pause did not prevent subsequent successful drain.]

Multiple failed      Additional failed attempts across 6-hour window.
attempts             [TRAP: No signal. executedWithdrawals still unchanged.]

07:36 UTC, June 2    BNB Chain: 874 BNB (~$250K).
                     [TRAP on Ethereum deployment: no signal — different chain.]
                     [TRAP on BNB deployment (if deployed): execGrowth > 0, creditGrowth = 0
                      → zero-backing trigger fires.]

~07:40 UTC           FIRST ETHEREUM WITHDRAWAL.
                     collect():
                       executedWithdrawals += meaningful amount
                       validatedInboundCredits = 0 (unchanged)
                     execGrowth > 0, creditGrowth == 0 → zero-backing trigger.
                     shouldRespond() returns (true, abi.encode(execGrowth, 0, 0, 0))
                     [TRAP: Fires 1 block after trigger (baseline operator latency)]

~07:40 + 1 block
                     Operator network reaches consensus.
                     snapFreeze() executes: vault, gateway, router paused best-effort via try/catch.
                     AttackPrevented emitted with drainDelta = execGrowth value.

~07:40–08:00 UTC     [ACTUAL] Remaining Ethereum drains: USDT, USDC, DAI, WBTC, ETH.
                     [WITH TRAP] All subsequent transactions revert against frozen vault.
                     Majority of Ethereum-side ~$3.1M protected.

Trap exposure window:   1–2 blocks (~12–24 seconds) from first Ethereum withdrawal
Actual exposure window: ~30–60 minutes for Ethereum drain (no automated pause)
Pre-drain detection gap: 6 hours of observable failed attempts — not covered by this trap
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| BNB Chain drain — 874 BNB (~$250K) | Lost | Lost — separate chain, requires separate BNB deployment |
| First Ethereum withdrawal (trigger event) | Lost | Lost — completes before snapFreeze (unavoidable trigger event) |
| Remaining Ethereum assets (~$2.5M+) | Lost | Protected — vault frozen within 1–2 blocks |
| **Total preventable (Ethereum only)** | — | **~$2.5M+** |
| **Total preventable (BNB + ETH, dual deployment)** | — | **~$2.7M+** |
| **Confirmed total loss** | ~$3.7M | ~$1M |

The first Ethereum withdrawal fires the trigger but completes before `snapFreeze()` executes. All subsequent drains occur across the following 30–60 minutes in separate transactions. Every one of them reverts against the frozen vault.

No dollar figure enters the damage table for the Phase 1 period because no assets moved during it. If a pre-attack window monitor had been deployed and fired during the failed-attempt window, the entire $3.7M loss is potentially preventable.

---

## 8. What the Trap Does Not Cover Here

**The 6-hour failed-attempt window.** Six hours of on-chain failed privileged function calls preceded the successful drain. `executedWithdrawals` never changes during failed transactions. The mismatch accounting trap has no signal to evaluate. This gap makes Force Bridge the strongest case for a pre-attack window monitor.

**Off-chain key compromise.** The deployer key was compromised entirely off-chain. No on-chain state change signals key theft.

**BNB Chain single-deployment gap.** The first successful transaction occurs on BNB Chain. A single Ethereum deployment cannot observe it. Full protection requires a parallel deployment on BNB Chain.

**Sunsetting context and threshold calibration.** After the sunset announcement, normal bridge flow decreases. The zero-backing trigger is unaffected by volume. The threshold path benefits from calibration against reduced baseline flow.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The zero-backing trigger covers Phase 2 correctly. No modification to existing vectors improves coverage for Phase 1. A production deployment should recalibrate `VAULT_DRAIN_THRESHOLD` as baseline volume decreases during wind-down.

**Beyond BridgeRouterGuard:**

Force Bridge provides concrete on-chain evidence for a pre-attack window monitor: six hours of failed `unlock()` and `release()` calls from a non-authorized address. These calls reverted but remain permanently visible on-chain. A separate trap watching for this pattern would read `failedAttemptCount` and `lastUnauthorizedCaller`, firing if N failed privileged calls occur within M blocks from an address outside the authorized signer set.

This concept is implemented as [`PreAttackMonitorTrap`](../src/concepts/PreAttackMonitorTrap.sol) and tested in [`test/concepts/PreAttackMonitor.t.sol`](../test/concepts/PreAttackMonitor.t.sol). The campaign demonstrated it at block 2801775 — `preAttackCampaign` executed 5 failed attempts against `MockPrivilegedBridge`, BridgeRouterGuard returned false (correct — no mismatch), and `failedAttemptCount` rose to 5. See [010 — Architecture and Extensions](./010-architecture-and-extensions.md#trap-3--pre-attack-window-monitor) for the full design.

Force Bridge and Orbit Chain ([002](./002-orbit-chain-dec-2023.md)) together demonstrate the need for this monitor. Force Bridge's failed-call window provides the more actionable signal — the same restricted functions that later succeeded.

---

## 10. Sources

- Halborn: "Explained: The Force Bridge Hack (June 2025)" — https://halborn.com/blog/post/explained-the-force-bridge-hack-june-2025
- The Block: "Hackers Drain Over $3 Million from Nervos Network's Force Bridge" — https://theblock.co/post/356535/hackers-drain-over-3-million-in-crypto-from-nervos-networks-force-cross-chain-bridge
- Crypto.news: "Nervos Network Loses $3M in Force Bridge Exploit" — https://crypto.news/nervos-network-suffers-major-exploit-as-3-9m-in-crypto-is-stolen-from-force-bridge/
- Extractor Web3 (via X, June 2, 2025): "There was failed attempt to execute an attack 6 hours prior to successful one." — https://twitter.com/extractor_web3/status/1929444219757756584
- Cyvers Alerts (via X, June 2, 2025): Initial detection and asset breakdown — https://twitter.com/cyversalerts/status/1929428359856935185
- Magickbase official statement (via X, June 2, 2025): "We've detected abnormal activity on #ForceBridge and have paused the service"

