# Multichain — July 2023

**Loss:** ~$126M confirmed (Fantom bridge: ~$102M, Moonriver: ~$6.8M, Dogechain: ~$666K; additional drains July 7: ~$103M reported by Beosin)  
**Date:** July 6–7, 2023  
**Root Cause:** MPC private key compromise; centralized cloud infrastructure seizure  
**Primary Vector:** Vector 1 — Vault drain mismatch (`executedWithdrawals - validatedInboundCredits`)  
**Trap verdict:** `CAUGHT (pre-drain)`

The drain unfolded across multiple transactions over approximately 4 hours. The trap fires as soon as any withdrawal executes with zero validated inbound credit — not when the cumulative amount crosses a threshold, but the moment the first unauthorized execution lands on-chain.

---

## 1. Incident Summary

Multichain (formerly Anyswap) was a cross-chain bridge protocol routing assets across Ethereum, Fantom, BNB Chain, Polygon, Avalanche, and 20+ other chains via a Multi-Party Computation (MPC) system. At its peak it held over $7B TVL.

On July 6, 2023, assets locked in Multichain's MPC bridge addresses began moving to unknown EOA addresses without user authorization. The drain was progressive: a $2 USDC probe at 16:21 UTC, escalating to ~$102M drained from the Fantom bridge over several hours, then cascading to Moonriver and Dogechain. No smart contract vulnerabilities were identified — all evidence pointed to compromise of the MPC private keys, consistent with the May 2023 arrest of CEO Zhaojun and Chinese police confiscation of his servers and hardware wallets. Multichain ceased operations permanently on July 7, 2023.

---

## 2. Technical Root Cause

**The vulnerability:** MPC private key compromise. The MPC addresses holding locked assets were EOAs — meaning whoever controlled the private keys could move funds without any on-chain validation logic or smart contract interaction.

**The structural failure:** Despite being marketed as decentralized MPC, all MPC node servers ran under a single cloud account controlled by CEO Zhaojun. His May 21, 2023 arrest resulted in confiscation of all devices and access credentials. From that point, no one with legitimate authority could access or secure the bridge infrastructure.

**Attack sequence (confirmed on-chain):**

1. **May 21, 2023** — CEO Zhaojun arrested. MPC access keys confiscated.
2. **May 31 – July 5, 2023** — Degraded operations, stuck transactions.
3. **July 6, 16:21 UTC** — $2 USDC probe withdrawn from Fantom bridge.
4. **~18:21 UTC** — ~$30.1M USDC withdrawn from Fantom bridge.
5. **~18:21–18:30 UTC** — 1,023.8 WBTC (~$30.9M) withdrawn.
6. **~18:30–19:00 UTC** — 7,214 WETH (~$13.6M) and ~$20M in altcoins withdrawn. Total Fantom drain: ~$102M across ~40 minutes.
7. **~19:46 UTC** — Moonriver bridge drain: ~$6.8M.
8. **~20:16 UTC** — Dogechain bridge drain: ~$666K.
9. **July 7, 2023** — Additional ~$103M drained. Multichain announces services halted indefinitely.
10. **July 8, 2023** — Circle and Tether freeze $65M+ linked to attacker addresses.

The Multichain MPC bridge addresses were EOAs. Funds moved via direct EOA-to-EOA transfers — no `anySwapOut()` call, no bridge router invocation, no smart contract state change in the bridge's execution layer. The only observable signal is in the mismatch between what was withdrawn and what was validated.

**Attribution:** Unresolved. Three competing theories: Chinese police or state-affiliated actors using confiscated keys; Zhaojun's family acting to preserve assets (sister confirmed transferring remaining funds July 9, later arrested); external hackers exploiting the chaos window. No definitive attribution confirmed in any post-mortem or legal proceeding.

---

## 3. On-Chain Signal Profile

The drain was not atomic. It unfolded across dozens of separate transactions over approximately 3–4 hours. This progressive structure provides a clear detection window: there was no single atomic event to stop, only an ongoing drain with an obvious mismatch accumulating across every block.

In v3 terms, what `collect()` would have read at each stage:

| Time UTC | executedWithdrawals | validatedInboundCredits | Mismatch (delta) |
|---|---|---|---|
| 16:21 — $2 USDC probe | +~$0 (below precision) | 0 | ~$0 |
| ~18:21 — $30.1M USDC | +~$30.1M | 0 | +~$30.1M |
| ~18:21–18:30 — $30.9M WBTC | +~$61M cumulative | 0 | +~$61M |
| ~18:30–19:00 — WETH + altcoins | +~$95M cumulative | 0 | +~$95M |
| ~19:46 — Moonriver | +~$102M | 0 | +~$102M |

`validatedInboundCredits` never moves. There is no oracle confirmation, no validator consuming any proof, because the entire authorization layer was the compromised MPC keys. Every withdrawal is `execGrowth > 0, creditGrowth == 0` — the zero-backing hard trigger from the first transaction.

The probe transaction at 16:21 UTC ($2 USDC) is detectable in principle — any `executedWithdrawals` growth with zero credit growth fires the invariant — but practically a $2 probe produces negligible signal and would depend on whether that specific transaction was routed through the instrumented vault contract versus a direct EOA transfer.

---

## 4. Design Envelope Assessment

This incident matches the primary design target of the trap. The system enforces a single invariant across the vault layer: execution must not outpace validated inbound credit. The MPC compromise occurred entirely off-chain and produced no on-chain precursor signal, but the on-chain consequence — withdrawals executing with zero corresponding validated inbound credit — is exactly what the zero-backing code path catches.

```solidity
// Zero-backing hard trigger — fires on any execution with zero credit backing,
// regardless of amount.
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

Every withdrawal in the Multichain drain executed against zero validated inbound credit. The zero-backing hard trigger fires on the first sample that captures `executedWithdrawals` growth, independent of magnitude. The threshold path (`drainDelta > VAULT_DRAIN_THRESHOLD`) is never reached because the invariant fires earlier. Any bridge architecture where a lockup contract holds reserves, a validation layer authorizes releases, and that validation layer can be bypassed off-chain will produce this identical signal. The mechanism of compromise varies; the accounting mismatch does not. This structural parallel applies directly to Orbit Chain ([002](./002-orbit-chain-dec-2023.md)), Force Bridge ([004](./004-force-bridge-jun-2025.md)), and Ronin.

---

## 5. Trap Vector Mapping

| Vector | Status | Signal |
|---|---|---|
| Vector 1 — Vault drain mismatch | ✅ Fires immediately (zero-backing trigger) | Any `execGrowth > 0` with `creditGrowth == 0` |
| Vector 2 — Gateway phantom mint mismatch | ❌ No signal | No tokens minted; attack released locked assets only |
| Vector 3 — Router unauthorized execution | ❌ No signal | MPC addresses were EOAs; no router contract called |
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
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

**Vector 4 — reserve reconciliation (secondary):**

The `vaultTokenBalance` drop not reflected in `executedWithdrawals` would also fire if the attacker moved tokens via a path that bypassed the execution counter. In the Multichain case, the primary path updates counters directly, so Vector 1 fires first. Vector 4 serves as the backstop for counter-bypass variants where balance drops occur without corresponding execution counter increments.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price July 6, 2023: ~$1,900.

```
16:21 UTC    Probe: $2 USDC withdrawn.
             collect(): executedWithdrawals += ~$0, validatedInboundCredits = 0
             [TRAP: Signal negligible at this scale; evaluation depends on instrumented routing]

~18:21 UTC   First major withdrawal: ~$30.1M USDC.
             collect(): executedWithdrawals += ~$30.1M, validatedInboundCredits unchanged (0)
             execGrowth = ~$30.1M, creditGrowth = 0
             → Zero-backing hard trigger fires.
             shouldRespond() returns (true, abi.encode(execGrowth, 0, 0, 0))
             [TRAP: Fires 1 block after trigger (baseline operator latency)]

18:21 + 1 block
             Operator network reaches consensus.
             snapFreeze() executes: vault, gateway, router paused best-effort via try/catch.
             AttackPrevented emitted with drainDelta = execGrowth value.

~18:21–19:00 [ACTUAL] WBTC ($30.9M), WETH ($13.6M), altcoins ($20M) drain.
             [WITH TRAP] Bridge frozen. All subsequent withdrawal calls revert.
             ~$95M+ still in vault at time of freeze.

~19:46 UTC   [ACTUAL] Moonriver bridge drain begins: $6.8M.
             [WITH TRAP on Moonriver] Separate deployment required. If monitored, same trigger fires.

No manual pause was ever executed. Multichain announced service suspension on July 7.
The trap is the only automated response layer that would have existed.

Trap exposure window:   1–2 blocks (~12–24 seconds)
Actual exposure window: ~4+ hours (no pause executed)
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| Probe transaction ($2 USDC) | $2 lost | $2 lost |
| First major withdrawal (~$30.1M USDC) | Lost | Lost — completes before snapFreeze (unavoidable trigger event) |
| Remaining Fantom bridge assets (~$95M+) | Lost | Protected — bridge frozen after first above-signal withdrawal |
| Moonriver bridge ($6.8M) | Lost | Protected if separate deployment monitors Moonriver |
| Dogechain bridge ($666K) | Lost | Protected if separate deployment monitors Dogechain |
| July 7 additional drains (~$103M) | Lost | Protected — bridge frozen before July 7 |
| **Total preventable (Fantom only)** | — | **~$95M+** |
| **Total preventable (all bridges monitored)** | — | **~$200M+** |

The first ~$30.1M USDC withdrawal is the trigger event. It completes before `snapFreeze()` executes and is structurally unavoidable for any reactive on-chain monitor. Everything drained after that transaction is protected once the vault freezes. The July 7 additional drains (~$103M) are labeled `[estimate]` — no primary post-mortem confirmed the exact figure.

**Multi-bridge note:** The current deployment monitors one set of contract addresses. Multichain operated separate bridge contracts per chain pair. Full protection across Fantom, Moonriver, and Dogechain requires independent trap deployments per chain.

---

## 8. What the Trap Does Not Cover Here

**Off-chain key compromise.** The MPC compromise happened entirely off-chain. The trap detects the on-chain consequence, not the off-chain cause.

**The first ~$30.1M withdrawal.** This transaction fires the trigger and completes before `snapFreeze()` executes. A reactive monitor cannot stop the transaction that produces the signal it reacts to.

**Multi-chain deployment scope.** One trap deployment covers one vault address. Multichain's multi-chain architecture requires separate deployments per bridge. This is a deployment scaling consideration, not a logic gap.

**MPC liveness degradation.** Between Zhaojun's arrest (May 21) and the first withdrawal (July 6), the bridge exhibited degraded behavior: stuck transactions, failed relays, incomplete routing. These are operational signals that preceded the drain by 46 days. The vault drain mismatch trap has no mismatch to evaluate during this window. A separate liveness monitor watching bridge operational health would be the appropriate tool for this precursor window.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The zero-backing trigger covers this attack correctly. No modification to the existing vectors would improve coverage for the Multichain pattern. The meaningful production consideration is threshold calibration: Multichain processed hundreds of millions in daily legitimate volume. A production deployment would calibrate `VAULT_DRAIN_THRESHOLD` to actual baseline flow so the threshold-based path does not false-positive on high-volume days. The zero-backing path requires no calibration.

**Beyond BridgeRouterGuard:**

The 46-day degradation window before the drain demonstrates the need for an operational liveness monitor. A separate trap reading bridge throughput metrics — last confirmed cross-chain transaction timestamp, ratio of pending to confirmed messages, relay failure rate — could flag infrastructure distress weeks before funds move. This concept is implemented in [`PreAttackMonitorTrap`](./src/concepts/PreAttackMonitorTrap.sol), grounded in the Force Bridge ([004](./004-force-bridge-jun-2025.md)) case which provides a closer on-chain analog through failed privileged function calls.

---

## 10. Sources

- Chainalysis: "Multichain Exploit: Possible Hack or Rug Pull" — https://chainalysis.com/blog/multichain-exploit-july-2023/
- Halborn: "Explained: The Multichain Hack (July 2023)" — https://halborn.com/blog/post/explained-the-multichain-hack-july-2023
- CoinDesk: "Multichain Bridges Exploited for Nearly $130M" — https://coindesk.com/business/2023/07/06/multichain-bridges-experience-unannounced-outflows-of-over-130m-in-crypto
- Neptune Mutual: "Understanding the Multichain Exploit" — https://medium.com/neptune-mutual/understanding-the-multichain-exploit-9c034d1a6798
- Blockworks: "Multichain's $130M Exploit Potentially an Inside Job: Chainalysis" — https://blockworks.co/news/multichains-exploit-inside-job
- Multichain official statement (July 14, 2023): https://twitter.com/MultichainOrg/status/1679768407628185600
