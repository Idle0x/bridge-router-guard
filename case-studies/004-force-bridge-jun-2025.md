# Force Bridge — June 2025

**Loss:** ~$3.7M confirmed (~$3.1M on Ethereum, ~$600K on BNB Chain)
**Date:** June 1–2, 2025; failed attempts beginning ~01:36 UTC June 1; successful drain at 07:36 UTC June 2
**Vectors triggered:** 1 (Vault Drain Velocity)
**Trap verdict:** `CAUGHT (pre-drain)` — and uniquely, the trap would have fired during the 6-hour failed-attempt window before any funds moved; this is the clearest case in this set for the value of automated real-time monitoring

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

Force Bridge is a cross-chain bridge connecting the Nervos Network (CKB) to
Ethereum and BNB Chain, operated by Magickbase. It uses a multi-signature wallet
protecting locked asset reserves on both chains. The day before the attack,
Nervos announced it would sunset Force Bridge by November 2025, giving users a
withdrawal window.

On June 1–2, 2025, an attacker with access to privileged deployer keys made
multiple failed attempts to drain Force Bridge over approximately six hours before
successfully executing the exploit. The first successful drain began at 07:36 UTC
on June 2 on BNB Chain, followed by Ethereum. Total losses: ~$3.7M across both
chains. Assets drained: 257,800 USDT, 539 ETH (~$1.35M), 898,300 USDC, 60,400
DAI, and 0.79 WBTC (~$83K). All assets were converted to ETH and routed through
Tornado Cash and FixedFloat.

Magickbase detected abnormal activity at 03:12 UTC and paused services as a
precaution — during the failed-attempt window, before any successful drain. The
attacker still succeeded approximately four hours later, suggesting the pause
was incomplete or lifted.

Attribution: Unconfirmed. The sunset announcement timing — attack occurring one
day after the wind-down announcement — raises the possibility of an insider with
advance knowledge. Halborn noted this directly without concluding either way.

---

## 2. Technical Root Cause

**The vulnerability:** Access control failure via compromised deployer key. The
attacker gained access to privileged accounts controlling protected functions
within Force Bridge's smart contracts — allowing direct calls to `unlock()` and
`release()` without providing valid cross-chain proof of corresponding locked
assets.

**No smart contract code vulnerability.** The bridge contracts functioned as
designed. The failure was entirely in key management. Code audits would not have
caught this.

**Attack sequence (confirmed on-chain):**

1. **~01:36 UTC, June 1:** First failed attempt to drain Force Bridge. Extractor Web3
   confirmed a failed exploit attempt approximately six hours before the successful
   drain. Exact reason for failure not confirmed — likely incorrect parameters or
   incomplete key access.

2. **~03:12 UTC, June 2:** Magickbase detects abnormal activity. Pauses Force Bridge
   services. Team begins investigation.

3. **Multiple failed attempts** across ~6 hours before successful calibration.

4. **07:36 UTC, June 2:** First successful drain — 874 BNB (~$572K) on BNB Chain.

5. **~07:40–08:00 UTC:** Ethereum-side assets drained across multiple transactions:
   257,800 USDT, 539 ETH, 898,300 USDC, 60,400 DAI, 0.79 WBTC. Ethereum total: ~$3.1M.

6. **Post-drain:** All assets converted to ETH, routed through Tornado Cash and
   FixedFloat across multiple wallet hops.

**Key technical detail:** The drain was executed across multiple transactions on
two chains over approximately 30–60 minutes after the first successful transaction.
Not a single-transaction atomic drain — structurally identical to the Multichain
pattern ([001](./001-multichain-jul-2023.md)), only smaller in scale.

The **6-hour failed-attempt window** is the most significant detail in this case
study: failed privileged function calls, abnormal access patterns, and transaction
reverts over six hours are all observable on-chain — and represent a pre-drain
warning window that no monitoring system exploited.

---

## 3. On-Chain Signal Profile

**Phase 1 — Failed attempt window (~01:36 – ~07:36 UTC):**

Failed transactions calling privileged bridge functions are on-chain events.
They produce no withdrawal velocity — `cumulativeWithdrawals` does not change.
Vector 1 has nothing to fire on. However, a privileged function call monitor
(see section 9) would fire here. Magickbase's manual monitoring did detect
something at 03:12 UTC — but detection did not prevent the subsequent drain.

**Phase 2 — Successful drain (~07:36 UTC onward):**

| Time UTC (approx) | Event | delta |
|---|---|---|
| 07:36 | BNB Chain: 874 BNB drained | +~$572K |
| 07:40–08:00 | ETH: USDT, ETH, USDC, DAI, WBTC drained | +~$3.1M |

The drain unfolded across multiple transactions over ~30–60 minutes — the same
progressive, multi-block signal profile as Multichain and Orbit Chain. The
velocity threshold is breached within the first few Ethereum-side transactions.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes. Force Bridge is a lock-and-release bridge with asset reserves on Ethereum
and BNB Chain, controlled by an off-chain authorization mechanism. The attack
pattern — unauthorized withdrawal without validated inbound transactions — is the
Vector 1 pattern in the README. The key compromise is off-chain; the trap detects
the downstream consequence.

**B. Does the on-chain consequence produce the detectable signal?**

Yes, during Phase 2. The sequential multi-transaction drain across ~30–60 minutes
produces a velocity signal that exceeds the 1,000 ETH threshold within the first
few Ethereum-side transactions. Vector 1 fires within 12 seconds of the first
above-threshold withdrawal.

Phase 1 (failed attempts) produces no velocity signal. This is the trap's honest
limitation for this case: the most valuable intervention window — six hours of
observable pre-drain activity — is not captured by a velocity detector. A different
trap class catches it (see section 9).

**C. Which similar protocols or architectures produce the same signal?**

Any lock-and-release bridge where a reserve of locked assets exists on-chain
and the release mechanism is controlled by an off-chain key set that can be
compromised. This describes Multichain ([001](./001-multichain-jul-2023.md)),
Orbit Chain ([002](./002-orbit-chain-dec-2023.md)), and Force Bridge — all produce
the same observable downstream signal when that key set is in the wrong hands.

The sunsetting context is also architecturally relevant: a bridge in wind-down
mode has declining normal volume. Static thresholds calibrated for normal
high-volume operation become too high for a protocol processing minimal flow.
Dynamic thresholds would tighten automatically as TVL decreases — becoming more
sensitive exactly when the protocol is most concentrated and exposed.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ✅ Fires within first above-threshold Ethereum withdrawal | USDC batch (~$898K) and other assets accumulate above 1,000 ETH in window |
| Vector 2 — Phantom Mint | ❌ Does not fire | No tokens minted; assets withdrawn from existing locked reserves |
| Vector 3 — Forged Router Payload | ❌ Does not fire | Privileged function calls using valid (compromised) keys; no forged cross-chain message |

**Vector 1 detail:**

```solidity
// BridgeRouterGuardTrap.sol → _evaluateVectors()
vaultVelocity = newest.cumulativeWithdrawals > oldest.cumulativeWithdrawals
    ? newest.cumulativeWithdrawals - oldest.cumulativeWithdrawals : 0;
isCritical = vaultVelocity > VAULT_DRAIN_THRESHOLD; // 1,000 ETH
```

USDC batch (~$898K) and USDT batch (~$258K) on Ethereum together exceed 1,000 ETH
equivalent (~$2.5M at ~$2,500/ETH) once accumulated in the window. Individual
large transactions also exceed the 400 ETH burst threshold independently.

**Note on BNB Chain:** The 874 BNB first transaction (~$250K) is below the 1,000
ETH threshold in ETH-equivalent terms. A separate BNB Chain deployment with a
threshold calibrated to BNB pricing would catch it. The single-chain Ethereum
deployment does not.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price June 2025: ~$2,500.
1,000 ETH threshold ≈ $2.5M.

```
~01:36 UTC, June 1
                     FIRST FAILED ATTEMPT. Attacker calls privileged bridge
                     function — reverts. cumulativeWithdrawals: unchanged.
                     [TRAP (Vector 1): No trigger. No withdrawal occurred.]
                     [TRAP (hypothetical access monitor): Would fire here.
                      See section 9.]

~03:12 UTC, June 2   Magickbase detects abnormal activity. Pauses service.
                     [MANUAL DETECTION: 1h 36min after first failed attempt.
                      Pause did not prevent subsequent successful drain.]

Multiple failed      Additional failed transactions across 6-hour window.
attempts             [TRAP (Vector 1): No trigger. No assets moved.]

07:36 UTC, June 2    FIRST SUCCESSFUL DRAIN — BNB Chain: 874 BNB (~$250K).
                     [TRAP: Below 1,000 ETH threshold. No trigger.]

~07:40–08:00 UTC     ETHEREUM DRAIN — multiple transactions.
                     USDC: ~$898K | USDT: ~$258K | DAI: ~$60K |
                     ETH: ~$1.35M | WBTC: ~$83K
                     Window total accumulates rapidly. Within 2–3 transactions,
                     crosses 1,000 ETH equivalent.

~07:40:12            Block N+1. collect() reads state.
                     Vector 1 fires. shouldRespond() returns (true, payload).

~07:40:24            3-operator consensus. snapFreeze() executes:
                       VAULT.emergencyPause()   → paused ✓
                       GATEWAY.emergencyPause() → paused ✓
                       ROUTER.emergencyPause()  → paused ✓

~07:40–08:00         [ACTUAL] Remaining Ethereum drains continue unimpeded.
                     [WITH TRAP: Bridge frozen at ~07:40:24. Subsequent
                      transactions revert. Majority of Ethereum-side protected.]

Trap exposure window:   ~24 seconds (from first above-threshold Ethereum tx)
Actual exposure window: ~30–60 minutes (no automated pause during drain)
Compression factor:     ~75–150×

Pre-drain detection gap: 6 hours of observable failed attempts.
Vector 1 does not fire during this window.
The privileged function monitor in section 9 would.
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| BNB Chain drain — 874 BNB (~$250K) | Lost | Lost — below ETH threshold; requires separate BNB deployment |
| First Ethereum transaction(s) below threshold | Lost | Lost — sub-threshold |
| Remaining Ethereum assets (~$2.5M+) | Lost | Protected — bridge frozen ~24s after first above-threshold tx |
| **Total preventable (Ethereum only)** | — | **~$2.5M+** |
| **Total preventable (BNB + ETH, dual deployment)** | — | **~$2.7M+** |
| **Confirmed total loss** | ~$3.7M | ~$1M |

The 6-hour pre-drain window produces no dollar figure for the damage table
because no assets moved during it. However, had a correctly configured access
monitor been in place, `snapFreeze` could have fired during Phase 1 — before any
funds were lost at all. Section 9 addresses this.

---

## 8. What the Trap Does Not Cover Here

**The 6-hour failed-attempt window.** This is the most significant limitation
for this specific case. Six hours of observable on-chain failed privileged function
calls preceded the successful drain. Vector 1 monitors `cumulativeWithdrawals`
— which does not change during failed transactions. No velocity signal exists
before funds move. Compare with Orbit Chain ([002](./002-orbit-chain-dec-2023.md)),
which had a similarly long probe window but with micro-transactions rather than
failed restricted calls — both cases argue for a pre-attack monitor.

**Off-chain key compromise.** The deployer key was compromised entirely off-chain.
No on-chain state change indicates "a key has been stolen."

**BNB Chain single-deployment gap.** The first successful transaction (BNB Chain,
~$250K) is below the ETH-equivalent threshold and occurs on a different chain.
Full protection requires a separate BNB Chain deployment.

**Sunsetting context and threshold calibration.** After the sunset announcement,
normal bridge flow would decrease as users withdraw. Static thresholds calibrated
for normal operation may be too high for a protocol in wind-down. Dynamic
thresholds that adjust to reduced baseline flow would fire earlier and at lower
absolute amounts — exactly when the protocol is most exposed.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The sunsetting context is the clearest argument in this case for lifecycle-aware
threshold adaptation. A bridge in wind-down mode has declining normal volume.
The same 1,000 ETH threshold that avoids false positives during normal operation
should tighten as baseline flow decreases. Dynamic thresholds tracking rolling
7-day average outflow would automatically become more sensitive as TVL winds down.
This is the rolling-baseline upgrade documented in the README's What's Next section.

**Beyond BridgeRouterGuard — a privileged function call monitor:**

The 6-hour failed-attempt window is the definitive proof of need for a trap class
that does not exist in BridgeRouterGuard: an access control monitor. This concept
also surfaces in the Orbit Chain case ([002](./002-orbit-chain-dec-2023.md)),
where a 4-hour probe window preceded the drain. Force Bridge's case is the stronger
argument because the failed attempts were the exact same restricted function calls
that later succeeded — not just probes, but actual drain attempts that reverted.

A privileged function call trap could:
- `collect()` reads the count of failed calls to restricted functions (e.g.,
  `unlock()`, `release()`, `withdraw()` guarded by `onlyOwner` or multisig) in
  the observation window
- `shouldRespond()` fires if N failed privileged calls occur within M blocks from
  an address not in the authorized signer set
- Response: pause the bridge and alert operators

In the Force Bridge case, this trap would have fired approximately six hours before
the successful drain — with zero assets at risk. Every dollar of the $3.7M loss
is preventable if containment fires during the failed-attempt window.

The implementation constraint: the bridge contract must emit events on failed
restricted calls, or expose a failed-attempt counter that `collect()` can read.
Most contracts revert silently rather than incrementing a counter. A production
deployment would require either modifying the bridge contract to expose this state,
or running an event-log monitor that feeds into the Drosera network.

---

## 10. Sources

- Halborn: "Explained: The Force Bridge Hack (June 2025)" — https://halborn.com/blog/post/explained-the-force-bridge-hack-june-2025
- The Block: "Hackers Drain Over $3 Million from Nervos Network's Force Bridge" — https://theblock.co/post/356535/hackers-drain-over-3-million-in-crypto-from-nervos-networks-force-cross-chain-bridge
- Crypto.news: "Nervos Network Loses $3M in Force Bridge Exploit" — https://crypto.news/nervos-network-suffers-major-exploit-as-3-9m-in-crypto-is-stolen-from-force-bridge/
- Extractor Web3 (via X, June 2, 2025): "There was failed attempt to execute an attack 6 hours prior to successful one." — https://twitter.com/extractor_web3/status/1929444219757756584
- Cyvers Alerts (via X, June 2, 2025): Initial detection and asset breakdown — https://twitter.com/cyversalerts/status/1929428359856935185
- Magickbase official statement (via X, June 2, 2025): "We've detected abnormal activity on #ForceBridge and have paused the service"
