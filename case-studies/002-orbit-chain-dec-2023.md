# Orbit Chain — December 2023

**Loss:** ~$81.68M confirmed
**Date:** December 31, 2023, ~18:14 UTC (probes) through ~21:30 UTC (final drain)
**Vectors triggered:** 1 (Vault Drain Velocity)
**Trap verdict:** `CAUGHT (pre-drain)` — parallel multi-asset drain across five transaction streams over ~3 hours; trap fires on the first bulk withdrawal, protecting the majority of funds still in the bridge

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

Orbit Chain is a South Korean cross-chain bridge protocol enabling asset
transfers between Ethereum and Klaytn, alongside other EVM-compatible networks.
Eight of the top assets on the Klaytn network by market cap were wrapped tokens
bridged from Ethereum through Orbit Bridge. At the time of the attack, the
Ethereum vault held approximately $115M.

On December 31, 2023, from approximately 18:14 UTC through ~21:30 UTC,
attackers executed a coordinated multi-asset drain of Orbit Bridge's Ethereum
vault. Five separate transaction streams — each targeting a different asset
(ETH, USDT, USDC, DAI, WBTC) — ran in parallel with small probe transactions
preceding each major drain by approximately 60–90 minutes. Total loss:
~$81.68M. Orbit Chain's balance dropped from ~$115M to ~$29M. No automated
pause was executed. The protocol confirmed the hack publicly at 20:52:47 UTC —
after all five drains had completed.

Attribution: Lazarus Group / DPRK-affiliated actors, assessed by Taylor Monahan
(MetaMask), @officer_cia, and SlowMist based on attack patterns consistent
with prior North Korean operations. No official confirmation.

---

## 2. Technical Root Cause

**The vulnerability:** Compromise of 7 of 10 multisig private keys controlling
Orbit Bridge's Ethereum vault. The multisig required a 7-of-10 threshold to
authorize withdrawals — meaning whoever controlled 7 or more signer keys had
full unilateral authority.

**Root cause:** Misuse of valid signatures for unauthorized withdrawal
transactions. The attacker created valid multisig signatures by compromising
7 private keys, likely via social engineering consistent with Lazarus Group
tactics. No smart contract vulnerability confirmed by CertK audits.

**Attack sequence (on-chain confirmed):**

1. **~16:14 UTC** — ETH probe: Exploiter 4 drains 0.004 ETH. Key confirmation test.
2. **~16:30 UTC** — USDT probe: Exploiter 5 drains 9.71 USDT.
3. **~17:45 UTC** — ETH second probe: 0.000137 ETH.
4. **~17:51 UTC** — USDT second probe: 9.71 USDT.
5. **~18:04 UTC** — USDC probe: Exploiter 1 drains 3.92 USDC.
6. **~18:22 UTC** — DAI probe: Exploiter 3 drains 1.322 DAI.
7. **~18:40 UTC** — WBTC probe: Exploiter 2 drains 0.012 WBTC.
8. **~20:00–21:30 UTC** — Five parallel bulk drains:
   - ETH: ~9,500 ETH (~$21.5M)
   - USDT: ~$30M
   - USDC: ~$10M
   - DAI: ~$10M
   - WBTC: ~230.879 WBTC (~$9.8M)
9. **20:52:47 UTC** — Orbit Chain posts official confirmation on X. All drains already complete.

**Key technical detail:** Like Multichain, the Orbit Bridge Ethereum vault was
controlled by an EOA multisig. Withdrawals were authorized by collecting 7 valid
ECDSA signatures from compromised key holders. Asset movements were direct
transfers — no smart contract router involved. Vector 3 and Vector 2 do not
apply. Vector 1 is the sole detection path.

---

## 3. On-Chain Signal Profile

This exploit has the most structured probe-then-drain pattern in this case study
set. The attacker spent ~4 hours confirming key access across five asset channels
before executing bulk withdrawals — creating a 4-hour observable window before
any material funds moved.

**Probe transactions (all below threshold):**

| Time UTC | Asset | Amount |
|---|---|---|
| ~16:14 | ETH | 0.004 ETH |
| ~16:30 | USDT | 9.71 USDT |
| ~17:45 | ETH | 0.000137 ETH |
| ~17:51 | USDT | 9.71 USDT |
| ~18:04 | USDC | 3.92 USDC |
| ~18:22 | DAI | 1.322 DAI |
| ~18:40 | WBTC | 0.012 WBTC |

**Bulk drains (threshold-triggering):**

| Time UTC (approx) | Asset | Amount | ETH equivalent (~$2,250/ETH) |
|---|---|---|---|
| ~20:00 | ETH | 9,500 ETH | 9,500 ETH |
| ~20:00–20:15 | USDT | ~$30M | ~13,333 ETH |
| ~20:15–20:30 | USDC | ~$10M | ~4,444 ETH |
| ~20:30–21:00 | DAI | ~$10M | ~4,444 ETH |
| ~21:00–21:30 | WBTC | 230.879 WBTC | ~4,356 ETH |

The ETH drain (~9,500 ETH) alone exceeds the 1,000 ETH window threshold by 9.5×
before any other asset is touched. The signal is unambiguous on the first bulk
withdrawal.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes, directly. Orbit Chain is a lock-and-release bridge with an ETH vault
holding locked reserves. The attack pattern — unauthorized vault outflows without
corresponding validated inbound deposits — is the exact model the README lists
as the Orbit Chain reference for Vector 1. The multisig key compromise is
off-chain; the trap detects the on-chain consequence.

**B. Does the on-chain consequence produce the detectable signal?**

Yes, clearly. The first bulk drain (~9,500 ETH at ~20:00 UTC) exceeds the
1,000 ETH window threshold by 9.5×. The trap fires within one block. The
remaining four asset drains — USDT ($30M), USDC ($10M), DAI ($10M), WBTC
($9.8M), totaling ~$60M — are still in the vault.

**C. Which similar protocols or architectures produce the same signal?**

Any multisig-controlled bridge vault where key compromise enables direct asset
withdrawal without smart contract validation. The Ronin bridge used 5-of-9;
Harmony used 2-of-5; Orbit used 7-of-10. The threshold for compromise differs
but the on-chain signal is identical. The [Multichain case (001)](./001-multichain-jul-2023.md)
is the closest parallel — MPC vs. multisig, but same detectable consequence.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ✅ Fires on first bulk drain | ~9,500 ETH at ~20:00 UTC; exceeds 1,000 ETH threshold by 9.5× |
| Vector 2 — Phantom Mint | ❌ Does not fire | No tokens minted; attack withdrew from locked reserve only |
| Vector 3 — Forged Router Payload | ❌ Does not fire | Multisig-authorized direct transfers; no router contract involved |

**Vector 1 detail:**

```solidity
// BridgeRouterGuardTrap.sol → _evaluateVectors()
vaultVelocity = newest.cumulativeWithdrawals > oldest.cumulativeWithdrawals
    ? newest.cumulativeWithdrawals - oldest.cumulativeWithdrawals : 0;
isCritical = vaultVelocity > VAULT_DRAIN_THRESHOLD; // 1,000 ETH
```

First bulk drain: ~9,500 ETH. Threshold: 1,000 ETH. Exceeds by 9.5×. At December
2023 prices (~$2,250/ETH), the threshold is ~$2.25M and the first drain is
~$21.5M. The window check fires. Burst check fires independently — 9,500 ETH
in a single block far exceeds the 400 ETH burst threshold.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price December 31, 2023: ~$2,250.
1,000 ETH threshold ≈ $2.25M.

```
~16:14 UTC   ETH probe: 0.004 ETH. [TRAP: No trigger — sub-threshold by ~250,000×]
~16:30 UTC   USDT probe: 9.71 USDT. [TRAP: No trigger.]
... (all 7 probes) [TRAP: No trigger on any probe.]

~20:00:00    FIRST BULK DRAIN — ETH: ~9,500 ETH (~$21.5M) leaves vault.
             Delta: 9,500 ETH >> 1,000 ETH threshold.
             Burst: 9,500 ETH >> 400 ETH burst threshold.
             [Block N.]

~20:00:12    Block N+1. collect() reads state.
             Vector 1 fires. shouldRespond() returns (true, payload).

~20:00:24    3-operator consensus. snapFreeze() executes:
               VAULT.emergencyPause()   → paused ✓
               GATEWAY.emergencyPause() → paused ✓
               ROUTER.emergencyPause()  → paused ✓

~20:00–21:30 [ACTUAL] USDT ($30M), USDC ($10M), DAI ($10M), WBTC ($9.8M) drain.
             [WITH TRAP: Vault frozen at ~20:00:24. All four drains revert. ~$60M protected.]

20:52:47     [ACTUAL] Orbit Chain posts confirmation on X.
             [WITH TRAP: Bridge frozen ~52 minutes earlier.]

Trap exposure window:   ~24 seconds
Actual exposure window: ~90 minutes for bulk drains (no pause executed)
Compression factor:     ~225×
```

Orbit Chain's team had reduced monitoring on New Year's Eve. The trap operates
identically regardless of time of day or calendar date.

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| ETH probe transactions (all assets) | ~$0 | ~$0 |
| First bulk drain — ETH (~9,500 ETH) | ~$21.5M lost | ~$21.5M lost — completes before snapFreeze |
| USDT bulk drain (~$30M) | $30M lost | $0 — vault frozen |
| USDC bulk drain (~$10M) | $10M lost | $0 — vault frozen |
| DAI bulk drain (~$10M) | $10M lost | $0 — vault frozen |
| WBTC bulk drain (~$9.8M) | $9.8M lost | $0 — vault frozen |
| Total loss | ~$81.68M | ~$21.5M |
| **Total preventable** | — | **~$60.2M** |

The ETH drain triggers the trap but completes before `snapFreeze` executes —
same fundamental constraint as the initial drain in Kelp ([008](./008-kelp-dao-apr-2026.md)):
a single transaction that completes atomically cannot be stopped mid-flight.
All subsequent drains occur across 90 minutes in separate transactions; every
one of them reverts against a frozen vault.

Orbit Chain had zero automated pause capability. The trap would have been the
only response layer in the entire system.

---

## 8. What the Trap Does Not Cover Here

**Off-chain key compromise.** 7-of-10 signer keys were compromised before any
on-chain event. Nothing detectable until funds move.

**The first bulk drain (~$21.5M ETH).** 9,500 ETH completes atomically before
`snapFreeze` executes. Same constraint documented for Kelp and CrossCurve.

**Probe transactions as pre-attack signal.** The 4-hour probe window is
observable on-chain but produces no signal above any reasonable threshold.
A threshold low enough to fire on sub-cent probes would produce continuous
false positives on any bridge processing normal micro-transactions. Compare with
Force Bridge ([004](./004-force-bridge-jun-2025.md)), where the pre-attack window
was failed privileged function calls — a meaningfully different and more
actionable signal.

**Multi-asset normalization gap.** The trap monitors a single ETH-equivalent
counter. In a production deployment monitoring Orbit Bridge, a unified
cumulative counter tracking all five assets in ETH-equivalent terms is needed.
For this specific incident, the 9,500 ETH drain triggers the trap regardless
of stablecoin normalization.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The existing Vector 1 correctly catches this attack. The only meaningful
enhancement specific to Orbit Chain is oracle-backed asset normalization to
ensure stablecoin-only drains below the 1,000 ETH threshold at current prices
also trigger — relevant for smaller attacks targeting only stablecoins. This is
the production upgrade documented in the README's What's Next section.

**Beyond BridgeRouterGuard — a probe-pattern detector:**

The Orbit Chain attack exhibited a 4-hour structured probe window before any
bulk drain — multiple small withdrawal tests across different asset types within
a short window. Combined with Force Bridge's ([004](./004-force-bridge-jun-2025.md))
6-hour failed-attempt window, these two cases together make the strongest
argument for a pre-attack monitor: both show that attacker preparation produces
on-chain signals well before funds move.

A separate trap could monitor probe clustering:
- `collect()` reads the count of small-value withdrawal events (below, say, 0.1
  ETH equivalent) across the observation window
- `shouldRespond()` fires if N or more distinct small-value withdrawals occur
  across M different asset types within a single window
- Response: lower-severity alert or rate-limiting, not full freeze

The false positive risk is real: any bridge with active developer testing or
micro-transaction traffic needs careful calibration. The concept is viable;
empirical threshold tuning against real bridge traffic is required before
deployment.

---

## 10. Sources

- Neptune Mutual: "Analysis of the Orbit Chain Exploit" — https://neptunemutual.com/blog/analysis-of-the-orbit-chain-exploit/
- Halborn: "Explained: The Orbit Bridge Hack (December 2023)" — https://halborn.com/blog/post/explained-the-orbit-bridge-hack-december-2023
- Blockworks: "$80M Lost in First Hack of 2024" — https://blockworks.co/news/80-million-lost-orbit-bridge
- Rekt News: "Orbit Bridge — Rekt" — https://rekt.news/orbit-bridge-rekt
- Orbit Chain official confirmation (Jan 1, 2024): https://twitter.com/Orbit_Chain/status/1741534532840141187
- BleepingComputer: "Orbit Chain Loses $86 Million in the Last Fintech Hack of 2023" — https://bleepingcomputer.com/news/security/orbit-chain-loses-86-million-in-the-last-fintech-hack-of-2023/
