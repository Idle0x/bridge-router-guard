# Multichain — July 2023

**Loss:** ~$126M confirmed (Fantom bridge: ~$102M, Moonriver: ~$6.8M, Dogechain: ~$666K; additional drains July 7: ~$103M reported by Beosin)
**Date:** July 6–7, 2023
**Vectors triggered:** 1 (Vault Drain Velocity)
**Trap verdict:** `CAUGHT (pre-drain)` — multi-transaction, multi-hour drain is exactly the signal profile this trap was built for; snapFreeze fires before the majority of funds leave

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

Multichain (formerly Anyswap) was a cross-chain bridge protocol routing assets
across Ethereum, Fantom, BNB Chain, Polygon, Avalanche, and 20+ other chains
via a Multi-Party Computation (MPC) system. At its peak it held over $7B TVL.

On July 6, 2023, assets locked in Multichain's MPC bridge addresses began
moving to unknown EOA addresses without user authorization. The drain was
progressive: a $2 USDC probe at 16:21 UTC, escalating to ~$102M drained from
the Fantom bridge over several hours, then cascading to the Moonriver and
Dogechain bridges. No smart contract vulnerabilities were identified — all
evidence pointed to compromise of the MPC private keys, consistent with the
May 2023 arrest of CEO Zhaojun and Chinese police confiscation of his servers
and hardware wallets. Multichain ceased operations permanently on July 7, 2023.

---

## 2. Technical Root Cause

**The vulnerability:** MPC private key compromise. Multichain's bridge
transactions were authorized by an MPC system where cryptographic key shards
were distributed across node operators. The MPC addresses holding locked assets
were EOAs — meaning whoever controlled the private keys could move funds without
any on-chain validation logic or smart contract interaction.

**The structural failure:** Despite being marketed as decentralized MPC, all
MPC node servers ran under a single cloud account controlled by CEO Zhaojun.
His May 21, 2023 arrest by Chinese police resulted in confiscation of all
devices and access credentials. From that point, no one with legitimate
authority could access or secure the bridge infrastructure.

**Attack sequence (confirmed on-chain):**

1. **May 21, 2023:** CEO Zhaojun arrested. MPC access keys confiscated.
2. **May 31 – July 5, 2023:** Degraded operations, stuck transactions.
3. **July 6, 16:21 UTC:** $2 USDC probe withdrawn from Fantom bridge.
4. **~18:21 UTC:** ~$30.1M USDC withdrawn from Fantom bridge.
5. **~18:21–18:30 UTC:** 1,023.8 WBTC (~$30.9M) withdrawn.
6. **~18:30–19:00 UTC:** 7,214 WETH (~$13.6M) and ~$20M in altcoins withdrawn. Total Fantom drain: ~$102M across ~40 minutes.
7. **~19:46 UTC:** Moonriver bridge drain: ~$6.8M.
8. **~20:16 UTC:** Dogechain bridge drain: ~$666K.
9. **July 7, 2023:** Additional ~$103M drained from further bridge addresses. Multichain announces services halted indefinitely.
10. **July 8, 2023:** Circle and Tether freeze $65M+ linked to attacker addresses.

**Key technical detail:** The Multichain MPC bridge addresses were EOAs, not
smart contracts. Funds moved via direct EOA-to-EOA transfers — no
`anySwapOut()` call, no bridge router invocation, no smart contract state
change. The observable signal is entirely in the withdrawal counter.

**Attribution:** Unresolved. Three competing theories: Chinese police or
state-affiliated actors using confiscated keys; Zhaojun's family acting to
"preserve assets" (sister confirmed transferring remaining funds July 9, later
arrested); external hackers exploiting the chaos window. No definitive
attribution confirmed in any post-mortem or legal proceeding.

---

## 3. On-Chain Signal Profile

The drain was not atomic. It was progressive across multiple transactions
spanning approximately 3–4 hours — the ideal signal profile for a
velocity-tracking trap.

| Time UTC | Event | Cumulative delta |
|---|---|---|
| 16:21 | $2 USDC probe | ~$0 (below noise) |
| ~18:21 | $30.1M USDC | ~$30M |
| ~18:21–18:30 | $30.9M WBTC | ~$61M |
| ~18:30–19:00 | $13.6M WETH + $20M altcoins | ~$95M |
| ~19:46 | $6.8M Moonriver drain | ~$102M |
| ~20:16 | $666K Dogechain drain | ~$103M |

The delta accumulates across blocks, becoming unambiguous well before the drain
completes. By the time ~$30M in USDC left, the velocity threshold was already
breached. Vector 1 is the only applicable detection path — no derivative tokens
were minted, no smart contract router was called.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes — this is the primary design target. Multichain is the first incident in
the README pattern table and the most explicit reference for Vector 1. The trap
was built specifically to catch unmatched vault outflow: withdrawals executing
without corresponding validated inbound deposit proofs. The MPC compromise is
off-chain, but the consequence — large volumes of locked assets leaving without
user-initiated bridge transactions — produces the exact velocity signal the
trap monitors.

**B. Does the on-chain consequence produce the detectable signal?**

Yes, clearly and early. The threshold (1,000 ETH equivalent in the 7-block
window, or 400 ETH per block) is breached within the first significant withdrawal
batch at ~18:21 UTC — well before the bulk of WBTC and WETH left the bridge.

**C. Which similar protocols or architectures produce the same signal?**

Any bridge holding a locked reserve and using an off-chain authorization
mechanism to release it produces this signal on compromise: MPC-based bridges
where key compromise enables direct EOA withdrawals; multisig-controlled bridges
where a sufficient quorum is compromised (see [Orbit Chain — December 2023](./002-orbit-chain-dec-2023.md));
trusted relayer or operator sets where key material is concentrated. The trap
does not care how the authorization was bypassed — it reads the consequence.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ✅ Fires within first withdrawal batch | ~$30.1M USDC at ~18:21 UTC exceeds 1,000 ETH threshold by ~15× |
| Vector 2 — Phantom Mint | ❌ Does not fire | No derivative tokens minted; attack released locked assets, did not mint |
| Vector 3 — Forged Router Payload | ❌ Does not fire | MPC addresses were EOAs; no router contract called, no `spoofedMessageExecuted` flag |

**Vector 1 detail:**

```solidity
// BridgeRouterGuardTrap.sol → _evaluateVectors()
vaultVelocity = newest.cumulativeWithdrawals > oldest.cumulativeWithdrawals
    ? newest.cumulativeWithdrawals - oldest.cumulativeWithdrawals : 0;
isCritical = vaultVelocity > VAULT_DRAIN_THRESHOLD; // 1,000 ETH
```

The ~$30M USDC withdrawal at ~18:21 UTC exceeds 1,000 ETH equivalent (~$2M at
July 2023 ETH prices) by approximately 15×. This is the first major withdrawal,
not the last. The trap fires here — with the remaining ~$95M+ still in the bridge.

The burst detection path fires independently:

```solidity
// _countBursts()
if (delta > BURST_THRESHOLD_VAULT) vaultBursts++; // 400 ETH per block
```

The initial USDC withdrawal (~$30M) in a single block exceeds the 400 ETH burst
threshold by ~75×.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price July 6, 2023: ~$1,900.
1,000 ETH threshold ≈ $1.9M.

```
16:21 UTC    Probe: $2 USDC withdrawn.
             cumulativeWithdrawals delta: ~$0 vs $1.9M threshold.
             [TRAP: No trigger.]

~18:21 UTC   First major withdrawal: ~$30.1M USDC leaves Fantom bridge.
             Delta >> 1,000 ETH threshold. Single-block burst >> 400 ETH.
             [Block N. First threshold-crossing event.]

~18:21:12    Block N+1. collect() reads state.
             Vector 1 window check fires. Burst check fires independently.
             shouldRespond() returns (true, payload).

~18:21:24    3-operator consensus. snapFreeze() executes:
               VAULT.emergencyPause()   → paused ✓
               GATEWAY.emergencyPause() → paused ✓
               ROUTER.emergencyPause()  → paused ✓

~18:21–19:00 [ACTUAL] WBTC ($30.9M), WETH ($13.6M), altcoins ($20M) drain.
             [WITH TRAP: Bridge frozen at ~18:21:24. ~$95M+ protected.]

No manual pause was ever executed. Multichain announced suspension on July 7.
The trap would have been the only automated defense layer in the system.

Trap exposure window:   ~24 seconds (Fantom bridge)
Actual exposure window: ~4+ hours (no pause executed)
Compression factor:     ~600×
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| Probe transaction ($2 USDC) | $2 lost | $2 lost |
| First major withdrawal (~$30.1M USDC) | Lost | Lost — completes before snapFreeze |
| Remaining Fantom bridge assets (~$95M+) | Lost | Protected — bridge frozen at ~18:21:24 |
| Moonriver bridge ($6.8M) | Lost | Protected if Moonriver trap deployed |
| Dogechain bridge ($666K) | Lost | Protected if Dogechain trap deployed |
| July 7 additional drains (~$103M) | Lost | Protected — bridge frozen night before |
| **Total preventable (Fantom only)** | — | **~$95M+** |
| **Total preventable (all bridges monitored)** | — | **~$200M+** |

The $30.1M USDC withdrawal triggers the trap. Everything drained after that
transaction — WBTC, WETH, altcoins, all subsequent bridges — is protected once
snapFreeze fires. The July 7 additional drain (~$103M, per Beosin) is labeled
`[estimate]` as no primary post-mortem confirmed the exact figure.

**Multi-bridge caveat:** The current deployment monitors a single set of contract
addresses. Full protection across Fantom, Moonriver, and Dogechain requires
three separate deployments, each monitoring the respective bridge reserve.

---

## 8. What the Trap Does Not Cover Here

**Off-chain centralization is the root cause.** The MPC key compromise happened
entirely off-chain. There is no on-chain signal that the key was compromised
before the first withdrawal. The trap detects the consequence, not the cause.

**The first ~$30M withdrawal is lost.** The probe at 16:21 UTC is $2 — below
threshold. The trap fires on the first significant withdrawal at ~18:21 UTC.
That $30.1M USDC transaction completes before snapFreeze executes (~24 seconds
later).

**Multi-bridge architecture requires multiple deployments.** Multichain ran
separate bridge contracts per chain pair. A single Fantom-bridge deployment
does not catch the Moonriver or Dogechain drains at different addresses.

**No manual pause backup existed.** Multichain had no functional emergency pause
capability — the only person with access was under arrest. The trap is the only
automated response layer that would have existed.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The three existing vectors are well-matched to the observable consequence. A
production deployment monitoring Multichain would need to calibrate the threshold
against actual baseline flow — Multichain's normal daily volume routinely
processed hundreds of millions in legitimate transactions. Static 1,000 ETH
thresholds are correct for this PoC but underscore the production need for
dynamic baseline-relative thresholds documented in the README's What's Next
section.

**Beyond BridgeRouterGuard — an MPC liveness monitor:**

The Multichain compromise had a 46-day observable precursor: from Zhaojun's
arrest (May 21) to the first withdrawal (July 6), the MPC node infrastructure
was degraded — stuck transactions, failed relays, reduced throughput. These
operational anomalies produced on-chain signals: increasing transaction failure
rates, growing pending queue depth, unusual gaps in confirmation times.

A separate trap could monitor MPC bridge liveness:
- `collect()` reads the timestamp of the last confirmed bridge transaction per
  route and the ratio of pending vs. confirmed transactions
- `shouldRespond()` fires if the confirmed-transaction gap exceeds a threshold
  (no confirmed cross-chain transaction for N blocks on a historically active route)
- Response: pause the bridge pending manual review

This would not stop a key compromise directly, but could have triggered a
precautionary pause during the 46-day degradation window — before any funds
moved. The Force Bridge case ([004](./004-force-bridge-jun-2025.md)) provides a
second example of a multi-hour pre-attack observable window that a different
trap class would have caught.

---

## 10. Sources

- Chainalysis: "Multichain Exploit: Possible Hack or Rug Pull" — https://chainalysis.com/blog/multichain-exploit-july-2023/
- Halborn: "Explained: The Multichain Hack (July 2023)" — https://halborn.com/blog/post/explained-the-multichain-hack-july-2023
- CoinDesk: "Multichain Bridges Exploited for Nearly $130M" — https://coindesk.com/business/2023/07/06/multichain-bridges-experience-unannounced-outflows-of-over-130m-in-crypto
- Neptune Mutual: "Understanding the Multichain Exploit" — https://medium.com/neptune-mutual/understanding-the-multichain-exploit-9c034d1a6798
- Blockworks: "Multichain's $130M Exploit Potentially an Inside Job: Chainalysis" — https://blockworks.co/news/multichains-exploit-inside-job
- Multichain official statement (July 14, 2023): https://twitter.com/MultichainOrg/status/1679768407628185600
