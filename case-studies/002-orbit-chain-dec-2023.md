# Orbit Chain — December 2023

**Loss:** ~$81.68M confirmed  
**Date:** December 31, 2023, ~16:14 UTC (probes) through ~21:30 UTC (final drain)  
**Root Cause:** 7-of-10 multisig private key compromise; social engineering / Lazarus Group tactics  
**Primary Vector:** Vector 1 — Vault drain mismatch (`executedWithdrawals - validatedInboundCredits`)  
**Trap verdict:** `CAUGHT (pre-drain)`

Five parallel asset streams drained over ~90 minutes after a structured 4-hour probe window. Like Multichain, every withdrawal executed against zero validated inbound credit. The zero-backing hard trigger fires on the first bulk drain — with four remaining asset streams still in the vault.

---

## 1. Incident Summary

Orbit Chain is a South Korean cross-chain bridge protocol enabling asset transfers between Ethereum and Klaytn, alongside other EVM-compatible networks. Eight of the top Klaytn assets by market cap were wrapped tokens bridged from Ethereum through Orbit Bridge. At the time of the attack, the Ethereum vault held approximately $115M.

On December 31, 2023, attackers executed a coordinated multi-asset drain of Orbit Bridge's Ethereum vault across five separate transaction streams — each targeting a different asset (ETH, USDT, USDC, DAI, WBTC) — preceded by small probe transactions approximately 60–90 minutes earlier. Total loss: ~$81.68M. Orbit Chain's balance dropped from ~$115M to ~$29M. No automated pause was executed during the attack. The protocol confirmed the hack publicly at 20:52:47 UTC — after all five drains had completed.

Attribution: Lazarus Group / DPRK-affiliated actors, assessed by Taylor Monahan (MetaMask), @officer_cia, and SlowMist based on attack patterns consistent with prior North Korean operations. No official confirmation.

---

## 2. Technical Root Cause

**The vulnerability:** Compromise of 7 of 10 multisig private keys controlling Orbit Bridge's Ethereum vault. The multisig required a 7-of-10 threshold to authorize withdrawals — meaning whoever controlled 7 or more signer keys had full unilateral authority over the vault.

**Root cause:** The attacker created valid multisig signatures by compromising 7 private keys, likely via social engineering consistent with Lazarus Group tactics. No smart contract vulnerability — the contracts functioned exactly as designed.

**Attack sequence (on-chain confirmed):**

1. **~16:14 UTC** — ETH probe: 0.004 ETH drained. Key confirmation test.
2. **~16:30 UTC** — USDT probe: 9.71 USDT.
3. **~17:45 UTC** — ETH second probe: 0.000137 ETH.
4. **~17:51 UTC** — USDT second probe: 9.71 USDT.
5. **~18:04 UTC** — USDC probe: 3.92 USDC.
6. **~18:22 UTC** — DAI probe: 1.322 DAI.
7. **~18:40 UTC** — WBTC probe: 0.012 WBTC.
8. **~20:00–21:30 UTC** — Five parallel bulk drains: ETH (~9,500 ETH / ~$21.5M), USDT (~$30M), USDC (~$10M), DAI (~$10M), WBTC (~230.879 WBTC / ~$9.8M).
9. **20:52:47 UTC** — Orbit Chain posts official confirmation on X. All drains already complete.

Like Multichain, the Orbit Bridge vault was controlled by an EOA multisig. Withdrawals were authorized by collecting 7 valid ECDSA signatures from compromised key holders. Asset movements were direct transfers — no smart contract router involved.

---

## 3. On-Chain Signal Profile

This exploit exhibits a structured observable pre-attack window: 4 hours of probe transactions confirming key access before any bulk drain. The probes fall below practical detection precision. The trap's detection window opens at the bulk drain phase.

**Probe transactions — below zero-backing trigger precision:**

| Time UTC | Asset | Amount | executedWithdrawals growth |
|---|---|---|---|
| ~16:14 | ETH | 0.004 ETH | ~$8 |
| ~16:30 | USDT | 9.71 USDT | ~$10 |
| ~17:45–18:40 | Various | Sub-cent amounts | Negligible |

**Bulk drains — zero-backing trigger fires immediately:**

| Time UTC | Asset | Amount | executedWithdrawals growth | validatedInboundCredits |
|---|---|---|---|---|
| ~20:00 | ETH | ~9,500 ETH | +~$21.5M | 0 — unchanged |
| ~20:00–20:15 | USDT | ~$30M | +~$51.5M cumulative | 0 — unchanged |
| ~20:15–20:30 | USDC | ~$10M | +~$61.5M cumulative | 0 — unchanged |
| ~20:30–21:00 | DAI | ~$10M | +~$71.5M cumulative | 0 — unchanged |
| ~21:00–21:30 | WBTC | ~$9.8M | +~$81.3M cumulative | 0 — unchanged |

`validatedInboundCredits` never moves at any point. There is no oracle confirmation, no validator consuming any proof — the entire authorization was the compromised multisig. The ETH bulk drain at ~20:00 UTC is the first `execGrowth > 0, creditGrowth == 0` event at meaningful scale. The zero-backing hard trigger fires here.

---

## 4. Design Envelope Assessment

This incident matches the primary design target of the trap. Orbit Chain operates as a lock-and-release bridge with an Ethereum vault holding locked reserves. The attack pattern — unauthorized vault outflows with zero corresponding validated inbound credit — is the exact failure mode Vector 1 was built to detect. The multisig key compromise occurred off-chain; the trap detects the on-chain accounting consequence.

```solidity
// Zero-backing hard trigger — fires on any execution with zero credit backing,
// regardless of amount.
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

The ETH bulk drain at ~20:00 UTC grows `executedWithdrawals` against `validatedInboundCredits = 0`. The zero-backing hard trigger fires immediately on the first sample capturing this growth. The remaining four bulk streams — USDT ($30M), USDC ($10M), DAI ($10M), WBTC ($9.8M), totaling ~$60.2M — remain in the vault at the moment of trigger. Any multisig-controlled bridge vault where key compromise enables direct asset withdrawal without smart contract validation produces this identical signal. The threshold for compromise varies across protocols (Ronin 5-of-9, Harmony 2-of-5, Orbit 7-of-10), but the on-chain accounting mismatch is structurally identical to Multichain ([001](./001-multichain-jul-2023.md)).

---

## 5. Trap Vector Mapping

| Vector | Status | Signal |
|---|---|---|
| Vector 1 — Vault drain mismatch | ✅ Fires on first bulk drain | ETH bulk drain: `execGrowth > 0`, `creditGrowth == 0` → zero-backing trigger |
| Vector 2 — Gateway phantom mint mismatch | ❌ No signal | No tokens minted; attack withdrew from locked reserve only |
| Vector 3 — Router unauthorized execution | ❌ No signal | Multisig-authorized direct transfers; no router contract called |
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

The probe transactions at sub-cent amounts are also `execGrowth > 0, creditGrowth == 0` in principle, but they fall below the precision at which ERC20 accounting registers meaningful movement. The first meaningful trigger is the ETH bulk drain. Vector 4 serves as the backstop for counter-bypass variants where balance drops occur without corresponding execution counter increments.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price December 31, 2023: ~$2,250.

```
~16:14 UTC   ETH probe: 0.004 ETH. [TRAP: Negligible execGrowth. No practical trigger.]
~16:30–18:40 UTC  Remaining probes. [TRAP: No meaningful signal.]

~20:00:00    FIRST BULK DRAIN — ETH: ~9,500 ETH (~$21.5M) leaves vault.
             collect():
               executedWithdrawals += ~$21.5M
               validatedInboundCredits unchanged (0)
             execGrowth > 0, creditGrowth == 0 → zero-backing trigger.
             shouldRespond() returns (true, abi.encode(execGrowth, 0, 0, 0))
             [TRAP: Fires 1 block after trigger (baseline operator latency)]

~20:00 + 1 block
             Operator network reaches consensus.
             snapFreeze() executes:
               vault.emergencyPause()   → paused ✓
               gateway.emergencyPause() → paused ✓
               router.emergencyPause()  → paused ✓
             AttackPrevented emitted. drainDelta = execGrowth value.

~20:00–21:30 [ACTUAL] USDT ($30M), USDC ($10M), DAI ($10M), WBTC ($9.8M) drain.
             [WITH TRAP] Vault frozen. All four streams revert.
             ~$60.2M protected across the subsequent 90 minutes.

20:52:47     [ACTUAL] Orbit Chain posts confirmation on X.
             [WITH TRAP] Bridge frozen ~52 minutes earlier.

Monitoring cadence or calendar date does not affect operator evaluation.

Trap exposure window:   1–2 blocks (~12–24 seconds)
Actual exposure window: ~90 minutes for bulk drains (no pause executed)
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| Probe transactions (all assets) | ~$0 | ~$0 |
| First bulk drain — ETH (~9,500 ETH) | ~$21.5M lost | ~$21.5M lost — completes before snapFreeze (unavoidable trigger event) |
| USDT bulk drain (~$30M) | $30M lost | $0 — vault frozen |
| USDC bulk drain (~$10M) | $10M lost | $0 — vault frozen |
| DAI bulk drain (~$10M) | $10M lost | $0 — vault frozen |
| WBTC bulk drain (~$9.8M) | $9.8M lost | $0 — vault frozen |
| Total loss | ~$81.68M | ~$21.5M |
| **Total preventable** | — | **~$60.2M** |

The ETH bulk drain fires the trigger but completes before `snapFreeze()` executes — the transaction that produced the signal is already confirmed on-chain. All four subsequent drains occur across the following 90 minutes in separate transactions. Every one of them reverts against the frozen vault.

Orbit Chain had zero automated pause capability. The trap is the only automated response layer that would have existed.

---

## 8. What the Trap Does Not Cover Here

**Off-chain key compromise.** 7-of-10 signer keys were compromised before any on-chain event. Nothing is detectable until funds move.

**The first bulk drain (~$21.5M ETH).** This transaction fires the trigger and completes before `snapFreeze()` executes. A reactive monitor cannot stop the transaction that produces the signal it reacts to.

**The 4-hour probe window.** The probe transactions are observable on-chain but produce no meaningful signal above the zero-backing trigger's practical precision at sub-cent amounts. A threshold low enough to fire on 0.004 ETH probes would produce continuous false positives on any bridge processing normal micro-transactions.

**Multi-asset normalization.** The vault tracks a single ETH-equivalent counter. For this specific attack the ETH bulk drain triggers regardless. For a stablecoin-only attack below the threshold, oracle-backed normalization would be required.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

Vector 1 correctly covers this attack. The production consideration is identical to Multichain: threshold calibration against actual baseline flow for the threshold path. The zero-backing path requires no calibration.

**Beyond BridgeRouterGuard:**

The 4-hour structured probe window — multiple small withdrawals across five asset types testing key access — is a distinguishable signal from normal bridge activity. Combined with Force Bridge's ([004](./004-force-bridge-jun-2025.md)) 6-hour failed-attempt window, these two cases demonstrate the need for a pre-attack window monitor that fires before any bulk drain. The concept is implemented and tested as [`PreAttackMonitorTrap`](./src/concepts/PreAttackMonitorTrap.sol). See [010 — Architecture and Extensions](./010-architecture-and-extensions.md#trap-2--pre-attack-window-monitor) for the precise design and validation tests.

---

## 10. Sources

- Neptune Mutual: "Analysis of the Orbit Chain Exploit" — https://neptunemutual.com/blog/analysis-of-the-orbit-chain-exploit/
- Halborn: "Explained: The Orbit Bridge Hack (December 2023)" — https://halborn.com/blog/post/explained-the-orbit-bridge-hack-december-2023
- Blockworks: "$80M Lost in First Hack of 2024" — https://blockworks.co/news/80-million-lost-orbit-bridge
- Rekt News: "Orbit Bridge — Rekt" — https://rekt.news/orbit-bridge-rekt
- Orbit Chain official confirmation (Jan 1, 2024): https://twitter.com/Orbit_Chain/status/1741534532840141187
