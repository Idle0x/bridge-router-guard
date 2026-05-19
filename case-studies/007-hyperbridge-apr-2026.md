# Hyperbridge — April 2026

**Loss:** ~$237K initial (108.2 ETH realized) · revised to ~$2.5M (four-chain incentive pool losses included)  
**Date:** April 13, 2026, ~03:55 UTC (Phase 1); Phase 2 ~04:55 UTC  
**Root Cause:** Missing bounds check in MMR proof verification library; forged cross-chain admin grant  
**Primary Vector:** Vector 2 — Gateway phantom mint mismatch (`cumulativeMinted - validatedMintAuthorizations`) — Phase 2  
**Secondary Vector:** Vector 1 — Vault drain mismatch — Phase 1 (zero-backing trigger)  
**Trap verdict:** `CAUGHT (post-drain)`

Hyperbridge exhibits the most complex signal profile in this set: a two-phase attack separated by ~1 hour, where Phase 1 triggers the zero-backing invariant and Phase 2 produces the largest single-sample phantom mint overshoot in the entire campaign — ~51× above threshold. The trap fires decisively on both phases. Phase 1 containment prevents Phase 2 entirely.

---

## 1. Incident Summary

Hyperbridge is a cross-chain interoperability protocol built by Polytope Labs, connecting Polkadot to EVM-compatible chains using its Interoperability State Machine Protocol (ISMP). Its Token Gateway manages asset transfers including DOT bridged from Polkadot to Ethereum, Base, BNB Chain, and Arbitrum.

On April 13, 2026, at approximately 03:55 UTC, an attacker exploited a missing bounds check in Hyperbridge's Merkle Mountain Range (MMR) proof verification library. The vulnerability allowed the attacker to submit a forged cross-chain message that bypassed state-proof validation, granting themselves administrative control over the bridged DOT token contract. The attack unfolded in two phases approximately one hour apart:

**Phase 1 (~03:55 UTC):** The attacker extracted approximately 245 ETH (~$561K) directly from the TokenGateway contract using the same validation bypass for a simpler asset drain.

**Phase 2 (~04:55 UTC):** The attacker submitted a forged `ChangeAssetAdmin` message through `HandlerV1.handlePostRequests`, gained admin control over the bridged DOT token contract, and minted approximately 1 billion bridged DOT tokens. These were immediately dumped into available DEX liquidity (primarily Uniswap V4), yielding approximately 108.2 ETH (~$237K) — a fraction of the tokens' nominal ~$1.17–1.19B face value, limited entirely by thin pool liquidity. Phantom DOT minting also affected ARGN, MANTA, and CERE tokens.

Hyperbridge paused bridging operations upon detection. The initial public estimate of $237K was revised upward to ~$2.5M on April 16 after reconciling two-phase losses and incentive pool impacts across four chains.

---

## 2. Technical Root Cause

**The vulnerability:** A missing bounds check (`leaf_index < leafCount`) in the `CalculateRoot` function of Polytope Labs' `MerkleMountainRange` Solidity library.

**How the bypass works:**

```solidity
// MerkleMountainRange.sol — CalculateRoot (vulnerable version)
function CalculateRoot(
    bytes32[] memory proof,
    MmrLeaf[] memory leaves,
    uint256 leafCount
) internal pure returns (bytes32) {
    // Special handle: single-leaf MMR
    if (leafCount == 1 && leaves.length == 1 && leaves[0].leaf_index == 0) {
        return leaves[0].hash;
    }
    // General path — missing: require(leaf_index < leafCount)
}
```
→ Polytope Labs `MerkleMountainRange` library (vulnerable deployment)

With `leaf_index = 1` and `leafCount = 1`, the special-case path does not trigger but the general path accepts an out-of-bounds index. `CalculateRoot` returns a value derived from an attacker-controlled proof element rather than a legitimately anchored root. The attacker recycled a legitimate recent state commitment (`overlay_root`) publicly visible on-chain and attached it to a forged `ChangeAssetAdmin` message — making the forged message appear valid to the broken verification function.

**Two-phase structure:**
- **Phase 1:** Direct asset extraction from TokenGateway (~245 ETH). Same validation bypass applied to authorize a direct withdrawal.
- **Phase 2 (~1 hour later):** 1B DOT phantom mint via forged `ChangeAssetAdmin`.

---

## 3. On-Chain Signal Profile

**Phase 1 — zero-backing trigger:**

| Field | Pre-Phase 1 | Post-Phase 1 | Delta |
|---|---|---|---|
| `executedWithdrawals` | baseline | +245 ETH | +245 ETH |
| `validatedInboundCredits` | baseline | unchanged | 0 |

245 ETH grows `executedWithdrawals` against zero `validatedInboundCredits`. The zero-backing invariant evaluates `execGrowth > 0 && creditGrowth == 0`. This condition is met. The threshold path (`drainDelta > VAULT_DRAIN_THRESHOLD`) is bypassed because the zero-backing check returns first. Phase 1 triggers `shouldRespond = true` on a fresh deployment regardless of the 245 ETH amount.

**Phase 2 — massive overshoot:**

| Field | Pre-Phase 2 | Post-Phase 2 | Delta |
|---|---|---|---|
| `cumulativeMinted` | baseline | +1B DOT (~$1.17B nominal) | +~511,000 ETH equivalent |
| `validatedMintAuthorizations` | baseline | unchanged | 0 |

1B DOT minted against zero authorization. `mintGrowth > 0`, `authGrowth == 0`. The zero-backing path fires for Vector 2. The threshold path also evaluates: `mintDelta = ~511,000 ETH`, `PHANTOM_MINT_THRESHOLD = 10,000 ETH`. Exceeds by ~51×.

If Phase 1 triggers containment on a fresh deployment, the bridge freezes before Phase 2 executes. If Phase 1 is missed due to bootstrap constraints or prior cooldown state, Phase 2 triggers decisively.

---

## 4. Design Envelope Assessment

This incident matches the design target of Vectors 1 and 2. The Token Gateway operates as a cross-chain bridge contract where cryptographic proof verification authorizes asset release and admin grants. The root cause is a verification library bug rather than a missing access control check or compromised key, but the on-chain consequence — unauthorized execution producing accounting mismatches — is identical to what the trap monitors. The mechanism of compromise differs; the observable mismatch does not.

```solidity
// [EXPLOIT MODEL: Hyperbridge Apr 2026 / IoTeX ioTube Feb 2026]
//
// changeAdmin() replicates the missing authorization check:
// attacker gains admin control without proof verification.
function changeAdmin(address newAdmin) external {
    // No authorization check — models the broken validation layer.
    admin = newAdmin;
}

// mintPhantom() replicates unbacked minting after privilege escalation.
// cumulativeMinted increments. validatedMintAuthorizations unchanged.
// The Vector 2 mismatch grows.
function mintPhantom(uint256 amount) external {
    require(!paused, "Gateway paused");
    cumulativeMinted += amount;
    emit PhantomMinted(amount);
}
```
→ [`src/mocks/core/MockTokenGateway.sol`](../src/mocks/core/MockTokenGateway.sol)

Phase 1 fires the zero-backing hard trigger. Phase 2 fires both the zero-backing path and the threshold path for Vector 2. Any bridge using the Polytope Labs `MerkleMountainRange` library or similar proof verification architectures that grant admin/minting rights in a single step produces this identical signal. The `ChangeAssetAdmin` pattern mirrors the IoTeX ([006](./006-iotex-iotube-feb-2026.md)) upgrade-then-takeover sequence: different root cause mechanism, same observable downstream consequence of permanent admin control in the wrong hands.

---

## 5. Trap Vector Mapping

| Vector | Status | Signal |
|---|---|---|
| Vector 1 — Vault drain mismatch | ✅ Fires (Phase 1) | 245 ETH withdrawal, zero credit → zero-backing trigger fires regardless of threshold |
| Vector 2 — Gateway phantom mint mismatch | ✅ Fires (Phase 2, ~51× above threshold) | 1B DOT ≈ 511,000 ETH equivalent; `PHANTOM_MINT_THRESHOLD` = 10,000 ETH; exceeds by ~51× |
| Vector 3 — Router unauthorized execution | ❌ No signal | Exploit used `handlePostRequests` — a different function class from `expressExecute`-style unauthorized call; `executedMessages` does not map to this path |
| Vector 4 — Reserve reconciliation | ✅ Fires (Phase 1, secondary) | `vaultTokenBalance` drops by 245 ETH without counter movement |

**Vector 1 — zero-backing hard trigger (Phase 1):**

```solidity
// Phase 1: 245 ETH withdrawn, validatedInboundCredits = 0
// execGrowth = 245 ETH > 0; creditGrowth = 0
// → zero-backing hard trigger fires. Amount is irrelevant.
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](../src/core/BridgeRouterGuardTrap.sol)

The threshold check is never reached for Phase 1. The zero-backing path evaluates first and returns unconditionally.

**Vector 2 — phantom mint overshoot (Phase 2):**

```solidity
// Phase 2: 1B DOT minted, validatedMintAuthorizations = 0
// mintGrowth = ~511,000 ETH equivalent > 0; authGrowth = 0
// → zero-backing path fires first. Threshold check (~51× above) also fires.
if (mintGrowth > 0 && authGrowth == 0) {
    return (true, abi.encode(uint256(0), mintGrowth, uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](../src/core/BridgeRouterGuardTrap.sol)

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price April 13, 2026: ~$2,290.

```
~03:55 UTC    PHASE 1 — TokenGateway direct drain (245 ETH).
              Forged message via MMR bounds-check bypass authorizes withdrawal.

              collect():
                executedWithdrawals += 245 ETH
                validatedInboundCredits = 0 (unchanged — no valid proof consumed)
              execGrowth = 245 ETH > 0; creditGrowth = 0
              → Zero-backing hard trigger fires.
              shouldRespond() returns (true, abi.encode(245e18, 0, 0, 0))
              [TRAP: Fires 1 block after trigger (baseline operator latency)]

~03:55 + 1 block
              Operator network reaches consensus.
              snapFreeze() executes: vault, gateway, router paused best-effort via try/catch.
              AttackPrevented emitted with drainDelta = 245e18.
              [Phase 2 never executes — bridge is frozen.]

~03:55–04:55  [WITHOUT TRAP] ~1-hour gap between Phase 1 and Phase 2.
              Attacker prepares Phase 2 transactions.

~04:55:00     [WITHOUT TRAP] PHASE 2 — ChangeAssetAdmin via forged handlePostRequests.
              1,000,000,000 bridged DOT minted.
              collect():
                cumulativeMinted += ~511,000 ETH equivalent
                validatedMintAuthorizations = 0 (unchanged)
              mintGrowth >> PHANTOM_MINT_THRESHOLD (~51× over)
              shouldRespond() returns (true, abi.encode(0, mintGrowth, 0, 0))
              [TRAP: Fires 1 block after trigger (baseline operator latency)]

~04:55 + 1 block [WITHOUT TRAP]
              Operator network reaches consensus.
              snapFreeze() executes: vault, gateway, router paused best-effort via try/catch.
              AttackPrevented emitted with mintDelta = ~511,000e18.
              Bridge frozen. Further minting reverts.

~04:55–05:XX  [ACTUAL] Attacker dumps 1B DOT into Uniswap V4.
              108.2 ETH (~$237K) extracted. ~99.98% of nominal value
              unextractable due to thin liquidity.

Trap exposure window (Phase 1, fresh deployment): 1–2 blocks
Trap exposure window (Phase 2, if Phase 1 missed): 1–2 blocks
Phase 1 actual exposure: Not contained (no trap deployed)
Phase 2 actual exposure: Until manual pause (minutes to ~1 hour)
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| Phase 1 — 245 ETH TokenGateway drain | ~$561K lost | ~$561K lost — completes before snapFreeze (unavoidable trigger event) |
| Phase 2 — 1B DOT mint + DEX dump | ~$237K realized + incentive pools | $0 — bridge frozen before Phase 2 executes |
| Incentive pool losses — multi-chain (~$1.7M) | ~$1.7M lost | $0 — gateway frozen before follow-on minting |
| **Phase 1 loss (unavoidable trigger event)** | ~$561K | ~$561K |
| **Total preventable** | — | **~$1.7M+ (Phase 2 + incentive pools)** |

The 1B DOT mint at ~$1.17B nominal produced only $237K in realized extraction due to thin DEX liquidity. The trap fires on the magnitude of the mint — `cumulativeMinted` growth of ~511,000 ETH equivalent — not on the realized liquidation value. This is correct behavior: the threat is the nominal minted supply, not the amount the attacker managed to extract before liquidity collapsed. A more liquid market would have produced a proportionally larger realized loss.

**Multi-chain deployment note:** Incentive pool losses on Base, BNB Chain, and Arbitrum (~$1.7M of the revised total) require independent trap deployments per chain.

---

## 8. What the Trap Does Not Cover Here

**Phase 1 trigger event.** The 245 ETH withdrawal completes before `snapFreeze()`. A reactive monitor cannot stop the transaction that produces its own trigger.

**Admin grant precedes mint.** The `ChangeAssetAdmin` message grants the attacker permanent admin control in the same block as the mint. Even with a one-block response, the admin grant is already in effect.

**Thin liquidity does not reduce the signal.** The trap fires on `cumulativeMinted` growth, which is independent of whether the attacker can liquidate the minted tokens. The trap fires on an event whose realized financial harm was far less than its nominal magnitude.

**Multi-chain deployment gap.** Incentive pool losses on Base, BNB Chain, and Arbitrum require independent deployments.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**
The zero-backing trigger correctly covers both phases. The threshold path is secondary to the zero-backing check and does not alter the outcome.

**Beyond BridgeRouterGuard:**
Both the IoTeX case ([006](./006-iotex-iotube-feb-2026.md)) and this case independently produce the same intermediate step before phantom minting: an admin change on a bridge token contract. A monitor reading `owner()` on each bridged token contract fires in the same block as the `ChangeAssetAdmin` execution — before the first phantom mint is submitted, with the attacker holding admin rights but no minted tokens yet.

This concept is implemented as [`OwnershipMonitorTrap`](../src/concepts/OwnershipMonitorTrap.sol) and tested in [`test/concepts/OwnershipMonitor.t.sol`](../test/concepts/OwnershipMonitor.t.sol). See [010 — Architecture and Extensions](./010-architecture-and-extensions.md#trap-2--ownership-state-monitor) for the full design and validation tests. The convergence of two independent exploit paths on the same intermediate on-chain state change reinforces the architectural case for this monitor.

---

## 10. Sources

- Hyperbridge official post-mortem: "Update on Recovery Efforts and Next Steps" — https://blog.hyperbridge.network/recovery-and-next-steps/
- Verichains: "How a Missing Bounds Check Led to $237K Exploit on Hyperbridge" — https://blog.verichains.io/p/how-a-missing-bounds-check-led-to
- Medium / Stepan Chekhovskoi: "DOT Hacked: The Hyperbridge Exploit" — https://medium.com/@SteMak/dot-hacked-the-hyperbridge-exploit-53e149b93961
- CryptoTimes: "Hyperbridge Raises Exploit Loss Estimate to $2.5M From $237K" — https://cryptotimes.io/2026/04/16/hyperbridge-raises-exploit-loss-estimate-to-2-5m-from-237k/
- Decrypt: "Polkadot-Ethereum Bridge Hack Losses Were 10x Worse Than Reported" — https://decrypt.co/364588/polkadot-ethereum-bridge-hack-losses-10x-worse-team-admits
- crypto.news: "Hyperbridge exploit mints 1 billion fake DOT on Ethereum, nets just $237K" — https://crypto.news/hyperbridge-exploit-mints-1-billion-fake-dot-on-ethereum-nets-just-237k/
- Tekedia: "Hyperbridge Faces ~$250,000 Hack After Making April Fool Post" — https://tekedia.com/hyperbridge-faces-250000-hack-after-making-april-fool-post-of-having-robust-security-systems/
- BeInCrypto: "Polkadot Based Hyperbridge Revises Exploit Losses to $2.5M" — https://beincrypto.com/hyperbridge-exploit-losses-revised-25m/
