# Hyperbridge — April 2026

**Loss:** ~$237K initial (108.2 ETH realized) · revised to ~$2.5M (four-chain incentive pool losses included)
**Date:** April 13, 2026, ~03:55 UTC (Phase 1); Phase 2 ~04:55 UTC
**Vectors triggered:** 2 (Phantom Mint Velocity — Phase 2) + 1 (Vault Drain — Phase 1 below threshold; see section 5)
**Trap verdict:** `CAUGHT (post-drain)` — Phase 1 vault drain falls below threshold (documented gap); Phase 2 phantom mint exceeds threshold by ~51×; trap fires on block N+1 of Phase 2, containing multi-chain propagation

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

Hyperbridge is a cross-chain interoperability protocol built by Polytope Labs,
connecting Polkadot to EVM-compatible chains using its Interoperability State
Machine Protocol (ISMP). Its Token Gateway manages asset transfers including DOT
bridged from Polkadot to Ethereum, Base, BNB Chain, and Arbitrum.

On April 13, 2026, at approximately 03:55 UTC, an attacker exploited a missing
bounds check in Hyperbridge's Merkle Mountain Range (MMR) proof verification
library. The vulnerability allowed the attacker to submit a forged cross-chain
message that bypassed state-proof validation, granting themselves administrative
control over the bridged DOT token contract. The attack unfolded in two phases:

**Phase 1 (~03:55 UTC):** The attacker extracted approximately 245 ETH (~$561K)
directly from the TokenGateway contract using the same validation bypass for a
simpler asset drain.

**Phase 2 (~04:55 UTC):** The attacker submitted a forged `ChangeAssetAdmin`
message, gained admin control over the bridged DOT token contract, and minted
approximately 1 billion bridged DOT tokens. These were immediately dumped into
available DEX liquidity (primarily Uniswap V4), yielding approximately 108.2 ETH
(~$237K) — a fraction of the tokens' ~$1.17–1.19B nominal value, limited entirely
by thin pool liquidity. Phantom DOT minting also affected ARGN, MANTA, and CERE
tokens.

Hyperbridge paused bridging operations upon detection. The initial public estimate
of $237K was revised to ~$2.5M on April 16 after reconciling two-phase losses
and incentive pool impacts across four chains.

Twelve days prior, Hyperbridge had published an April Fools' post joking about a
catastrophic exploit, boasting the protocol was "un-hackable."

---

## 2. Technical Root Cause

**The vulnerability:** A missing bounds check (`leaf_index < leafCount`) in the
`CalculateRoot` function of Polytope Labs' `MerkleMountainRange` Solidity library
— a shared dependency used by Hyperbridge's proof verification stack.

**How the bypass works:**
An MMR proof allows the bridge to verify that a message was legitimately included
in Polkadot's state. The `CalculateRoot` function contains a special-case path
for single-leaf MMRs:

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
    // ... general verification path (missing: require leaf_index < leafCount)
}
```

The special case checks `leafCount == 1` and `leaf_index == 0`. If the attacker
passes `leaf_index = 1` with `leafCount = 1`, the special-case path does not
trigger — but the general path does not validate that `leaf_index < leafCount`.
An index of 1 in a tree with only 1 leaf (valid range: 0–0) is out of bounds,
but the check is absent. `CalculateRoot` returns a value derived from an
attacker-controlled proof element, not a legitimately anchored root.

**The exploit pattern via `HandlerV1.handlePostRequests`:**
1. Set `leafCount = 1`, `leaf_index = 1` (out of bounds, bypasses special case)
2. Set `proof[0]` to `overlay_root` — a legitimate recent state commitment publicly visible on-chain
3. Construct a `ChangeAssetAdmin` payload assigning admin rights to the attacker
4. Submit via `handlePostRequests` — forged message passes MMR verification because the computed "root" matches the real `overlay_root` through the manipulated path

BlockSec/Phalcon described this as an MMR proof replay: the attacker recycled a
legitimate state commitment and attached it to a forged message by exploiting the
bounds-check gap.

**Two-phase structure:**
- **Phase 1:** Direct asset extraction from TokenGateway (~245 ETH). Same validation bypass applied to authorize a direct withdrawal.
- **Phase 2 (~1 hour later):** The 1B DOT phantom mint via `ChangeAssetAdmin`.

---

## 3. On-Chain Signal Profile

Hyperbridge has the most complex signal profile in this set because of its
two-phase structure, its phantom-mint-to-realized-loss ratio (~$1.17B nominal vs.
$237K realized), and its multi-chain deployment.

**Phase 1 signal — ~03:55 UTC:**

| Event | State variable | Delta |
|---|---|---|
| 245 ETH extracted from TokenGateway | `cumulativeWithdrawals` | +245 ETH |

245 ETH is below the VAULT_DRAIN_THRESHOLD of 1,000 ETH. It is also below the
400 ETH burst threshold. **Vector 1 does NOT fire on Phase 1.** This is the
most important signal analysis in this case study: a real $561K loss that falls
below the configured thresholds.

**Phase 2 signal — ~04:55 UTC:**

| Event | State variable | Delta |
|---|---|---|
| 1B bridged DOT minted | `phantomMinted` | +1B DOT (~$1.17B nominal) |

1B DOT at ~$1.17/DOT ≈ $1.17B nominal ≈ ~511,000 ETH equivalent.
PHANTOM_MINT_THRESHOLD: 10,000 ETH. **Exceeds by ~51×.** Vector 2 fires decisively.

The starkest illustration in this set that market impact ≠ on-chain signal
magnitude: the ~$1.17B nominal mint produced only $237K in extracted value
due to thin DEX liquidity. The trap fires on the nominal minting event, not
the realized liquidation — which is the correct behavior.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes — the Token Gateway is a cross-chain bridge contract where message forgery
leads to unauthorized minting. Vector 2 was designed for exactly this class, and
the README explicitly lists Hyperbridge as a Vector 2 reference.

The qualification unique to Hyperbridge: the root cause is a cryptographic
verification library bug — not a missing access control check (CrossCurve, [005](./005-crosscurve-feb-2026.md))
or a compromised key (IoTeX, [006](./006-iotex-iotube-feb-2026.md)). The attacker did
not bypass an administrative check; they satisfied a broken cryptographic
verification function with a mathematically valid but semantically invalid input.
Different root cause class, but the on-chain consequence — unauthorized admin
grant followed by phantom minting — is identical to the IoTeX pattern. The trap
detects the consequence regardless of how the admin grant was obtained.

**B. Does the on-chain consequence produce the detectable signal?**

Yes, clearly for Phase 2. The 1B DOT mint produces a `phantomMinted` spike
exceeding the threshold by ~51×.

Phase 1 (245 ETH drain, Vector 1) does NOT produce a detectable signal at the
configured threshold. This is documented honestly in section 5.

**C. Which similar protocols or architectures produce the same signal?**

Any cross-chain bridge using a shared cryptographic proof library where `ChangeAssetAdmin`-type
messages can be forged produces this signal when the library has edge-case failures:
- Any bridge using the Polytope Labs `MerkleMountainRange` library (open-source, potentially shared across the Polkadot ecosystem)
- Any bridge where proof verification leads directly to admin/minting grants in a single step (high-impact single step: pass verification → get admin → mint unlimited)
- Any bridge where a single verified message can permanently change control authority, rather than authorizing a single transfer

The `ChangeAssetAdmin` message type is particularly high-impact precisely because
it grants permanent control, not a one-time transfer. This mirrors the IoTeX
([006](./006-iotex-iotube-feb-2026.md)) upgrade-then-takeover: different mechanism,
same downstream consequence of permanent admin control ending up in the wrong hands.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ⚠️ Phase 1 below threshold | 245 ETH < 1,000 ETH threshold; 245 ETH < 400 ETH burst threshold; Phase 1 NOT caught |
| Vector 2 — Phantom Mint Velocity | ✅ Fires immediately on Phase 2 (Block N+1) | 1B DOT ≈ 511,000 ETH equivalent; exceeds 10,000 ETH threshold by ~51× |
| Vector 3 — Forged Router Payload | ❌ Does not fire | Exploit used `handlePostRequests` — a different function class from `expressExecute`-style unauthorized call; `spoofedMessageExecuted` does not map to this path |

**Vector 2 detail:**

```solidity
// BridgeRouterGuardTrap.sol → _evaluateVectors()
phantomVelocity = newest.phantomMinted > oldest.phantomMinted
    ? newest.phantomMinted - oldest.phantomMinted : 0;
isCritical = phantomVelocity > PHANTOM_MINT_THRESHOLD; // 10,000 ETH
```

1B DOT minted. Nominal value ~$1.17B = ~511,000 ETH equivalent.
Threshold: 10,000 ETH. Exceeds by ~51×. Hard velocity check.

**Phase 1 honestly stated:** The 245 ETH extraction is a real loss (~$561K) that
falls below the configured detection thresholds. This is the clearest manifestation
in this set of the documented threshold limitation: sub-1,000 ETH single-transaction
drains are not caught by Vector 1. Dynamic thresholds calibrated to baseline flow
would be more sensitive — see section 9.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price April 13, 2026: ~$2,290.
1,000 ETH threshold ≈ $2.29M. 10,000 ETH threshold ≈ $22.9M.

```
~03:55 UTC    PHASE 1 — TokenGateway direct drain.
              Forged message via MMR bypass authorizes 245 ETH withdrawal.
              cumulativeWithdrawals: +245 ETH.
              [TRAP (Vector 1): 245 ETH < 1,000 ETH. No trigger.
               245 ETH (~$561K) leaves. NOT CAUGHT.]

~03:55–04:55  ~1-hour gap between Phase 1 and Phase 2.
              [TRAP: No trigger during gap.]

~04:55:00     PHASE 2 — ChangeAssetAdmin via forged handlePostRequests.
              MMR bypass: leaf_index=1, leafCount=1, proof[0]=overlay_root.
              Admin granted to attacker. 1,000,000,000 bridged DOT minted.
              phantomMinted: 0 → ~511,000 ETH equivalent.
              [Block N.]

~04:55:12     Block N+1. collect() reads state.
              Vector 2: phantomVelocity = ~511,000 ETH >> 10,000 ETH threshold.
              shouldRespond() returns (true, payload) immediately.

~04:55:24     3-operator consensus. snapFreeze() executes:
                VAULT.emergencyPause()   → paused ✓
                GATEWAY.emergencyPause() → paused ✓
                ROUTER.emergencyPause()  → paused ✓

~04:55–05:XX  [ACTUAL] Attacker dumps 1B DOT into Uniswap V4.
              108.2 ETH (~$237K) extracted. ~99.98% of nominal value
              unextractable — price crashes to near-zero on bridged DOT pools.
              ARGN, MANTA, CERE also affected.
              [WITH TRAP: Bridge frozen at ~04:55:24. Further admin calls
               and minting revert. DEX dump of already-minted tokens continues —
               attacker holds 1B DOT on mainnet; trap does not freeze
               attacker wallet.]

Hyperbridge    [ACTUAL] Hyperbridge pauses bridging operations upon detection.
detects        [WITH TRAP: Bridge frozen seconds to minutes before manual pause.]

April 16       Revised $2.5M loss figure released. Four-chain incentive pool
               reconciliation confirms additional losses on Base, BNB, Arbitrum.

Trap exposure window (Phase 2):  ~24 seconds
Phase 1 exposure window:          Not caught (below threshold)
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| Phase 1 — 245 ETH TokenGateway drain | ~$561K lost | ~$561K lost — below Vector 1 threshold |
| Phase 2 — 1B DOT mint, DEX dump (~$237K realized) | ~$237K lost | ~$237K lost — mint completes before snapFreeze |
| Phase 2 — any subsequent minting calls | Lost | $0 — gateway frozen at ~04:55:24 |
| Incentive pool losses — multi-chain (~$1.7M) | ~$1.7M lost | Reduced per deployed chain; full protection requires per-chain deployment |
| **Phase 1 + Phase 2 realized losses** | ~$2.5M revised | ~$798K (Phase 1: $561K + Phase 2: $237K) |
| **Truly preventable with trap** | — | **~$1.7M (incentive pools + follow-on minting, multi-chain)** |

**The honest Hyperbridge damage calculus is more constrained than other cases:**

Phase 1 (~$561K): Not caught — 245 ETH is genuinely below the 1,000 ETH Vector 1
threshold. This is a real gap, not a close call.

Phase 2 realized loss (~$237K): The 1B DOT mint is atomic in one transaction. The
attacker holds the minted tokens before `snapFreeze` fires. The DEX liquidation
that produces $237K is within the attacker's capability from their mainnet balance.
`snapFreeze` stops new minting; it does not confiscate already-minted tokens or
prevent their liquidation.

**Basis for $2.5M revised figure:** Hyperbridge's April 16 update attributed the
revision to four-chain incentive pool reconciliation. $237K is the Phase 2
Ethereum-side realized loss. $561K is Phase 1. Combined: ~$798K directly
attributable to the original attacker. The ~$1.7M remainder reflects secondary
effects including incentive pool losses and actions by users who exploited the
incident window.

---

## 8. What the Trap Does Not Cover Here

**Phase 1 is below threshold.** 245 ETH drain is ~75% below VAULT_DRAIN_THRESHOLD
and ~39% below the 400 ETH burst threshold. At the configured thresholds, a
sub-$600K vault drain is not caught. Dynamic thresholds calibrated to baseline
flow — much lower for Hyperbridge than for Multichain or Orbit Chain — would be
more sensitive. This is the oracle-backed dynamic threshold upgrade documented in
What's Next.

**Admin grant precedes mint.** The `ChangeAssetAdmin` message grants the attacker
permanent admin control in the same block as the mint. Even with a one-block
response, the admin grant is already in effect. The attacker can potentially call
external contracts with admin authority before the next `snapFreeze` block.

**Thin liquidity limits visible signal.** The 1B DOT nominal mint (~$1.17B)
produced only $237K in realized extraction. If only realized liquidation were
monitored, Vector 2 would need a different signal design. The trap correctly
monitors nominal minting — which is the right design choice — but it means the
trap fires on an event that produced far less actual financial harm than its
magnitude suggests.

**The ~1-hour gap between phases.** Phase 1 generates no alert from Vector 1.
During this gap, a human could theoretically intervene if Phase 1 generated a
low-severity alert. The `shouldAlert()` path, configured with a lower threshold
than `shouldRespond()`, could enable this — generating an alert on the 245 ETH
drain even without triggering `snapFreeze`.

**Multi-chain deployment gap.** Incentive pool losses on Base, BNB Chain, and
Arbitrum (~$1.7M) require independent trap deployments per chain.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The Phase 1 threshold gap is addressable through dynamic baseline calibration.
Hyperbridge's normal daily TokenGateway flow is substantially lower than Multichain
or Orbit Chain. A 245 ETH single-transaction withdrawal may be anomalous at 10–50×
normal flow even if it falls below the static 1,000 ETH threshold. Rolling-baseline
dynamic thresholds would make the trap sensitive to context-relative anomalies.

The `shouldAlert()` function offers a partial solution within the current
architecture: a separate alert threshold set at ~200 ETH could generate a
`MODERATE` alert on Phase 1, enabling human review in the ~1-hour window between
phases — without triggering `snapFreeze`.

**Beyond BridgeRouterGuard — an admin-change monitor:**

Both the IoTeX case ([006](./006-iotex-iotube-feb-2026.md)) and this case independently
produce the same intermediate step before phantom minting: an admin change on a
bridge token contract. Both section-9s propose the same response:

- `collect()` reads the admin address of each bridged token contract on each block
  (e.g., `IBridgedToken(DOT_TOKEN).owner()`)
- `shouldRespond()` fires if the admin address changes to anything outside a
  known-authorized set
- Response: pause Token Gateway and freeze minting authority

This fires in the same block as the `ChangeAssetAdmin` execution — before the
first phantom mint is submitted, with the attacker holding admin rights but no
minted tokens yet. This is the closest to pre-mint detection achievable for this
exploit class within Drosera's model.

The convergence of IoTeX and Hyperbridge on the same proposed monitor — arrived
at from different attack paths — is the strongest argument for implementing it.
Two independent attack mechanisms produce the same observable intermediate state
change. A trap watching that state is durable across the attack class.

---

## 10. Sources

- Hyperbridge official post-mortem: "Update on Recovery Efforts and Next Steps" — https://blog.hyperbridge.network/recovery-and-next-steps/
- Verichains: "How a Missing Bounds Check Led to $237K Exploit on Hyperbridge" — https://blog.verichains.io/p/how-a-missing-bounds-check-led-to
- Medium / Stepan Chekhovskoi: "DOT Hacked: The Hyperbridge Exploit" (HandlerV1 and CalculateRoot code analysis) — https://medium.com/@SteMak/dot-hacked-the-hyperbridge-exploit-53e149b93961
- CryptoTimes: "Hyperbridge Raises Exploit Loss Estimate to $2.5M From $237K" — https://cryptotimes.io/2026/04/16/hyperbridge-raises-exploit-loss-estimate-to-2-5m-from-237k/
- Decrypt: "Polkadot-Ethereum Bridge Hack Losses Were 10x Worse Than Reported" — https://decrypt.co/364588/polkadot-ethereum-bridge-hack-losses-10x-worse-team-admits
- crypto.news: "Hyperbridge exploit mints 1 billion fake DOT on Ethereum, nets just $237K" — https://crypto.news/hyperbridge-exploit-mints-1-billion-fake-dot-on-ethereum-nets-just-237k/
- Tekedia: "Hyperbridge Faces ~$250,000 Hack After Making April Fool Post" (contains first public timing — 3:55 AM UTC) — https://tekedia.com/hyperbridge-faces-250000-hack-after-making-april-fool-post-of-having-robust-security-systems/
- BeInCrypto: "Polkadot Based Hyperbridge Revises Exploit Losses to $2.5M" — https://beincrypto.com/hyperbridge-exploit-losses-revised-25m/

