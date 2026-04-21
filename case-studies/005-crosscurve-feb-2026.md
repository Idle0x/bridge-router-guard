# CrossCurve — February 2026

**Loss:** ~$2.76M–$3M confirmed (BlockSec: $2.76M; estimates up to $3M across all chains; EYWA tokens extracted but unliquidatable — see section 7)
**Date:** February 2, 2026; drain unfolded across multiple chains within hours
**Vectors triggered:** 3 (Forged Router Payload — direct hit, cleanest Vector 3 match in this case study set)
**Trap verdict:** `CAUGHT (post-drain)` — each individual chain drain is a single atomic transaction; trap fires within one block per chain, preventing repeat calls and cross-chain propagation

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

CrossCurve (formerly EYWA) is a cross-chain decentralized exchange and bridge
built in partnership with Curve Finance, with ~$7M in venture funding. Its
architecture combines Axelar's General Message Passing (GMP) layer with internal
PortalV2 bridge contracts and a custom EYWA Oracle Network. ReceiverAxelar
contracts receive and validate cross-chain messages, then authorize PortalV2 to
release or mint tokens.

On February 2, 2026, an attacker exploited a missing validation check in
CrossCurve's ReceiverAxelar contract. The `expressExecute()` function — designed
for expedited cross-chain execution — was publicly callable with no authentication
of message origin. The only enforced check was whether a `commandId` had been
previously used, trivially bypassed with a fresh unique value. The attacker
called `expressExecute()` directly with a fully fabricated payload, bypassing the
Axelar gateway entirely, and triggered PortalV2 to release tokens without any
corresponding deposit.

The exploit was replicated across Ethereum, Arbitrum, Optimism, Base, Mantle,
Kava, Frax, Celo, and Blast. BlockSec confirmed ~$1.3M on Ethereum and ~$1.28M
on Arbitrum as primary losses; smaller amounts across remaining chains. Total:
~$2.76M–$3M. CrossCurve paused contracts upon detection, identified ten
attacker-linked addresses, and issued a 72-hour fund-return window.

**Note on EYWA token extraction:** The attacker also minted 999,787,453 EYWA
tokens on Ethereum. However, EYWA's entire circulating supply had migrated to
Arbitrum at token generation. No on-chain liquidity pools existed for EYWA on
Ethereum, and the sole CEX with an Ethereum deposit channel froze it immediately.
These tokens could not be liquidated and are excluded from the confirmed loss figure.

---

## 2. Technical Root Cause

**The vulnerability:** Missing access control on `ReceiverAxelar.expressExecute()`.

Under Axelar's intended security model, cross-chain messages must be approved by
the Axelar Gateway on the destination chain and pass `validateContractCall()`
before execution. The `expressExecute()` path was designed as a fast-path
alternative for legitimate Axelar relayers only. CrossCurve's implementation
enforced no such restriction — the function was publicly callable by anyone.

**The vulnerable code (confirmed by QuillAudits and independent analysis):**

```solidity
// VULNERABLE — CrossCurve ReceiverAxelar
function expressExecute(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload
) external {
    require(!executedCommands[commandId], "Already executed");
    executedCommands[commandId] = true;
    // NO validation of sourceChain authenticity
    // NO validation of sourceAddress against whitelist
    // NO multi-guardian confirmation requirement
    // NO verification that Axelar actually relayed this message
    _executePayload(sourceChain, sourceAddress, payload);
}
```

Additionally: the confirmation threshold was misconfigured to 1, disabling
multi-guardian validation even on paths that attempted it.

**Attack sequence:**

1. Attacker generates a fresh `commandId` (any unique `bytes32`).
2. Attacker spoofs `sourceChain` and `sourceAddress` to appear as a legitimate CrossCurve portal address.
3. Attacker crafts a malicious payload: `abi.encode(UNLOCK_SELECTOR, attackerAddress, tokenAddress, amount)`
4. Attacker calls `ReceiverAxelar.expressExecute()` directly — no Axelar gateway involvement. Contract accepts, marks `commandId` as executed, triggers `PortalV2.unlock()`. Tokens released.
5. Attack replicated across 9 chains with fresh `commandId` values per chain.
6. Arbitrum assets converted to WETH via CoW Protocol, bridged to Ethereum via Across Protocol.

This is structurally identical to the Nomad 2022 exploit ($190M), where a root
hash initialized to zero allowed any message replay. CrossCurve is a direct
descendant of that pattern class, four years later.

---

## 3. On-Chain Signal Profile

CrossCurve is the cleanest Vector 3 case in this entire set. The signal is not
velocity — it is a binary state change per chain.

`spoofedMessageExecuted` maps to a router/receiver contract executing a
cross-chain payload without canonical gateway validation.
`ReceiverAxelar.expressExecute()` bypassing `validateContractCall()` is exactly
this invariant. One unauthorized call = immediate trigger.

| Chain | Loss | Signal type | Vector 3 fires? |
|---|---|---|---|
| Ethereum | ~$1.3M | Single `expressExecute()` call | ✅ Immediately |
| Arbitrum | ~$1.28M | Single `expressExecute()` call | ✅ Immediately |
| Optimism, Base, Mantle, Kava, Frax, Celo, Blast | Smaller amounts | Same | ✅ Per chain |

The signal is hard boolean — no multi-block buildup. `spoofedMessageExecuted`
flips in a single transaction. Vector 3 fires on block N+1 with zero history
required. Vector 1 may also fire if the per-chain drain exceeds 1,000 ETH
equivalent, but Vector 3 fires unconditionally regardless.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes — CrossCurve is the primary real-world reference for Vector 3 in the README,
and the technical analysis confirms the match is exact. `expressExecute()` bypassing
`validateContractCall()` is structurally identical to `MockBridgeRouter.expressExecute()`
bypassing `validatedPayloads` in the mock. The invariant is the same:
**execution must not occur without gateway-validated authorization.**

**B. Does the on-chain consequence produce the detectable signal?**

Yes, immediately. One unauthorized `expressExecute()` call = `spoofedMessageExecuted`
flips to true = Vector 3 fires on the next `collect()`, ~12 seconds after the
drain. No threshold calibration needed. No history required.

**C. Which similar protocols or architectures produce the same signal?**

Any cross-chain bridge using Axelar GMP where the destination-side receiver
exposes a publicly callable execution function that skips `validateContractCall()`:
- Any custom `ReceiverAxelar` relying only on `commandId` uniqueness rather than
  Gateway approval (replay protection is not access control)
- Any bridge where `expressExecute()` or a fast-path equivalent is callable
  without the Axelar Gateway's approval signature
- Any bridge receiver that accepts user-supplied `sourceChain` and `sourceAddress`
  without whitelisting them against trusted peers

The Kelp exploit ([008](./008-kelp-dao-apr-2026.md)) operates on a different
messaging layer (LayerZero rather than Axelar) but is in the same family:
forged cross-chain messages bypassing multi-party validation. Both CrossCurve
and Kelp demonstrate that the "single point of trust" pattern — whether a
1-of-1 DVN or an unauthenticated execution function — produces the same class
of exploitable surface.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ⚠️ Chain and threshold dependent | Ethereum ~$1.3M and Arbitrum ~$1.28M may be below 1,000 ETH threshold depending on token composition; Vector 3 fires unconditionally |
| Vector 2 — Phantom Mint | ⚠️ EYWA tokens only — illiquid | 999M EYWA minted but unliquidatable; no practical harm; Vector 3 fires regardless |
| Vector 3 — Forged Router Payload | ✅ Fires immediately (Block N+1) | `expressExecute()` called directly without Axelar gateway validation; hard boolean invariant |

**Vector 3 detail:**

```solidity
// BridgeRouterGuardTrap.sol → shouldRespond()
if (newest.spoofedMessageExecuted) {
    return (true, abi.encode(..., true));
}
```

`ReceiverAxelar.expressExecute()` called directly by attacker without Axelar
Gateway approval = unauthorized payload execution = `spoofedMessageExecuted`
maps to true on the next block's `collect()` call. Hard boolean invariant. No
history needed. One unauthorized call = immediate `snapFreeze`.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum). ETH price February 2026: ~$2,500.

```
Pre-exploit:         expressExecute() publicly callable since deployment.
                     No prior unauthorized calls. [TRAP: No trigger.]

T+0:00               FIRST UNAUTHORIZED expressExecute() — Ethereum.
                     commandId: fresh unique bytes32.
                     sourceChain / sourceAddress: spoofed.
                     payload: UNLOCK_SELECTOR + attacker + ~$1.3M tokens.
                     PortalV2.unlock() executes. Tokens released.
                     [Block N. Drain complete. Irreversible.]

T+0:12               Block N+1. collect() reads state.
                     Vector 3: spoofedMessageExecuted = true.
                     shouldRespond() fires immediately. No history needed.

T+0:24               3-operator consensus. snapFreeze() executes — Ethereum:
                       VAULT.emergencyPause()   → paused ✓
                       GATEWAY.emergencyPause() → paused ✓
                       ROUTER.emergencyPause()  → paused ✓
                     Any further expressExecute() calls on Ethereum revert.

T+0 to T+hours       [ACTUAL] Attack replicated on Arbitrum, Optimism, Base,
                     Mantle, Kava, Frax, Celo, Blast.
                     [WITH PER-CHAIN TRAPS: Each chain fires within 24s of
                      its first unauthorized call.]
                     [WITHOUT per-chain traps: Other chains drain unimpeded.]

Hours later          CrossCurve manually pauses contracts, identifies 10 wallets,
                     issues 72-hour return window.

Trap exposure window (per chain):   ~24 seconds from first unauthorized call
Actual exposure window:             Hours (no automated containment)
```

---

## 7. Damage Assessment

Three loss figures circulate — $1.4M (QuillAudits, liquid assets only), $2.76M
(BlockSec, most detailed chain-by-chain breakdown), ~$3M (Defimon, all chains).
This analysis uses BlockSec's $2.76M as the primary confirmed figure.

| | Without Trap | With Trap (per-chain deployment) |
|---|---|---|
| Ethereum — first expressExecute() (~$1.3M) | Lost | Lost — single atomic tx |
| Ethereum — any subsequent expressExecute() calls | Lost | $0 — bridge frozen at T+24s |
| Arbitrum (~$1.28M) | Lost | $0 if Arbitrum trap deployed; lost if not |
| Remaining 7 chains (smaller amounts) | Lost | $0 per chain if trap deployed |
| EYWA tokens (999M, ~illiquid) | Minted, unliquidatable | Same — already minted |
| **Total preventable (cross-chain propagation)** | — | **~$1.28M+ (Arbitrum) + smaller chains** |

**Honest assessment:** CrossCurve is the hardest case in this set for the damage
prevention claim. Each chain's drain was a single atomic call. The trap fires on
block N+1 — after that call is complete. The primary value here is: (1) preventing
repeat calls on the same chain after the first drain, (2) enabling faster
cross-chain alerts so manual intervention can stop other chains before they drain,
and (3) speed — CrossCurve's manual pause took hours; the trap fires in 24 seconds.

---

## 8. What the Trap Does Not Cover Here

**Single-atomic-transaction drain per chain.** The first `expressExecute()` on
each chain completes before the trap fires. No on-chain monitor prevents a
well-crafted single-transaction exploit from completing its first execution.

**Multi-chain deployment requirement.** 9 chains affected. A single deployment
catches only one. Full protection requires independent deployments per chain —
a deployment scale problem, not a trap logic problem.

**Day-zero vulnerability.** `expressExecute()` was callable from the contract's
deployment. Any monitoring system is reactive; it fires after the first call,
not before.

**The root cause requires a code fix.** The correct fix is adding
`require(gateway.validateContractCall(...))` before `_executePayload()`.
A monitor does not substitute for proper input validation in the contract itself.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

Vector 3 is the correct and sufficient vector. A production `collect()` monitoring
CrossCurve would read `ReceiverAxelar.unauthorizedExecuteCount()` — a counter
incremented each time `expressExecute()` is called without a prior
`gateway.validateContractCall()` confirmation. This requires the ReceiverAxelar
contract to expose this state.

**Beyond BridgeRouterGuard — a gateway approval correlation trap:**

The ideal detection mechanism for this attack class is pre-execution, not
post-execution. A gateway approval monitor could:
- `collect()` reads `IAxelarGateway.isContractCallApproved()` for recent message
  hashes targeting ReceiverAxelar
- `shouldRespond()` fires if a ReceiverAxelar execution occurs for a commandId
  with no corresponding gateway approval record
- This correlates state from two contracts in the same `collect()` call —
  architecturally viable within Drosera's view constraints

This would detect the gap between "gateway has not approved" and "execution about
to happen" — potentially preventing even the first atomic drain on each chain.
It is the strongest possible extension for this attack class and would represent
a genuine pre-execution detection capability.

The Nomad 2022 parallel: a gateway approval monitor deployed on Nomad-style
bridges would have fired before any of the 300+ copycat drains that followed the
initial exploit. CrossCurve is a four-year repeat of a known vulnerability class.
A trap watching for validation bypass is the systemic defense.

---

## 10. Sources

- Halborn: "Explained: The CrossCurve Hack (February 2026)" — https://halborn.com/blog/post/explained-the-crosscurve-hack-february-2026
- BlockSec: "Newsletter February 2026" (primary chain-by-chain breakdown) — https://blocksec.com/blog/newsletter-february-2026
- QuillAudits: "Cross Curve $1.4M Implementation Bug [Explained]" — https://quillaudits.com/blog/hack-analysis/cross-curve-exploit
- The Block: "CrossCurve Bridge Exploited for ~$3M Across Multiple Chains" — https://theblock.co/post/387939/crosscurve-bridge-exploited-for-approximately-3-million-across-multiple-chains
- Decrypt: "CrossCurve Threatens Legal Action After $3M Bridge Exploit" — https://decrypt.co/356599/crosscurve-legal-action-3m-cross-chain-bridge-exploit
- DEV.to: "The CrossCurve $3M Bridge Exploit: How One Missing Check Let Attackers Forge Cross-Chain Messages" — https://dev.to/ohmygod/the-crosscurve-3m-bridge-exploit-how-one-missing-check-let-attackers-forge-cross-chain-messages-516m
