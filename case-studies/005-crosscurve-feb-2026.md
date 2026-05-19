# CrossCurve — February 2026

**Loss:** ~$2.76M–$3M confirmed (BlockSec: $2.76M; estimates up to $3M across all chains; EYWA tokens extracted but unliquidatable — see section 7)  
**Date:** February 2, 2026; drain unfolded across multiple chains within hours  
**Root Cause:** Missing access control on publicly callable execution function; Axelar gateway validation bypass  
**Primary Vector:** Vector 3 — Router unauthorized execution (`executedMessages - gatewayValidatedMessages`)  
**Trap verdict:** `CAUGHT (post-drain)`

CrossCurve is the cleanest Vector 3 case in this set. A missing access control check on `ReceiverAxelar.expressExecute()` allowed the attacker to call it directly with a fabricated payload, bypassing the Axelar gateway entirely. In v3 terms: `executedMessages` increments, `gatewayValidatedMessages` does not — the mismatch is immediate and the trap fires on the same block as the unauthorized execution.

---

## 1. Incident Summary

CrossCurve (formerly EYWA) is a cross-chain decentralized exchange and bridge built in partnership with Curve Finance, with ~$7M in venture funding. Its architecture combines Axelar's General Message Passing (GMP) layer with internal PortalV2 bridge contracts and a custom EYWA Oracle Network. `ReceiverAxelar` contracts receive and validate cross-chain messages, then authorize PortalV2 to release or mint tokens.

On February 2, 2026, an attacker exploited a missing validation check in CrossCurve's `ReceiverAxelar` contract. The `expressExecute()` function — designed for expedited cross-chain execution — was publicly callable with no authentication of message origin. The only enforced check was whether a `commandId` had been previously used, trivially bypassed with a fresh unique value. The attacker called `expressExecute()` directly with a fully fabricated payload, bypassing the Axelar gateway entirely, and triggered `PortalV2` to release tokens without any corresponding deposit on a source chain.

The exploit was replicated across Ethereum, Arbitrum, Optimism, Base, Mantle, Kava, Frax, Celo, and Blast. BlockSec confirmed ~$1.3M on Ethereum and ~$1.28M on Arbitrum as primary losses; smaller amounts across remaining chains. Total: ~$2.76M–$3M. CrossCurve paused contracts upon detection, identified ten attacker-linked addresses, and issued a 72-hour fund-return window.

**Note on EYWA token extraction:** The attacker also minted 999,787,453 EYWA tokens on Ethereum. However, EYWA's entire circulating supply had migrated to Arbitrum at token generation. No on-chain liquidity pools existed for EYWA on Ethereum, and the sole CEX with an Ethereum deposit channel froze it immediately. These tokens could not be liquidated and are excluded from the confirmed loss figure.

---

## 2. Technical Root Cause

**The vulnerability:** Missing access control on `ReceiverAxelar.expressExecute()`.

Under Axelar's intended security model, cross-chain messages must be approved by the Axelar Gateway on the destination chain and pass `validateContractCall()` before execution. The `expressExecute()` path was designed as a fast-path alternative for legitimate Axelar relayers only. CrossCurve's implementation enforced no such restriction — the function was publicly callable by anyone.

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
    // NO verification that Axelar actually relayed this message
    _executePayload(sourceChain, sourceAddress, payload);
}
```

Additionally: the confirmation threshold was misconfigured to 1, disabling multi-guardian validation even on paths that attempted it.

**Attack sequence:**

1. Attacker generates a fresh `commandId` (any unique `bytes32`).
2. Attacker spoofs `sourceChain` and `sourceAddress` to appear as a legitimate CrossCurve portal address.
3. Attacker crafts a malicious payload: `abi.encode(UNLOCK_SELECTOR, attackerAddress, tokenAddress, amount)`.
4. Attacker calls `ReceiverAxelar.expressExecute()` directly — no Axelar gateway involvement. Contract accepts, marks `commandId` as executed, triggers `PortalV2.unlock()`. Tokens released.
5. Attack replicated across 9 chains with fresh `commandId` values per chain.
6. Arbitrum assets converted to WETH via CoW Protocol, bridged to Ethereum via Across Protocol.

---

## 3. On-Chain Signal Profile

CrossCurve is a hard invariant case — the signal is not a velocity accumulation, it is a binary state change per chain.

In v3 terms, what `collect()` would read:

| Field | Pre-attack | Post `expressExecute()` | Delta |
|---|---|---|---|
| `executedWithdrawals` | baseline | +released amount | grows |
| `validatedInboundCredits` | baseline | unchanged — no gateway validation | 0 |
| `cumulativeMinted` | baseline | +EYWA minted (illiquid) | grows |
| `validatedMintAuthorizations` | baseline | unchanged — no authorization consumed | 0 |
| `executedMessages` | baseline | +1 | +1 |
| `gatewayValidatedMessages` | baseline | unchanged — no gateway validation | 0 |
| `vaultTokenBalance` | baseline | drops by released amount | drops |

Three invariants are violated simultaneously on the same block:
- Vector 1: `executedWithdrawals` grows, `validatedInboundCredits` does not → zero-backing trigger
- Vector 2: `cumulativeMinted` grows (EYWA), `validatedMintAuthorizations` does not → mismatch (below threshold for illiquid EYWA)
- Vector 3: `executedMessages` grows, `gatewayValidatedMessages` does not → hard invariant fires

Vector 3 fires first and unconditionally. It requires no threshold check and no prior sample.

---

## 4. Design Envelope Assessment

This incident matches the design target of Vector 3. CrossCurve's architecture relies on a destination-side receiver contract that must enforce gateway validation before executing cross-chain payloads. The `expressExecute()` bypass of `validateContractCall()` is structurally identical to the mock router's exploit path: execution occurs without a corresponding gateway-validated message registration.

```solidity
// [EXPLOIT EXECUTION — CrossCurve Feb 2026 pattern]
// expressExecute() with no gateway validation check.
// executedMessages increments. gatewayValidatedMessages does not.
// The invariant fires: executedMessages > gatewayValidatedMessages.
function expressExecute(bytes calldata, bytes32) external {
    require(!paused, "Router paused");
    executedMessages++;
    // gatewayValidatedMessages unchanged — the mismatch grows.
}
```
→ [`src/mocks/core/MockBridgeRouter.sol`](../src/mocks/core/MockBridgeRouter.sol)

One unauthorized `expressExecute()` call causes `executedMessages` to exceed `gatewayValidatedMessages` by exactly 1. Vector 3's hard invariant fires immediately on the first sample capturing this growth. No threshold calibration is required. No historical baseline is needed. Any cross-chain bridge using Axelar GMP where the destination-side receiver exposes a publicly callable execution function that skips `validateContractCall()` produces this identical signal. The Kelp DAO exploit ([008](./008-kelp-dao-apr-2026.md)) operates on a different messaging layer but shares the same structural family: forged cross-chain messages bypassing single-point validation. CrossCurve's trust failure was an unauthenticated public function; Kelp's was a poisoned DVN. Both produce the same router execution mismatch.

---

## 5. Trap Vector Mapping

| Vector | Status | Signal |
|---|---|---|
| Vector 1 — Vault drain mismatch | ✅ Fires (same block) | `executedWithdrawals` grows, `validatedInboundCredits` unchanged — zero-backing trigger |
| Vector 2 — Gateway phantom mint mismatch | ⚠️ EYWA tokens — illiquid, below threshold | `cumulativeMinted` grows (999M EYWA), `validatedMintAuthorizations` unchanged — but EYWA market value produces delta below `PHANTOM_MINT_THRESHOLD` |
| Vector 3 — Router unauthorized execution | ✅ Fires immediately (same block, no history needed) | `executedMessages > gatewayValidatedMessages` → hard invariant |
| Vector 4 — Reserve reconciliation | ✅ Fires (same block, secondary) | `vaultTokenBalance` drops without counter movement |

Vector 3 fires first. It requires a single sample and produces an immediate response regardless of amount. Vectors 1 and 4 fire on the same block as secondary confirmation. Vector 2 fires but produces a delta below the response threshold for EYWA's market valuation.

```solidity
// Hard invariant: router must never execute without gateway validation.
// Any gap between executedMessages and gatewayValidatedMessages = immediate response.
// No threshold. No prior sample needed. Single sample sufficient.
if (newest.executedMessages > newest.gatewayValidatedMessages) {
    uint256 unauthorizedExecs = newest.executedMessages - newest.gatewayValidatedMessages;
    return (true, abi.encode(uint256(0), uint256(0), unauthorizedExecs, uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](../src/core/BridgeRouterGuardTrap.sol)

**Multi-chain deployment reality:** This is a single-chain analysis. A single Ethereum deployment catches Ethereum's drain (~$1.3M trigger event + any follow-on attempts). The Arbitrum drain (~$1.28M) requires a separate Arbitrum deployment. Each chain fires independently within one block of the first unauthorized `expressExecute()` on that chain.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum). ETH price February 2026: ~$2,500.

```
Pre-exploit:         expressExecute() publicly callable since deployment.
                     collect(): all counters at baseline.
                     shouldRespond(): all invariants satisfied. false.

T+0:00               FIRST UNAUTHORIZED expressExecute() — Ethereum.
                     commandId: fresh unique bytes32.
                     sourceChain / sourceAddress: spoofed.
                     payload: UNLOCK_SELECTOR + attacker + ~$1.3M tokens.
                     PortalV2.unlock() executes. Tokens released.

                     collect() on this block:
                       executedMessages: baseline + 1
                       gatewayValidatedMessages: baseline (unchanged)
                       executedWithdrawals: grows by released amount
                       validatedInboundCredits: unchanged
                       vaultTokenBalance: drops

                     shouldRespond() evaluates Vector 3 first:
                       executedMessages > gatewayValidatedMessages → true
                       Returns (true, abi.encode(0, 0, unauthorizedExecs, 0))
                       [TRAP: Fires 1 block after trigger (baseline operator latency)]

T+0 + 1 block
                     Operator network reaches consensus.
                     snapFreeze() executes — Ethereum:
                       vault.emergencyPause()   → paused ✓
                       gateway.emergencyPause() → paused ✓
                       router.emergencyPause()  → paused ✓
                     Any further expressExecute() calls on Ethereum revert.

T+0 to T+hours       [ACTUAL] Attack replicated on Arbitrum, Optimism, Base,
                     Mantle, Kava, Frax, Celo, Blast in separate transactions.
                     [WITH PER-CHAIN TRAPS] Each chain fires within 1 block
                     of its first unauthorized call.
                     [WITHOUT per-chain traps] Other chains drain unimpeded.

Hours later          CrossCurve manually pauses contracts, identifies 10 wallets,
                     issues 72-hour return window.

Trap exposure window (per chain): 1–2 blocks from first unauthorized call
Actual exposure window:           Hours (no automated containment per chain)
```

---

## 7. Damage Assessment

Three loss figures circulate — $1.4M (QuillAudits, liquid assets only), $2.76M (BlockSec, most detailed chain-by-chain breakdown), ~$3M (Defimon, all chains). This analysis uses BlockSec's $2.76M as the primary confirmed figure.

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| Ethereum — first expressExecute() (~$1.3M) | Lost | Lost — completes before snapFreeze (unavoidable trigger event) |
| Ethereum — any subsequent expressExecute() attempts | Lost | $0 — router frozen |
| Arbitrum (~$1.28M) | Lost | $0 if Arbitrum trap deployed; lost if not |
| Remaining 7 chains (smaller amounts) | Lost | $0 per chain if trap deployed |
| EYWA tokens (999M, illiquid) | Minted, unliquidatable | Same — already minted |
| **Total preventable (Ethereum follow-on + Arbitrum with deployment)** | — | **~$1.28M+ (Arbitrum) + smaller chains** |

Each chain's drain is a single atomic call. The trap fires on that block, but the call completes before `snapFreeze()` executes. The containment value lies in preventing repeat calls on the same chain and blocking cross-chain propagation to chains where the trap is deployed before the attacker reaches them.

---

## 8. What the Trap Does Not Cover Here

**Single-atomic-transaction drain per chain.** The first `expressExecute()` on each chain completes in one transaction. The trap fires on that block but the call is already confirmed. A reactive monitor cannot stop the transaction that produces its own trigger.

**Multi-chain deployment requirement.** 9 chains affected. A single deployment catches only one. Full protection requires independent deployments per chain — each with its own `collect()` addresses, response contract, and operator set.

**Day-zero vulnerability.** `expressExecute()` was callable from the contract's deployment. There is no on-chain precursor to detect — the first call and the exploit are the same event.

**Root cause requires a code fix.** The correct mitigation is adding `require(gateway.validateContractCall(...))` before `_executePayload()`. The trap provides containment after first exploitation; it does not substitute for proper access control in the contract itself.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

Vector 3 is correct and sufficient. A production `collect()` monitoring CrossCurve would read `ReceiverAxelar.executedMessages` and `ReceiverAxelar.gatewayValidatedMessages` as separate counters — requiring the protocol to expose these as readable state. The mock implementation demonstrates exactly this:

```solidity
uint256 public executedMessages;
uint256 public gatewayValidatedMessages;

function executeValidated(bytes32 payloadHash, bytes calldata) external view {
    require(validatedPayloads[payloadHash], "Payload not validated by gateway");
    // Both counters increment together in legitimate operation.
}

function expressExecute(bytes calldata, bytes32) external {
    executedMessages++;
    // gatewayValidatedMessages unchanged — mismatch grows immediately.
}
```
→ [`src/mocks/core/MockBridgeRouter.sol`](../src/mocks/core/MockBridgeRouter.sol)

**Beyond BridgeRouterGuard:**

The ideal detection mechanism for this attack class would fire before the first execution. A gateway approval monitor reading `IAxelarGateway.isContractCallApproved()` for recent message hashes targeting `ReceiverAxelar` could detect the gap between unapproved gateway state and imminent execution — potentially enabling pre-execution containment. This extension addresses the atomic trigger constraint by shifting detection upstream to the validation layer itself.

---

## 10. Sources

- Halborn: "Explained: The CrossCurve Hack (February 2026)" — https://halborn.com/blog/post/explained-the-crosscurve-hack-february-2026
- BlockSec: "Newsletter February 2026" (primary chain-by-chain breakdown) — https://blocksec.com/blog/newsletter-february-2026
- QuillAudits: "Cross Curve $1.4M Implementation Bug [Explained]" — https://quillaudits.com/blog/hack-analysis/cross-curve-exploit
- The Block: "CrossCurve Bridge Exploited for ~$3M Across Multiple Chains" — https://theblock.co/post/387939/crosscurve-bridge-exploited-for-approximately-3-million-across-multiple-chains
- Decrypt: "CrossCurve Threatens Legal Action After $3M Bridge Exploit" — https://decrypt.co/356599/crosscurve-legal-action-3m-cross-chain-bridge-exploit
- DEV.to: "The CrossCurve $3M Bridge Exploit: How One Missing Check Let Attackers Forge Cross-Chain Messages" — https://dev.to/ohmygod/the-crosscurve-3m-bridge-exploit-how-one-missing-check-let-attackers-forge-cross-chain-messages-516m

---

```bash
rm case-studies/005-crosscurve-feb-2026.md
```

```bash
nano case-studies/005-crosscurve-feb-2026.md
```

```bash
git commit -m "docs(case-studies): standardize 005-crosscurve to v3 forensic template" \
-m "- Align CrossCurve Feb 2026 analysis with v3 accounting-mismatch architecture and standardized section structure" \
-m "- Correct relative paths to ../src/ for mock and trap contract references" \
-m "- Enforce declarative tone, explicit vector mapping, and operator-latency framing consistent with 001-004 and 006-010" \
-m "- Document Vector 3 hard-invariant behavior, multi-chain deployment constraints, and atomic trigger limitations"
```
