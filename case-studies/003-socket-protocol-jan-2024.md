# Socket Protocol — January 2024

**Loss:** ~$3.3M confirmed (net ~$1M–$1.5M after 1,032 ETH returned by attacker)
**Date:** January 16, 2024, ~18:20 UTC; two exploit transactions within approximately 2 minutes
**Vectors triggered:** None as deployed — see section 4
**Trap verdict:** `PARTIAL` — the attack class intersects Vector 3 conceptually, but the exploit's actual mechanism (user approval draining via injected calldata) targets distributed wallet state rather than a bridge reserve; the trap monitors the wrong contracts to catch this

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

Socket Protocol is a cross-chain interoperability layer used by applications to
route asset and data transfers across blockchains. Its SocketGateway contract
aggregates multiple bridge and swap routes, acting as a unified entry point.
Bungee is Socket's consumer-facing bridge interface built on top of SocketGateway.

On January 16, 2024, an attacker exploited a newly deployed route in
SocketGateway's aggregator system. The vulnerable contract —
`WrappedTokenSwapperImpl` — had been deployed just three days before the attack
and had not been audited. It contained a call injection vulnerability: the
`performAction` function passed user-supplied `swapExtraData` directly to a
low-level `call()` without validation, allowing the attacker to inject an
arbitrary `transferFrom()` call and drain tokens from any wallet that had
previously granted approvals to the SocketGateway contract.

Two exploit transactions drained approximately $3.3M from ~231 affected users
within approximately 2 minutes. Socket paused the affected contracts within 14
minutes. The attacker later returned 1,032 ETH following on-chain negotiation.

---

## 2. Technical Root Cause

**The vulnerability:** Incomplete input validation in
`WrappedTokenSwapperImpl.performAction()`. The `swapExtraData` parameter was
passed unsanitized to a `call()` instruction, allowing injection of a
`transferFrom()` function signature to steal tokens from approved wallets.

**The structural flaw:** `performAction` included a balance check ensuring net
native token balance matched a designated input `amount`. However, the function
did not restrict `amount` to non-zero values. By passing `amount = 0`, the
balance check always passed — leaving the injected `transferFrom()` unchecked.

**Attack sequence:**

1. Attacker wallet funded via fixed-float transaction linked to Tornado Cash.
2. Attacker deployed a malicious contract to orchestrate the exploit.
3. Called `0x00000196()` on SocketGateway — the hex signature triggered the
   fallback routing to slot 406, where `WrappedTokenSwapperImpl` had been
   deployed three days prior.
4. Injected `transferFrom(victim, attacker, amount)` via `swapExtraData` in
   `performAction()`.
5. Function executed injected calldata against each pre-queried victim address,
   transferring approved tokens directly to the attacker.

**Two transactions, ~2 minutes apart:**
- Transaction 1: ~$2.5M USDC drained from 127 victims
- Transaction 2: WETH, USDT, WBTC, DAI, MATIC drained from 104 victims

**Critical distinction:** Socket's exploit did not drain a bridge reserve or
vault. No locked assets moved. The attacker stole from individual users' wallets
by exploiting their existing token approvals to SocketGateway. The bridge
reserve itself was untouched. This is an approval-draining attack against end
users, not a bridge reserve drain — and that distinction determines the trap's
verdict.

**Response time:** Socket identified and paused the vulnerable route within
14 minutes of the first exploit transaction. Fast for a manual response.

---

## 3. On-Chain Signal Profile

**What the trap monitors:**
BridgeRouterGuard reads three state variables from three contracts:
- `MockBridgeVault.cumulativeWithdrawals` — cumulative reserve outflow
- `MockTokenGateway.phantomMinted` — cumulative unbacked mint counter
- `MockBridgeRouter.spoofedMessageExecuted` — router execution boolean

**What the Socket exploit actually changed on-chain:**
- Individual user wallet balances decreased (ERC20 `transferFrom` events)
- SocketGateway did not change its own reserve state
- No cumulative bridge reserve counter moved
- No phantom tokens were minted
- `performAction` executed, but called `transferFrom` on user wallets — not a
  bridge message execution that would set `spoofedMessageExecuted`

**The signal mismatch:**

| Signal the trap reads | Socket exploit on-chain event | Match? |
|---|---|---|
| `cumulativeWithdrawals` spike | No vault/reserve drain occurred | — |
| `phantomMinted` spike | No token minting occurred | — |
| `spoofedMessageExecuted` = true | `performAction` executed with injected calldata | Partial — different mechanism |

The entire attack window was ~2 minutes — shorter than Socket's own 14-minute
manual response. Any on-chain velocity monitor with correct instrumentation
would fire within 12 seconds of the first transaction. But only if monitoring
the right contracts and the right state variables.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Partially — with an important qualification that changes the verdict.

The attack class is the same at a conceptual level (execution without
validation) but the mechanism differs in a way that matters for detection:

- **What the trap was designed for:** A router executing a cross-chain message
  payload without gateway proof — the bridge reserve releases funds because an
  unauthorized message was accepted. This is the [CrossCurve pattern (005)](./005-crosscurve-feb-2026.md).
- **What actually happened:** A router executing `transferFrom` on user wallets
  because calldata was unsanitized. No inbound cross-chain message. No reserve
  drain. The bridge contract was used as a calldata injection vector, not a
  messaging relay.

These share the same root invariant (execution without validation) but differ
at the detection layer. The trap's `spoofedMessageExecuted` flag catches
unauthorized cross-chain message execution. It does not catch arbitrary calldata
injection into a swap function on a router that the trap does not monitor.

**B. Does the on-chain consequence produce the detectable signal?**

Not through the current three monitored state variables. The on-chain
consequence is ERC20 balance changes across ~231 user wallets — distributed
state, not a single readable counter. None of `cumulativeWithdrawals`,
`phantomMinted`, or `spoofedMessageExecuted` change during this attack.

**C. Which similar protocols or architectures produce the same signal?**

The Socket attack class — calldata injection via unsanitized router input — is
detectable by the trap only if the router contract exposes cumulative drained
value as on-chain readable state, OR if the attack produces a bridge reserve
outflow as a secondary consequence. Neither applies here. Approval-draining
attacks targeting individual user wallets (Dexible, Hector Bridge, Socket)
are structurally different from reserve-drain attacks.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | — | Out of scope — no bridge reserve drained; attack targets user wallet approvals, not protocol reserves |
| Vector 2 — Phantom Mint | — | Out of scope — no token minting occurred in any form |
| Vector 3 — Forged Router Payload | ⚠️ Partial match — does not fire as deployed | `performAction` executed with injected calldata; conceptually related but `spoofedMessageExecuted` maps to a different contract and mechanism |

**Vector 3 detail:**

`spoofedMessageExecuted` is set to `true` when `expressExecute()` is called on
`MockBridgeRouter` without gateway-validated payload — explicit simulation of
unauthorized cross-chain message execution. In a production deployment monitoring
SocketGateway, an equivalent flag would need to be set on unauthorized
`performAction` invocations. SocketGateway does not expose such a state variable
as deployed. The attack happened and completed before any on-chain state the
trap reads would reflect it.

The conceptual invariant is correct: `performAction` executed a payload (the
injected `transferFrom`) without validating its contents. This is execution
without validation. But the trap's current implementation reads a specific state
variable that does not exist on SocketGateway in the needed form.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet).

```
~18:20 UTC   Transaction 1: ~$2.5M USDC drained from 127 victims via injected
             transferFrom in performAction().
             [TRAP: cumulativeWithdrawals = 0. phantomMinted = 0.
             spoofedMessageExecuted = false (not set by SocketGateway).
             shouldRespond() returns false. No trigger.]

~18:22 UTC   Transaction 2: WETH, USDT, WBTC, DAI, MATIC drained from 104 more
             victims. Total: ~$3.3M.
             [TRAP: Same — no monitored state variable changes. No trigger.]

~18:34 UTC   Socket team identifies issue and pauses vulnerable route.
             ~14 minutes after first exploit transaction.
             [TRAP AS DEPLOYED: Does not fire — wrong contracts monitored.
              HYPOTHETICAL CORRECT CONFIG: Would fire within 12 seconds of
              Transaction 1 — ~13m 48s faster than the manual pause.]

Trap exposure window (as deployed):       N/A — trap does not fire
Actual exposure window:                   ~14 minutes (manual pause)
Hypothetical correctly configured trap:   ~12 seconds
```

---

## 7. Damage Assessment

| | Without Trap (actual) | With Trap as deployed | With correctly configured trap |
|---|---|---|---|
| Transaction 1 — $2.5M USDC | Lost | Not detected | Lost — completes before snapFreeze |
| Transaction 2 — ~$0.8M mixed assets | Lost | Not detected | $0 — frozen after Tx 1 |
| **Total loss** | ~$3.3M | ~$3.3M (no detection) | ~$2.5M |
| **Total preventable** | — | **$0** | **~$0.8M** |
| Recovery via on-chain negotiation | 1,032 ETH returned | — | — |

The "correctly configured trap" column assumes a modified `collect()` reading
SocketGateway's execution state with a properly mapped `spoofedMessageExecuted`
equivalent. Even then, Transaction 1 ($2.5M USDC) completes atomically before
any response fires. Only Transaction 2 (~$0.8M) would be preventable.

**The honest assessment:** The trap as deployed provides zero protection against
this specific attack because it monitors different contracts than those exploited.
This is not a failure of the trap design — it is a scope boundary. BridgeRouterGuard
was built for bridge reserve drains, not approval-draining attacks against user
wallets.

---

## 8. What the Trap Does Not Cover Here

**Wrong contract, wrong state variable.** The trap monitors bridge vault,
gateway, and router reserve infrastructure. Socket's exploit hit user wallet
approvals to an aggregator contract. These are different parts of the stack.

**Approval-draining is a different attack class.** The attack stole from
distributed user approvals across 231 wallets — distributed state that cannot
be summed via a single on-chain counter read. A velocity circuit breaker on
bridge reserves structurally cannot catch approval-draining attacks.

**Two-transaction atomic attack.** Both transactions completed within ~2 minutes,
each a single block. Transaction 1 ($2.5M) would complete before any on-chain
response even with correct instrumentation.

**No reserve to freeze.** `snapFreeze` pauses bridge reserve contracts. Even if
it fired on SocketGateway, pausing it would not reverse already-executed
`transferFrom` calls. The damage to user wallets is already done.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The Socket exploit could be partially addressed by adding a vector specifically
for aggregator contracts:

```solidity
// Hypothetical Vector 4 — Aggregator Calldata Injection
uint256 unauthorizedPerformActionCount; // counter on SocketGateway
```

This requires SocketGateway to expose a cumulative counter of unauthorized
`performAction` executions — state that does not currently exist on the contract.
Adding it requires modifying SocketGateway itself, which is not something a
trap can impose unilaterally on a live protocol.

**The deeper gap:** Approval-draining attacks target distributed state. The
correct mitigations are at the user or contract level: finite approval limits
rather than infinite approvals; per-transaction approval architecture (ERC-2612
permit pattern); pre-deploy auditing of all new routes before activation.

**The practical lesson:**

Not every DeFi attack produces a signal that a velocity circuit breaker on
protocol reserves can catch. Socket is included in this case study set
deliberately — it is the correct counterexample. Every exploit that fires the
trap is more credible because this one honestly does not. BridgeRouterGuard is
a precision tool with a defined detection surface, not a universal DeFi attack
detector.

---

## 10. Sources

- Halborn: "Explained: The Socket Protocol Hack (January 2024)" — https://halborn.com/blog/post/explained-the-socket-protocol-hack-january-2024
- CertiK: "Socket Tech Incident Analysis" — https://certik.com/resources/blog/socket-tech-incident-analysis
- Neptune Mutual: "How Was Socket Protocol Exploited?" — https://medium.com/neptune-mutual/how-was-socket-protocol-exploited-a2ce4e81587c
- Beosin: "Socket Protocol Falls Victim to Hacker's Call Injection Attack" — https://beosin.com/resources/socket-protocol-falls-victim-to-hackers-call-injection-attack
- CoinDesk: "Socket, Bungee Restart Operations After Apparent $3.3M Exploit" — https://coindesk.com/tech/2024/01/17/socket-bungee-restart-operations-after-apparent-33m-exploit
- The Block: "Socket Says It Recovered 1,032 ETH Following Bungee Exploit" — https://theblock.co/post/273964/socket-ether-recovery-bungee-exploit
- Socket Protocol official statement (Jan 16, 2024): https://twitter.com/SocketDotTech/status/1747256879731843117
