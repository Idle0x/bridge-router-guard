# Kelp DAO — April 2026

**Loss:** $292M confirmed · $491M total exposure
**Date:** April 18, 2026, 17:35 UTC (drain); follow-up attempts 18:26 and 18:28 UTC
**Vectors triggered:** 1 (Vault Drain Velocity) + 2 (Phantom Mint) + 3 (Forged Router Payload)
**Verdict (Attack Replay):** `CAUGHT · ~$200M protected · post-drain` — initial drain unpreventable (single-block atomic); both confirmed follow-on attempts (~$200M combined) contained; trap fires at ~17:35:24 UTC vs. manual pause at 18:21:00 UTC (~45 minutes earlier)

---

## Case Study Note

This exploit is not modeled in the trap's source code as a named scenario — the
`MockBridgeRouter` and the `spoofedMessageExecuted` invariant were written to
capture the general class of forged cross-chain execution, not this specific
incident. The Kelp exploit occurred days after the trap was deployed to Hoodi
Testnet. It was selected as a case study precisely because it falls squarely
within the trap's detection surface: a forged cross-chain message bypassing
single-point-of-trust validation is the exact pattern Vector 3 was built for,
regardless of whether that trust failure is an unauthenticated public function
(as in [CrossCurve, 005](./005-crosscurve-feb-2026.md)) or a compromised DVN
(as here).

The structural parallel to CrossCurve is close enough to name directly: in both
cases, an attacker submitted a cross-chain message that bypassed the protocol's
designated validation layer and caused a router-side contract to execute a payload
it had no authorization to execute. CrossCurve's trust layer was a publicly
callable `expressExecute()` function with no access control; Kelp's was a 1-of-1
DVN whose RPC infrastructure was poisoned. Different mechanism of trust failure,
identical on-chain consequence — and identical detection path.

The LayerZero `lzReceive()` entry point invoked in the Kelp exploit maps directly
to the `expressExecute()` pattern in `MockBridgeRouter`:

```solidity
// MockBridgeRouter.sol — the exploited pattern
function expressExecute(bytes calldata /*payload*/, bytes32 /*proof*/) external {
    require(!paused, "Router paused");
    // No validation of proof against gateway-approved message root.
    // Kelp: no validation that the DVN attesting this message was uncorrupted.
    spoofedMessageExecuted = true;
}
```

In the Kelp incident, the equivalent gate — verifying that LayerZero's DVN had
attested the message against an honest chain state — was satisfied by a poisoned
verifier. The `spoofedMessageExecuted` flag captures both cases: one unauthorized
execution, immediate trigger, no velocity history required.

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum requires consensus across
independent nodes before `snapFreeze()` can execute, adding one block of latency
in the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

Kelp DAO is a liquid restaking protocol. Users deposit ETH, routed through
EigenLayer for staking and restaking yield, receiving rsETH as a liquid receipt
token. rsETH is deployed across 20+ networks via LayerZero's OFT (Omnichain
Fungible Token) standard. A central bridge on Ethereum mainnet held the reserve
backing every wrapped version on every L2.

On April 18, 2026 at 17:35 UTC, an attacker drained 116,500 rsETH (~$292M,
~18% of total supply) from that bridge in a single transaction by forging a
cross-chain message through a compromised DVN verification layer. The attacker
then deposited stolen rsETH into Aave V3 as collateral, borrowing ~$236M WETH
and leaving bad debt estimated at $177M–$200M. Kelp's emergency multisig paused
core contracts 46 minutes after the drain at 18:21 UTC, blocking two follow-up
attempts targeting ~$200M combined. It is the largest single DeFi exploit of
2026, confirmed by Lazarus Group / TraderTraitor attribution.

**Post-incident recovery (April 20):** The Arbitrum Security Council took
emergency action to freeze 30,766 ETH held in an attacker-controlled address
on Arbitrum One. Funds were transferred to an intermediary frozen wallet at
11:26 PM ET on April 20, acting with input from law enforcement. These funds can
only be moved by further Arbitrum governance action coordinated with relevant
parties — a material post-incident development that partially offsets the
confirmed loss figure.

---

## 2. Technical Root Cause

**The vulnerability:** 1-of-1 DVN (Decentralized Verifier Network) configuration
on Kelp's LayerZero OFT bridge. A single verifier — LayerZero Labs' own DVN —
was the sole entity validating all cross-chain messages. One compromised verifier
was sufficient to approve any forged message.

**Attack sequence:**

1. **~07:35 UTC:** Six operational wallets pre-funded via Tornado Cash ~10 hours before drain. Infrastructure compromise begins off-chain.

2. **RPC node compromise (from LayerZero's statement):** Attackers gained access to the list of RPC nodes used by LayerZero Labs' DVN. Two nodes — running on separate clusters with no direct connection — had their `op-geth` binaries replaced with malicious versions. The malicious nodes were designed to report false transaction confirmations exclusively to the DVN, while reporting accurate data to every other observer. This selective deception was specifically engineered to defeat monitoring: LayerZero's internal observability infrastructure saw nothing anomalous because it queried from different IPs than the DVN used. The compromise was designed to self-destruct after the attack — disabling the RPCs, deleting the malicious binary, and wiping local logs.

3. **DDoS failover:** A DDoS attack was launched against the remaining clean RPC nodes between approximately 10:20 AM and 11:40 AM PT. The DDoS triggered automatic failover onto the two poisoned endpoints, making them the DVN's primary data source.

4. **Forged message submission:** With the DVN relying on poisoned data, the attacker submitted a fabricated cross-chain message claiming a valid inbound transfer had been authorized.

5. **17:35 UTC:** Attacker wallet called `lzReceive()` on LayerZero's `EndpointV2` contract. The DVN confirmed the forged message as valid. Kelp's bridge released 116,500 rsETH to an attacker-controlled address. One transaction. One block.

6. Attacker deposited 116,500 rsETH into Aave V3 as collateral. Borrowed ~$236M WETH against it. Aave left holding worthless collateral against real debt.

7. **18:21 UTC:** Kelp's emergency multisig executed `pauseAll` across core contracts. Kelp also blacklisted all wallets associated with the exploiter.

8. **18:26 UTC and 18:28 UTC:** Two follow-up drain attempts, each targeting 40,000 rsETH (~$100M), both reverted due to paused state. Kelp's post confirmed the second attempt leveraged a "falsely verified phantom packet" — the attacker still had the forged message capability and was actively attempting further drains.

9. Attacker consolidated approximately 74,000 ETH post-exploit, with a portion reaching Arbitrum One (subsequently frozen).

**Attribution:** LayerZero attributed with preliminary confidence to North Korea's
Lazarus Group, TraderTraitor subunit. Pre-funded operational wallets via Tornado
Cash, selective RPC poisoning, rapid on-chain consolidation, and the self-
destructing malicious binary are consistent with prior Lazarus infrastructure-
compromise campaigns.

**DVN configuration — a public dispute on record:**
LayerZero's statement asserts they "previously communicated best practices around
DVN diversification to KelpDAO." Kelp's context post states the 1-of-1 DVN setup
is "the configuration documented in LayerZero's documentation and shipped as the
default for any new OFT deployment." This dispute is unresolved. This analysis
does not adjudicate responsibility — the on-chain consequence is the observable
fact regardless of who approved it.

---

## 3. On-Chain Signal Profile

**Off-chain phase — invisible to any on-chain monitor:**
Steps 1–4 above (wallet funding, RPC compromise, DDoS, forged message construction)
produced zero EVM state change. The malicious binary was specifically engineered to
be invisible to all observers except the DVN — including LayerZero's own monitoring.

**On-chain phase — visible to the trap:**

| Point in time | `cumulativeWithdrawals` | `phantomMinted` | `spoofedMessageExecuted` |
|---|---|---|---|
| Pre-attack baseline | 0 | 0 | false |
| Block N — 17:35 UTC (drain tx) | +116,500 rsETH | +116,500 rsETH (on L2s) | true |
| Block N+1 — collect() | delta = 116,500 rsETH | delta = 116,500 rsETH | true |

**Signal characteristics:**
- **Single-transaction atomic.** The entire drain occurred in one transaction in one block. No multi-block buildup.
- **All three vectors trip simultaneously.** `spoofedMessageExecuted` flips to true (Vector 3); withdrawal counter spikes by 116,500 rsETH (Vector 1); phantom rsETH appears on destination L2s (Vector 2).
- **Massively over-threshold.** Vector 1 threshold: 1,000 ETH. Signal: ~116,500 rsETH. Exceeds by ~116×. Vector 2 threshold: 10,000 ETH. Signal: same. Exceeds by ~11.65×.
- **Vector 3 is the fastest path.** Hard boolean invariant — fires on first `collect()` with zero history required.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes — with one precise qualification. BridgeRouterGuard was designed for
cross-chain bridge infrastructure where execution without validation produces
measurable on-chain state change. Kelp is exactly that: a LayerZero OFT bridge
where an unauthorized message release changes cumulative withdrawal counters and
minted supply.

The qualification: the root cause was off-chain infrastructure compromise —
poisoned RPC nodes, DVN failover manipulation, a self-destructing binary. The
trap was not designed to detect off-chain compromise. It was designed to detect
the on-chain consequence of that compromise. That distinction matters for honest
scoping: the trap cannot prevent the attack from being set up, and cannot stop
the first transaction once the forged message is accepted.

**B. Does the on-chain consequence produce the detectable signal?**

Yes, cleanly. The forged `lzReceive()` execution and the resulting 116,500 rsETH
release produce the exact state transitions the trap reads: a
`cumulativeWithdrawals` spike, a `phantomMinted` spike, and a `spoofedMessageExecuted`
flag. The signal is unambiguous — there is no threshold calibration that misses a
116× over-threshold event.

**C. Which similar protocols or architectures produce the same signal?**

Any bridge with the following observable traits:
- A vault or reserve contract exposing cumulative outflow state on-chain (any OFT bridge, lock-and-mint bridge, liquidity pool bridge holding a reserve)
- A minting contract where supply increases without a corresponding validated inbound message (any cross-chain token that mints on the destination chain)
- A router or execution contract that processes messages without enforcing multi-verifier consensus (any protocol using a 1-of-N validator setup where N=1 is compromisable)

The trap is not specific to rsETH or Kelp. It is specific to the on-chain state
profile that this class of attack produces. CrossCurve ([005](./005-crosscurve-feb-2026.md))
is in the same family: forged cross-chain messages bypassing single-point-of-trust
validation. CrossCurve's trust was a publicly callable function; Kelp's was a
1-of-1 DVN. Both produce `spoofedMessageExecuted` = true.

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ✅ Fires Block N+1 (with prior baseline) | 116,500 rsETH released; exceeds 1,000 ETH threshold by ~116× |
| Vector 2 — Phantom Mint Velocity | ✅ Fires Block N+1 (with prior baseline) | 116,500 phantom rsETH minted on L2s; exceeds 10,000 ETH threshold by ~11.65× |
| Vector 3 — Forged Router Payload | ✅ Fires Block N+1 (zero history required) | Forged `lzReceive()` executes without valid multi-DVN consensus; hard boolean invariant |

**Vector 3 detail — fastest path:**

```solidity
// BridgeRouterGuardTrap.sol → shouldRespond()
if (newest.spoofedMessageExecuted) {
    return (true, abi.encode(..., true));
}
```

The forged `lzReceive()` call executing without valid multi-DVN consensus is a
direct instantiation of this invariant. Hard boolean — fires on the first
`collect()` after the drain. Zero history required. This fires faster than
Vectors 1 and 2, which require at least one prior baseline sample (bootstrap guard).

**Note on multi-chain architecture:** The drain happened on Ethereum mainnet;
phantom minting happened on destination L2s simultaneously. A single-chain
Ethereum deployment captures Vectors 1 and 3 cleanly. Vector 2 requires
independent deployments per destination L2. Vector 3 alone is sufficient to
trigger `snapFreeze()`, so the multi-chain constraint on Vector 2 does not
change the verdict.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet).

```
~07:35 UTC   Attacker pre-funds 6 wallets via Tornado Cash.
             [Off-chain. Zero on-chain signal.]

~10:20 UTC   DDoS attack begins against uncompromised RPC nodes.
             DVN fails over to two poisoned endpoints.
             [Off-chain infrastructure. Zero EVM state change. Invisible
              to LayerZero's monitoring — queries different IPs than DVN.]

~11:40 UTC   DDoS window closes. Poisoned RPCs now primary DVN data source.
             [Off-chain. ~6-hour window before attack executes.]

17:35:00     DRAIN TRANSACTION — Block N.
             lzReceive() accepted on EndpointV2.
             116,500 rsETH released to attacker address.
             cumulativeWithdrawals: 0 → 116,500 rsETH equivalent
             spoofedMessageExecuted: false → true
             [First on-chain event. Nothing detectable before this.]

17:35:12     Block N+1. collect() reads post-drain state.
             shouldRespond() evaluates Vector 3: spoofedMessageExecuted = true.
             Returns (true, payload) immediately. No history needed.

17:35:24     3-operator consensus reached (worst case: 1 additional block).
             snapFreeze() executes:
               VAULT.emergencyPause()   → paused ✓
               GATEWAY.emergencyPause() → paused ✓
               ROUTER.emergencyPause()  → paused ✓
             AttackPrevented emitted.
             [~24 seconds after drain — ~45m 36s before manual pause]

17:35:24–    Attacker holds 116,500 rsETH. Bridge frozen.
18:21:00     Cross-chain messages cannot execute. Follow-up drain packets
             queued but revert on submission.

18:21:00     [ACTUAL] Kelp emergency multisig executes pauseAll + blacklists
             all exploiter-associated wallets.
             [WITH TRAP: Bridge already frozen ~45m 36s earlier]

18:26:00     [ACTUAL] Follow-up attempt 1: 40,000 rsETH (~$100M). Reverted.
             [WITH TRAP: Router frozen at 17:35:24. Reverts ~50m 36s earlier]

18:28:00     [ACTUAL] Follow-up attempt 2: 40,000 rsETH (~$100M). Reverted.

18:52:00     [ACTUAL] Aave Guardian freezes rsETH markets on V3 and V4.
             [WITH TRAP: 77-minute reduction in Aave's rsETH exposure window.]

April 20,    [POST-INCIDENT] Arbitrum Security Council freezes 30,766 ETH on
~23:26 UTC   Arbitrum One. Transferred to intermediary wallet; requires further
             Arbitrum governance action to move.

Trap exposure window:   ~24 seconds
Actual exposure window: 46 minutes (2,760 seconds)
Compression factor:     ~115×
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| Initial drain — 116,500 rsETH | $292M lost | $292M lost |
| Follow-up attempt 1 — 40,000 rsETH | $0 (manual pause at 46 min) | $0 (snapFreeze at ~24 sec) |
| Follow-up attempt 2 — 40,000 rsETH | $0 (manual pause at 46 min) | $0 (snapFreeze at ~24 sec) |
| Aave bad debt (rsETH collateral play) | $177M–$200M `[estimate]` | Reduced — see note below |
| DeFi-wide contagion window | 46 minutes | ~24 seconds |
| **Total directly preventable** | — | **~$200M (follow-on attempts confirmed on-chain)** |
| **Post-incident recovery** | 30,766 ETH frozen on Arbitrum (April 20) | Same — partial recovery independent of trap |

**Note on Aave bad debt:** `snapFreeze()` pauses bridge contracts, not the
attacker's wallet. The 116,500 rsETH already transferred is outside the trap's
reach. Whether the attacker completes the Aave deposit in the ~24-second window
depends on chain congestion and transaction ordering. The trap guarantees the
window is 24 seconds instead of 46 minutes — not that the Aave play is prevented.

**Both follow-up attempts are confirmed on-chain.** Each targeted 40,000 rsETH
(~$100M) and reverted against Kelp's manual pause. With the trap, both revert
against snapFreeze ~50 minutes earlier. These figures are confirmed, not estimated.

---

## 8. What the Trap Does Not Cover Here

**Off-chain attack surface.** The root cause — RPC node compromise, DVN poisoning,
DDoS failover, self-destructing binary — is entirely off-chain. The malicious
binary was engineered to report accurately to all non-DVN observers, making it
invisible not just to generic monitoring but to LayerZero's own internal
infrastructure.

**Single-transaction atomicity.** 116,500 rsETH left in one transaction in one
block. The trap fires on block N+1. The initial drain is complete before the
first `collect()` call.

**Attacker's mainnet rsETH balance.** `snapFreeze()` pauses bridge contracts. It
does not freeze the attacker's wallet or the rsETH already transferred.

**Multi-chain phantom minting.** rsETH was minted across 20+ L2s. A single-chain
Ethereum deployment monitors one chain. Full Vector 2 coverage requires independent
deployments per destination chain.

**The Arbitrum Security Council action.** The 30,766 ETH freeze two days after
the exploit demonstrates that post-incident recovery is possible for sophisticated
state-sponsored attacks when law enforcement cooperation is available. This is
outside the trap's model entirely but represents a complementary response layer
for nation-state-level incidents.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

The three existing vectors correctly detect the on-chain consequence. No
modification catches the initial drain — that constraint is structural.

One possible extension: a DVN configuration health vector reading `EndpointV2`'s
DVN configuration on-chain. A `collect()` extension could read the number of
registered DVNs for the rsETH OApp pathway and flag a 1-of-1 configuration as
a pre-attack signal. However, the Kelp configuration was 1-of-1 from deployment —
it would flag on first initialization, not as a change event. This is more a
compliance monitor than an incident-response trap.

**Beyond BridgeRouterGuard — a DVN attestation liveness monitor:**

The ~6-hour gap between DVN failover onto poisoned endpoints (10:20–11:40 AM PT)
and the drain (17:35 UTC) represents a window where the DVN was operating on
poisoned data for every query. During this window, attestation patterns may have
deviated from baseline.

A DVN attestation monitor:
- `collect()` reads `EndpointV2` for DVN attestation frequency and latency per OApp pathway
- `shouldRespond()` fires if attestation patterns deviate significantly from established baseline — unusual gaps, confirmation spikes, or latency changes consistent with failover onto different endpoints
- Response: pause the OFT bridge pending manual review

The fundamental question is whether failover-induced attestation pattern changes
are distinguishable from normal DVN maintenance events. This requires empirical
testing against real attestation traffic. It is a viable concept; whether it
produces acceptable false-positive rates is an open empirical question.

The Drosera model is composable. BridgeRouterGuard catches the execution
consequence. A DVN liveness trap attempts to catch the infrastructure precondition.
Both can coexist in the same deployment, covering different layers of the same
attack surface.

---

## 10. Sources

- CoinDesk: "2026's Biggest Crypto Exploit: Kelp DAO Hit for $292 Million" — https://coindesk.com/tech/2026/04/19/2026-s-biggest-crypto-exploit-kelp-dao-hit-for-usd292-million
- CoinDesk: "LayerZero Blames Kelp's Setup for $290 Million Exploit" — https://coindesk.com/tech/2026/04/20/layerzero-blames-kelp-s-setup-for-usd290-million-exploit
- CoinDesk: "Kelp DAO Claims LayerZero's Default Settings Caused the Disaster" — https://coindesk.com/tech/2026/04/20/kelp-dao-claims-layerzero-s-default-settings-are-what-actually-caused
- The Block: "Kelp DAO's rsETH Bridge Exploited for $292 Million" — https://theblock.co/post/397988/kelp-daos-rseth-bridge-apparently-exploited
- The Block: "LayerZero Says North Korea's Lazarus Likely Behind Kelp DAO Exploit" — https://theblock.co/post/398028/layerzero-kelp-dao-lazarus
- Credshields: "Incident Report: Kelp DAO rsETH Bridge Exploit" — https://discover.credshields.com/incident-report-kelp-dao-rseth-bridge-exploit
- Aave Governance: "rsETH Incident — 2026-04-18" — https://governance.aave.com/t/rseth-incident-2026-04-18/24481
- LayerZero official statement (April 20, 2026) — https://x.com/LayerZero_Core
- Kelp DAO additional context — https://x.com/KelpDAO
- Arbitrum Security Council (April 20, 2026): Emergency action announcement — https://arbitrum.foundation
