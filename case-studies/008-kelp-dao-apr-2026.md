# Kelp DAO — April 2026

**Loss:** $292M confirmed · $491M total exposure  
**Date:** April 18, 2026, 17:35 UTC (drain); follow-up attempts 18:26 and 18:28 UTC  
**Root Cause:** 1-of-1 DVN RPC infrastructure compromise; selective deception and DDoS-forced failover  
**Primary Vector:** Vector 1 — Vault drain mismatch (`executedWithdrawals - validatedInboundCredits`)  
**Secondary Vectors:** Vector 2 — Gateway phantom mint mismatch (L2 minting); Vector 4 — Reserve reconciliation  
**Trap verdict:** `CAUGHT (post-drain)`

Kelp DAO is the largest single DeFi exploit of 2026 and the most technically sophisticated in this set. A nation-state-level infrastructure attack — RPC node binary replacement, selective deception, DDoS-forced failover — produced a forged `lzReceive()` call that the poisoned DVN attested as valid. The vault drained in one transaction. The trap fires on the accounting consequence, not the infrastructure compromise.

One architectural correction from earlier analysis: **Vector 3 does not fire for the Kelp DAO exploit in v3.** The poisoned DVN caused both `executedMessages` and `gatewayValidatedMessages` to increment together. The validator consumed the message and registered a structurally valid attestation, so both counters moved in sync. The mismatch between them remained zero. Vector 3 only fires when `executedMessages` exceeds `gatewayValidatedMessages`, which requires execution to bypass the validation layer entirely rather than deceive it. Vector 1 fires instead — and fires immediately — because the vault mismatch between `executedWithdrawals` and `validatedInboundCredits` is real: 116,500 rsETH released against zero corresponding source-chain lock.

---

## 1. Incident Summary

Kelp DAO is a liquid restaking protocol. Users deposit ETH, routed through EigenLayer for staking and restaking yield, receiving rsETH as a liquid receipt token. rsETH is deployed across 20+ networks via LayerZero's OFT (Omnichain Fungible Token) standard. A central bridge on Ethereum mainnet held the reserve backing every wrapped version on every L2.

On April 18, 2026 at 17:35 UTC, an attacker drained 116,500 rsETH (~$292M, ~18% of total supply) from that bridge in a single transaction by forging a cross-chain message through a compromised DVN verification layer. The attacker then deposited stolen rsETH into Aave V3 as collateral, borrowing ~$236M WETH and leaving bad debt estimated at $177M–$200M. Kelp's emergency multisig paused core contracts 46 minutes after the drain at 18:21 UTC, blocking two follow-up attempts targeting ~$200M combined. It is the largest single DeFi exploit of 2026, confirmed by Lazarus Group / TraderTraitor attribution.

**Post-incident recovery (April 20):** The Arbitrum Security Council froze 30,766 ETH held in an attacker-controlled address on Arbitrum One. The funds were transferred to an intermediary frozen wallet acting with input from law enforcement. These funds can only be moved by further Arbitrum governance action — a material post-incident development that partially offsets the confirmed loss figure.

---

## 2. Technical Root Cause

**The vulnerability:** 1-of-1 DVN (Decentralized Verifier Network) configuration on Kelp's LayerZero OFT bridge. A single verifier — LayerZero Labs' own DVN — was the sole entity validating all cross-chain messages. One compromised verifier was sufficient to approve any forged message.

**Attack sequence:**

1. **~07:35 UTC** — Six operational wallets pre-funded via Tornado Cash ~10 hours before drain. Infrastructure compromise begins off-chain.
2. **RPC node compromise (from LayerZero's statement):** Attackers gained access to the list of RPC nodes used by LayerZero Labs' DVN. Two nodes on separate clusters had their `op-geth` binaries replaced with malicious versions designed to report false transaction confirmations exclusively to the DVN while reporting accurate data to every other observer. LayerZero's internal observability infrastructure saw nothing anomalous because it queried from different IPs than the DVN used. The compromise was designed to self-destruct after the attack — disabling the RPCs, deleting the malicious binary, and wiping local logs.
3. **DDoS failover (~10:20–11:40 AM PT):** A DDoS attack was launched against the remaining clean RPC nodes. The DDoS triggered automatic failover onto the two poisoned endpoints, making them the DVN's primary data source.
4. **Forged message submission:** With the DVN relying on poisoned data, the attacker submitted a fabricated cross-chain message claiming a valid inbound transfer had been authorized.
5. **17:35 UTC** — Attacker wallet called `lzReceive()` on LayerZero's `EndpointV2`. The DVN confirmed the forged message as valid. Kelp's bridge released 116,500 rsETH to an attacker-controlled address. One transaction. One block.
6. Attacker deposited 116,500 rsETH into Aave V3 as collateral. Borrowed ~$236M WETH. Aave left holding worthless collateral against real debt.
7. **18:21 UTC** — Kelp's emergency multisig executed `pauseAll`. Kelp also blacklisted all wallets associated with the exploiter.
8. **18:26 UTC and 18:28 UTC** — Two follow-up drain attempts, each targeting 40,000 rsETH (~$100M), both reverted due to paused state. Kelp's post confirmed the second attempt leveraged a "falsely verified phantom packet" — the attacker still had forged message capability and was actively attempting further drains.
9. Attacker consolidated approximately 74,000 ETH post-exploit.

**Attribution:** LayerZero attributed with preliminary confidence to North Korea's Lazarus Group, TraderTraitor subunit. Pre-funded operational wallets via Tornado Cash, selective RPC poisoning, rapid on-chain consolidation, and the self-destructing malicious binary are consistent with prior Lazarus infrastructure-compromise campaigns.

**DVN configuration — a public dispute on record:**
LayerZero's statement asserts they "previously communicated best practices around DVN diversification to KelpDAO." Kelp's context post states the 1-of-1 DVN setup is "the configuration documented in LayerZero's documentation and shipped as the default for any new OFT deployment." This dispute is unresolved. This analysis does not adjudicate responsibility.

---

## 3. On-Chain Signal Profile

**Off-chain phase — invisible to any on-chain monitor:**
Steps 1–4 above produced zero EVM state change. The malicious binary was specifically engineered to report accurately to all non-DVN observers — including LayerZero's own monitoring. No on-chain precursor exists.

**On-chain phase — the drain (visible to the trap):**

In v3 terms, what `collect()` reads at the drain block:

| Field | Pre-drain | Post-drain block | Delta |
|---|---|---|---|
| `executedWithdrawals` | baseline | +116,500 rsETH | +116,500 rsETH |
| `validatedInboundCredits` | baseline | 0 — unchanged | 0 |
| `cumulativeMinted` | baseline | +116,500 rsETH (on L2s) | +116,500 rsETH |
| `validatedMintAuthorizations` | baseline | 0 — unchanged | 0 |
| `executedMessages` | baseline | +1 (lzReceive confirmed by poisoned DVN) | +1 |
| `gatewayValidatedMessages` | baseline | **+1** (DVN attested — poisoned but consumed) | **+1** |
| `vaultTokenBalance` | baseline | drops by 116,500 rsETH | drops |

In v3, `gatewayValidatedMessages` increments when the validator processes a message, regardless of whether the underlying attestation source was compromised. The poisoned DVN caused the Validator contract to register the message as validated because a structurally valid attestation was provided. Both `executedMessages` and `gatewayValidatedMessages` increment together. The mismatch between them remains zero. Vector 3 does not fire.

Vector 1 fires instead: `executedWithdrawals` grows by 116,500 rsETH while `validatedInboundCredits` remains at zero, as no source-chain lock event was registered. The zero-backing hard trigger activates immediately.

---

## 4. Design Envelope Assessment

This incident matches the design target of the trap. Kelp DAO operates as a LayerZero OFT bridge where cross-chain message validation authorizes reserve releases. The attack pattern — an unauthorized release changing cumulative withdrawal counters against zero validated source-chain credit — produces the exact accounting mismatch Vector 1 monitors. The root cause was an off-chain infrastructure compromise. The trap detects the on-chain consequence: 116,500 rsETH released against zero `validatedInboundCredits`.

Vector 3 (`executedMessages - gatewayValidatedMessages`) fires when execution bypasses the validation layer entirely. In CrossCurve ([005](./005-crosscurve-feb-2026.md)), `expressExecute()` was called directly without gateway interaction, leaving `gatewayValidatedMessages` at zero. In Kelp, the DVN was deceived rather than bypassed. The validation layer was consulted and produced a confirmation, causing `gatewayValidatedMessages` to increment alongside `executedMessages`. The mismatch remained zero. Vector 3 catches explicit bypass; Vector 1 catches the accounting consequence. For Kelp, Vector 1 is the correct detection path.

The signal exceeds the `VAULT_DRAIN_THRESHOLD` by ~116× independently of the zero-backing path. Any bridge architecture where a vault exposes separate withdrawal and credit counters, and where the validation layer can be deceived to produce attestations without corresponding source-chain events, produces this identical signal. The mismatch is measured against the source-chain oracle record, not the destination-chain attestation. The oracle never registered a real deposit. The credit was never created. The mismatch is permanent.

---

## 5. Trap Vector Mapping

| Vector | Status | Signal |
|---|---|---|
| Vector 1 — Vault drain mismatch | ✅ Fires immediately (same block) | 116,500 rsETH `executedWithdrawals` growth, `validatedInboundCredits = 0` → zero-backing trigger + threshold (~116×) |
| Vector 2 — Gateway phantom mint mismatch | ✅ Fires (L2 minting, same block) | 116,500 phantom rsETH minted on destination L2s; `validatedMintAuthorizations = 0` → exceeds threshold by ~11.65× |
| Vector 3 — Router unauthorized execution | ❌ Does not fire | Poisoned DVN attested the message — `gatewayValidatedMessages` incremented alongside `executedMessages`; mismatch = 0 |
| Vector 4 — Reserve reconciliation | ✅ Fires (same block, secondary) | `vaultTokenBalance` drops by 116,500 rsETH without counter movement |

**Vector 3 — poisoned validator path:**

```solidity
// In the Kelp scenario: the DVN was poisoned, not bypassed.
// validateWithdrawal() was called — the poisoned DVN produced a valid attestation.
// gatewayValidatedMessages increments alongside executedMessages.
// The mismatch between them = 0. Vector 3 does not fire.
function validateWithdrawal(uint256 amount, bytes32 proofHash) external {
    require(msg.sender == authorizedValidator, "Not authorized");
    // authorizedValidator is the poisoned DVN.
    // It calls this function with a forged proof that passes local checks.
    vault.registerInboundCredit(amount);
    gatewayValidatedMessages++;
    executedMessages++; // Both increment together.
}
```
→ [`src/mocks/core/MockMessageValidator.sol`](./src/mocks/core/MockMessageValidator.sol)

The oracle check is the layer that catches the Kelp exploit at the source-chain level. The oracle never saw a real deposit event. If the validator had checked the oracle honestly, the credit would never have been registered and the withdrawal would have failed. The poisoned DVN bypassed the oracle check along with everything else — but the consequence remains a `validatedInboundCredits = 0` state. Vector 1 catches this correctly.

**Vector 1 — zero-backing hard trigger:**

```solidity
// Kelp drain block:
//   executedWithdrawals += 116,500 rsETH
//   validatedInboundCredits = 0 (no source-chain oracle event, no credit registered)
//   execGrowth = 116,500 rsETH > 0; creditGrowth = 0
//
// Zero-backing hard trigger fires first. No threshold check needed.
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol)

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet).

```
~07:35 UTC   Attacker pre-funds 6 wallets via Tornado Cash.
             [Off-chain. Zero on-chain signal.]

~10:20 UTC   DDoS attack begins against uncompromised RPC nodes.
             DVN fails over to two poisoned endpoints.
             [Off-chain infrastructure. Zero EVM state change.]

~11:40 UTC   DDoS window closes. Poisoned RPCs primary DVN source.
             [~6-hour window before attack executes.]

17:35:00     DRAIN TRANSACTION — Block N.
             lzReceive() accepted on EndpointV2.
             Poisoned DVN attested the forged message.
             116,500 rsETH released to attacker address.

             collect() on Block N:
               executedWithdrawals: 0 → 116,500 rsETH
               validatedInboundCredits: 0 → 0 (no source-chain oracle event)
               executedMessages: baseline → baseline + 1
               gatewayValidatedMessages: baseline → baseline + 1 (poisoned attestation)
               vaultTokenBalance: drops by 116,500 rsETH

             shouldRespond() evaluates:
               Vector 3: executedMessages == gatewayValidatedMessages → mismatch = 0 → false
               Vector 1: execGrowth = 116,500 rsETH > 0; creditGrowth = 0
                         → zero-backing hard trigger fires
               Returns (true, abi.encode(116500e18, 0, 0, 0))
               [TRAP: Fires 1 block after trigger (baseline operator latency)]

17:35 + 1 block
             Operator network reaches consensus.
             snapFreeze() executes:
               vault.emergencyPause()   → paused ✓
               gateway.emergencyPause() → paused ✓
               router.emergencyPause()  → paused ✓
             AttackPrevented emitted. drainDelta = 116,500 rsETH.

17:35–18:21  Attacker holds 116,500 rsETH. Bridge frozen.
             Cross-chain follow-up packets queued but revert on submission.
             Aave deposit window: seconds vs actual 46 minutes.

18:21:00     [ACTUAL] Kelp emergency multisig executes pauseAll.
             [WITH TRAP] Bridge already frozen ~45 minutes earlier.

18:26:00     [ACTUAL] Follow-up attempt 1: 40,000 rsETH (~$100M). Reverted.
             [WITH TRAP] Reverts against snapFreeze ~50 minutes earlier.

18:28:00     [ACTUAL] Follow-up attempt 2: 40,000 rsETH (~$100M). Reverted.

18:52:00     [ACTUAL] Aave Guardian freezes rsETH markets on V3 and V4.

April 20     Arbitrum Security Council freezes 30,766 ETH on Arbitrum One.

Trap exposure window:   1–2 blocks from drain
Actual exposure window: 46 minutes (2,760 seconds)
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| Initial drain — 116,500 rsETH | $292M lost | $292M lost — completes before snapFreeze (unavoidable trigger event) |
| Follow-up attempt 1 — 40,000 rsETH | $0 (manual pause at 46 min) | $0 (snapFreeze within blocks) |
| Follow-up attempt 2 — 40,000 rsETH | $0 (manual pause at 46 min) | $0 (snapFreeze within blocks) |
| Aave bad debt (rsETH collateral play) | $177M–$200M `[estimate]` | Reduced — see note |
| DeFi-wide contagion window | 46 minutes | Seconds to one block |
| **Total directly preventable** | — | **~$200M (follow-on attempts, confirmed on-chain)** |
| **Post-incident recovery** | 30,766 ETH frozen on Arbitrum (April 20) | Same — partial recovery independent of trap |

The two confirmed follow-on attempts each targeted 40,000 rsETH (~$100M). Both reverted against Kelp's manual pause 46 minutes after the drain. With the trap, both revert within blocks of the initial drain. These figures are confirmed on-chain.

`snapFreeze()` pauses bridge contracts, not the attacker's wallet. The 116,500 rsETH already transferred is outside the trap's authority. Whether the attacker could complete the Aave deposit in the window between the drain and `snapFreeze()` depends on transaction ordering and block space. The trap compresses the window from 46 minutes to seconds; what the attacker accomplishes in that window is structurally uncertain.

The Arbitrum Security Council action demonstrates that post-incident governance recovery is possible for sophisticated state-sponsored attacks when law enforcement cooperation is available. This is outside the trap's operational model.

---

## 8. What the Trap Does Not Cover Here

**Off-chain attack surface.** The root cause — RPC node compromise, DVN poisoning, DDoS failover, self-destructing binary — is entirely off-chain. The malicious binary was engineered to report accurately to all non-DVN observers, making it invisible to standard monitoring.

**The initial drain (trigger event).** 116,500 rsETH left in one transaction in one block. The trap fires on that block. A reactive monitor cannot stop the transaction that produces its own trigger.

**Vector 3 does not fire.** The poisoned DVN deceived the validator rather than bypassing it. Both `executedMessages` and `gatewayValidatedMessages` incremented together. The router mismatch stayed at zero. Vector 1 is the correct detection path.

**Attacker's mainnet rsETH balance.** `snapFreeze()` pauses bridge contracts. It does not freeze the attacker's wallet or reverse completed transfers.

**Multi-chain phantom minting.** rsETH was minted across 20+ L2s. A single Ethereum-side deployment captures Vectors 1 and 4. Full Vector 2 coverage requires independent deployments per destination chain.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**
The vectors that fire (1, 2, 4) correctly detect the on-chain consequence. No modification catches the initial drain — that constraint is structural. A DVN configuration health vector reading `EndpointV2`'s registered DVN count could flag a 1-of-1 configuration as a pre-existing risk condition, but the Kelp configuration was 1-of-1 from deployment. It would flag on initialization, not as a change event. This functions as a compliance monitor rather than an incident-response trap.

**Beyond BridgeRouterGuard:**
The ~6-hour gap between DVN failover onto poisoned endpoints and the drain represents a window where the DVN operated on falsified data. A separate trap monitoring `EndpointV2` for DVN attestation frequency and latency per OApp pathway — firing if patterns deviate significantly from baseline in ways consistent with endpoint failover — would target the infrastructure precondition rather than the execution consequence. Whether failover-induced attestation changes are distinguishable from normal DVN maintenance requires empirical testing against real attestation traffic. This concept is explored in [010 — Architecture and Extensions](./010-architecture-and-extensions.md#trap-4--dvn-attestation-liveness-monitor).

The downstream Aave-style consequence (stolen collateral concentration in a lending pool) is independently detectable. The [`PositionMonitorTrap`](./src/concepts/PositionMonitorTrap.sol) demonstrates this pattern. See [010](./010-architecture-and-extensions.md#trap-3--position-monitor) for the design and validation tests.

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
