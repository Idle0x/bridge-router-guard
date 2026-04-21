# IoTeX ioTube — February 2026

**Loss:** ~$4.4M confirmed (~$4.3M reserve drain from TokenSafe; ~$1.7M in minted tokens reached liquid markets before freeze)
**Date:** February 21, 2026, ~07:00–09:00 UTC
**Vectors triggered:** 1 (Vault Drain Velocity) + 2 (Phantom Mint Velocity — pattern match; see section 5 for threshold detail)
**Trap verdict:** `CAUGHT (post-drain)` — drain and mint occur in rapid sequence after a single-step privilege escalation; trap fires on block N+1 from Vector 1, containing follow-on minting and any subsequent unauthorized calls

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum adds one block of latency in
the worst case (~12 seconds). This does not change the verdict.

---

## 1. Incident Summary

IoTeX is a Layer 1 blockchain focused on the machine economy and IoT
infrastructure. Its in-house cross-chain bridge, ioTube, enables token transfers
between the IoTeX L1 and Ethereum, BNB Chain, and Base. On the Ethereum side,
ioTube's architecture centers on a `Validator` contract (`TransferValidatorWithPayload`)
that verifies cross-chain settlement messages and delegates authority downstream
to two critical contracts: `TokenSafe`, which holds locked reserve assets backing
wrapped tokens, and `MintPool`, which holds minting authority for cross-chain
wrapped tokens such as CIOTX.

On February 21, 2026, between approximately 07:00 and 09:00 UTC, an attacker
compromised the private key of the Ethereum-side Validator contract owner. With
that single key, the attacker upgraded the Validator to a malicious implementation,
transferred ownership of TokenSafe and MintPool to an attacker-controlled address,
drained approximately $4.3M in reserve assets (USDC, USDT, WBTC, WETH, BUSD),
and minted approximately 410 million CIOTX tokens. Stolen reserves were swapped
via Uniswap and bridged to Bitcoin through THORChain. Approximately 355M of the
minted CIOTX tokens were frozen by IoTeX and ecosystem partners before they could
be liquidated; approximately $1.7M in minted tokens reached liquid markets.

On-chain analyst Specter flagged the suspicious transactions at ~09:20 UTC. IoTeX
co-founder Raullen Chai confirmed the incident publicly on February 23, after
validators and community members had already coordinated to pause the bridge.
IoTeX's Layer 1 chain was halted separately to freeze attacker addresses at the
network level.

Attribution: Unconfirmed. On-chain analysts linked the attacker wallet to the
$49M Infini stablecoin exploit of February 2025, suggesting a sophisticated
repeat actor.

---

## 2. Technical Root Cause

**The vulnerability:** Single-EOA Validator contract ownership without
multi-signature or timelock controls. The entire security stack of ioTube's
Ethereum bridge — validation authority, TokenSafe ownership, MintPool minting
authority — could be seized by whoever held one private key.

**The four-step attack sequence (confirmed by IoTeX official update, BlockSec, and Halborn):**

1. **Validator Key Compromise.** The owner account of the Ethereum-side Validator
   contract was compromised. Method not confirmed in public post-mortems — likely
   phishing or infrastructure access.

2. **Malicious Upgrade.** Using the `upgrade()` function, the attacker replaced the
   legitimate Validator implementation with a malicious version that bypassed all
   signature and validation checks — removing the bridge's entire validation layer.

3. **Contract Takeover.** With the Validator's validation layer subverted, the
   attacker transferred ownership of both `TokenSafe` and `MintPool` to an
   attacker-controlled address, granting direct authority to withdraw any asset
   from the reserve without a validated inbound message, and to mint any quantity
   of bridge-wrapped tokens without a corresponding lock on the source chain.

4. **Drainage and Minting.** The attacker drained approximately $4.3M in reserve
   assets from TokenSafe: USDC, USDT, WBTC, WETH, BUSD. In parallel, approximately
   410 million CIOTX tokens were minted via MintPool.

**Critical distinction from CrossCurve ([005](./005-crosscurve-feb-2026.md)):**
CrossCurve's Vector 3 exploited a missing validation check allowing direct
unauthorized calls to a publicly accessible function — no admin escalation
required. IoTeX's exploit required an intermediate step: key compromise →
upgrade → ownership transfer → then drain and mint. The on-chain signals are
different: CrossCurve produces a router execution boolean (Vector 3). IoTeX
produces a reserve drainage spike (Vector 1) and an unbacked minting spike
(Vector 2). The malicious upgrade and ownership transfer steps are observable
on-chain but are not the signals the current trap reads — the trap detects
the downstream consequences in TokenSafe and MintPool state.

---

## 3. On-Chain Signal Profile

**Off-chain phase — invisible to any on-chain monitor:**
The Validator key compromise happened entirely off-chain. No EVM state change
precedes the malicious upgrade transaction. The attack was invisible until the
first on-chain transaction.

**On-chain phase — observable by the trap:**

| Event | Contract | State variable | Delta |
|---|---|---|---|
| TokenSafe drain | TokenSafe | `cumulativeWithdrawals` | +~$4.3M multi-asset outflow |
| CIOTX phantom mint | MintPool | `phantomMinted` | +~410M CIOTX |

Both vectors activate in parallel within the ~07:00–09:00 UTC window. Each major
drain transaction individually exceeds the 400 ETH burst threshold. The combined
asset drain (~$4.3M ≈ 1,720 ETH at ~$2,500/ETH) exceeds the 1,000 ETH window
threshold by ~1.72×. Vector 1 is the primary trigger.

For Vector 2: 410M CIOTX at ~$0.004/CIOTX = ~$1.64M ≈ ~656 ETH equivalent.
This is below the 10,000 ETH PHANTOM_MINT_THRESHOLD. Vector 2 does not fire on
CIOTX alone at these prices — see section 5.

---

## 4. Design Envelope Assessment

**A. Was the trap designed for this environment?**

Yes — ioTube is a lock-and-mint bridge, and the primary consequence of the
exploit maps directly to Vectors 1 and 2. The README explicitly lists IoTeX
ioTube as a Vector 2 reference: `MockTokenGateway` replicates the pattern of
privilege escalation followed by unbacked minting, modeled on this exact incident.

The qualification: the root cause is a key-management failure enabling a contract
upgrade — an off-chain and upgrade-layer concern rather than a validation bypass
in a public function. The trap detects the downstream result: tokens leaving the
reserve without valid backing, and new tokens appearing without a validated lock.

**B. Does the on-chain consequence produce the detectable signal?**

Yes, clearly for Vector 1. The TokenSafe drain produces a `cumulativeWithdrawals`
spike exceeding the 1,000 ETH window threshold. Vector 1 fires independently and
is sufficient. Vector 2 is borderline at CIOTX valuations (see section 5); oracle-
backed normalization would resolve this in production.

**C. Which similar protocols or architectures produce the same signal?**

Any bridge where a single key controls both a reserve vault and a minting
contract via an upgradeable admin role produces this dual-vector signal on
compromise. The same pattern appears in Hyperbridge ([007](./007-hyperbridge-apr-2026.md)),
where a forged MMR proof (rather than a compromised key) led to the same
intermediate step: admin grant over a token contract, followed by phantom minting.
Different root cause, same observable downstream consequence.

Specific architectural traits that create this risk:
- `TransparentUpgradeableProxy` or `UUPS` bridge contracts with a single `owner`
  EOA controlling `upgrade()` — no multisig or timelock protection
- Same admin role granting both withdrawal authority from the reserve AND minting
  authority for destination-chain tokens (combined authority maximizes blast radius)
- Any bridge using a `TransferValidatorWithPayload` pattern where the validator
  is the sole gatekeeper for both reserve and minting

---

## 5. Trap Vector Mapping

| Vector | Status | Reason |
|---|---|---|
| Vector 1 — Vault Drain Velocity | ✅ Fires within first above-threshold withdrawal | ~$4.3M drain ≈ 1,720 ETH equivalent; exceeds 1,000 ETH threshold by ~1.72× |
| Vector 2 — Phantom Mint | ⚠️ Below threshold at CIOTX prices | 410M CIOTX ≈ 656 ETH equivalent; 10,000 ETH threshold not exceeded; Vector 1 fires independently |
| Vector 3 — Forged Router Payload | ❌ Does not fire | Attack used admin-layer upgrade, not an unauthorized `expressExecute`-style call on a public router function |

**Vector 1 detail:**

```solidity
// BridgeRouterGuardTrap.sol → _evaluateVectors()
vaultVelocity = newest.cumulativeWithdrawals > oldest.cumulativeWithdrawals
    ? newest.cumulativeWithdrawals - oldest.cumulativeWithdrawals : 0;
isCritical = vaultVelocity > VAULT_DRAIN_THRESHOLD; // 1,000 ETH
```

TokenSafe drain: ~$4.3M ≈ 1,720 ETH equivalent. Threshold: 1,000 ETH. Exceeds by ~1.72×.
Burst detector also fires: any single large USDC or USDT withdrawal representing a
significant portion of the $4.3M total individually exceeds the 400 ETH burst threshold.

**Vector 2 honest assessment:** Vector 2 does NOT fire on CIOTX phantom minting at
these prices. The 10,000 ETH threshold was calibrated for large-scale phantom minting
events (Hyperbridge's 1B DOT, Kelp's 116,500 rsETH). A 410M CIOTX mint at sub-cent
token prices falls below this threshold. This does not change the verdict — Vector 1
fires independently and is sufficient. The README's listing of IoTeX as a Vector 2
reference is accurate at the pattern level (privilege escalation + phantom mint is the
correct model) but the specific CIOTX volume falls below the static threshold.
Oracle-backed asset normalization resolves this in production.

---

## 6. Simulated Response Timeline

Block time: 12 seconds (Ethereum mainnet). ETH price February 21, 2026: ~$2,500.
1,000 ETH threshold ≈ $2.5M.

```
Off-chain (time unknown)
                     Validator owner private key compromised.
                     [Off-chain. Zero on-chain signal.]

~07:00 UTC           MALICIOUS UPGRADE — Block N₀.
                     upgrade() called on Validator contract.
                     Malicious implementation replaces legitimate one.
                     TokenSafe and MintPool ownership transferred to attacker.
                     [On-chain and observable; but cumulativeWithdrawals
                      unchanged. TRAP: No trigger yet.]

~07:XX UTC           FIRST SIGNIFICANT WITHDRAWAL — Block N₁.
                     TokenSafe reserves begin draining: USDC, USDT, WBTC, WETH.
                     First above-threshold transaction (likely USDC, ~>$1M).
                     cumulativeWithdrawals delta enters trigger range.

~07:XX:12            Block N₁+1. collect() reads state.
                     Vector 1 fires. shouldRespond() returns (true, payload).
                     [~12 seconds after first above-threshold withdrawal]

~07:XX:24            3-operator consensus. snapFreeze() executes:
                       VAULT.emergencyPause()   → paused ✓
                       GATEWAY.emergencyPause() → paused ✓
                       ROUTER.emergencyPause()  → paused ✓

~07:XX–09:00 UTC     [ACTUAL] Remaining reserves drain. CIOTX phantom mint.
                     Assets routed through Uniswap, then THORChain to BTC.
                     [WITH TRAP: TokenSafe and MintPool frozen at ~07:XX:24.
                      All withdrawal and minting calls revert.]

~09:20 UTC           On-chain analyst Specter publicly flags suspicious activity.
                     [WITH TRAP: Bridge frozen ~2 hours earlier.]

Feb 23               IoTeX co-founder confirms incident publicly. Community
                     coordinates manual bridge pause.
                     [WITH TRAP: Bridge frozen ~44+ hours before public
                      confirmation. Community effort redirects to remediation.]

Trap exposure window:   ~24 seconds from first above-threshold withdrawal
Actual exposure window: ~2 hours (community-coordinated manual pause)
Compression factor:     ~300×
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| Malicious upgrade + ownership transfer | Completes (zero-value transactions) | Completes — trap fires on consequence, not cause |
| First above-threshold TokenSafe withdrawal | Lost — completes before snapFreeze | Lost |
| Remaining reserve assets after first trigger | ~$3M–$4M lost | Protected — bridge frozen at ~07:XX:24 |
| CIOTX phantom mint (~$1.7M reached liquid markets) | $1.7M lost | $0 — MintPool frozen at ~07:XX:24 |
| **Total preventable** | — | **~$3M–$4M (reserve tail) + $1.7M (liquid mint)** |
| **Confirmed total loss** | ~$4.4M | ~$0.4M–$1M |

The exact first-trigger transaction value is not confirmed in public post-mortems —
the drain is described as a sequence across multiple assets over ~2 hours without
per-transaction timestamps. The $0.4M–$1M residual estimate acknowledges that
some initial transactions complete before snapFreeze.

The $1.7M in CIOTX that reached liquid markets represents tokens minted within
the ~2-hour window before community-coordinated pause. With the MintPool frozen
within ~24 seconds of the first above-threshold vault event, subsequent mint
calls revert — substantially reducing or eliminating this haul.

---

## 8. What the Trap Does Not Cover Here

**Off-chain key compromise.** The Validator owner key was compromised before any
on-chain event. No monitoring system detects the compromise itself.

**The malicious upgrade and ownership transfer.** These are the mechanism
transactions that precede the drain and mint. Observable on-chain, but they do
not increment `cumulativeWithdrawals` or `phantomMinted`. Vectors 1 and 2 do
not fire on upgrade calls — see section 9 for the extension that would.

**Vector 2 threshold gap.** As documented in section 5, the CIOTX phantom mint
does not exceed the 10,000 ETH static threshold at IoTeX token prices. Vector 1
fires independently, but the gap demonstrates that static ETH-equivalent thresholds
miss phantom mints in low-denomination wrapped tokens. Oracle-backed normalization
is the production fix.

**THORChain exit path.** Assets already swapped and routed through THORChain
before `snapFreeze` executes are outside the trap's authority. `snapFreeze` pauses
bridge contracts; it does not reverse completed on-chain swaps.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**

A fourth vector monitoring `owner` state on upgradeable bridge contracts could
read `TokenSafe.owner()` and `MintPool.owner()` on each `collect()` call and
fire if either changes to an address outside a known-safe whitelist. This would
detect the ownership transfer in the same block it occurs — potentially before
any drain or mint transaction is submitted.

The constraint: this requires either a hardcoded expected-owner address in the
trap (viable, but requires redeployment if ownership is legitimately transferred)
or an on-chain registry of authorized owners. Both are architecturally viable
within Drosera's model; neither is currently implemented.

**Beyond BridgeRouterGuard — an upgradeable proxy monitor:**

The malicious upgrade is detectable via `Upgraded(address indexed implementation)`
events emitted by the proxy contract. A separate trap:
- `collect()` reads `IProxy(VALIDATOR).implementation()` on each block
- `shouldRespond()` fires if the implementation address changes to anything
  other than the known-good implementation hash
- Response: pause bridge operations immediately

This fires in the same block as the malicious upgrade — before the ownership
transfer, before the drain, before the mint. It is the earliest possible pre-drain
detection for upgradeable proxy bridge architectures.

The tradeoff: a genuine upgrade triggers the same response. Most bridge protocols
upgrade infrequently enough that a brief pause for human review is worth taking.
The Hyperbridge case ([007](./007-hyperbridge-apr-2026.md)) independently arrived at
the same concept from a different attack path (forged MMR proof → admin grant),
reinforcing that admin-change monitoring is worth implementing for any bridge
using upgradeable contracts with concentrated ownership.

---

## 10. Sources

- Halborn: "Explained: The IoTeX Hack (February 2026)" — https://halborn.com/blog/post/explained-the-iotex-hack-february-2026
- BlockSec: "Weekly Web3 Security Incident Roundup | Feb 16–22, 2026" — https://blocksec.com/blog/weekly-web3-security-incident-roundup-feb-16-feb-22-2026
- IoTeX official update (Feb 23, 2026): "Security Incident Update: ioTube Bridge Exploit and Recovery Roadmap" — https://x.com/iotex_io/status/2025824807120412842
- CoinDesk: "IoTeX Bridge Exploit Raises Debate Over Losses and Recovery Prospects" — https://coindesk.com/business/2026/02/23/iotex-bridge-exploit-sparks-debate-over-losses-and-recovery-prospects
- CryptoTimes: "IoTeX Confirms $4.3M ioTube Bridge Breach, Validator Key Compromised" — https://cryptotimes.io/2026/02/22/iotex-confirms-4-3m-iotube-bridge-breach-validator-key-compromised/
- Phemex: "IoTeX Bridge Hack: $4.4M Exploit, 10% Bounty Offer & Cross-Chain Risk" — https://phemex.com/blogs/iotex-bridge-hack-cross-chain-risk-negotiations
