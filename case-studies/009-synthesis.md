# 009 — One Pattern, Eight Instances

**This file does not introduce new case studies.**
It draws connections across the eight incidents already documented — patterns
that only become visible when reading them as a set, honest assessments of where
the trap design reaches its limits and why, and a grounded summary of what the
numbers actually say.

For architectural implications — what other traps would look like, how they
combine, and what the cases collectively define as a detection roadmap — see
[010-architecture-and-extensions.md](./010-architecture-and-extensions.md).

---

## The Thread

Eight exploits. Three years. One root cause: execution without validation.

The mechanisms evolved — MPC key compromise in 2023, cryptographic library bugs
and infrastructure-level RPC poisoning in 2026. The on-chain consequence did not.
In every case, a bridge released assets or minted tokens without a validated inbound
event on the source chain. That invariant is the single thread connecting all eight.

What changed was operational sophistication. The Kelp exploit required compromising
two independent RPC nodes on separate clusters, replacing their binaries with versions
that selectively deceived a single observer while reporting accurately to everyone
else, then DDoS-ing the clean nodes to force failover. That is nation-state-level
infrastructure attack. The 2023 cases required phishing a few signers or compromising
a CEO's hardware. The underlying vulnerability at the protocol layer — a single point
of trust that could be compromised — was structurally identical across all eight.

BridgeRouterGuard was designed to detect the on-chain consequence regardless of how
the off-chain attack was staged. That design choice is validated across all eight
cases: the consequence is always the same signal.

---

## What the Three Vectors Caught, and What They Didn't

### Symbol key

| Symbol | Meaning |
|---|---|
| ✅ | Fires — signal detected, threshold exceeded |
| ❌ | Does not fire — signal absent; this attack produces no output on this vector |
| ⚠️ | Signal present but below threshold, or only a partial architectural match |
| — | Out of scope — this vector monitors a different attack surface entirely |

### Verdict summary

| Case Study | Vector 1 | Vector 2 | Vector 3 | Verdict |
|---|---|---|---|---|
| [Multichain Jul 2023](./001-multichain-jul-2023.md) | ✅ Fires | ❌ No phantom mint | ❌ No router call | `CAUGHT (pre-drain)` |
| [Orbit Chain Dec 2023](./002-orbit-chain-dec-2023.md) | ✅ Fires | ❌ No phantom mint | ❌ No router call | `CAUGHT (pre-drain)` |
| [Socket Protocol Jan 2024](./003-socket-protocol-jan-2024.md) | — Wrong contracts | — No mint occurred | ⚠️ Partial match, does not fire | `PARTIAL` |
| [Force Bridge Jun 2025](./004-force-bridge-jun-2025.md) | ✅ Fires (Phase 2) | ❌ No phantom mint | ❌ No router call | `CAUGHT (pre-drain)` |
| [CrossCurve Feb 2026](./005-crosscurve-feb-2026.md) | ⚠️ Below threshold per chain | ⚠️ EYWA tokens illiquid | ✅ Fires immediately | `CAUGHT (post-drain)` |
| [IoTeX ioTube Feb 2026](./006-iotex-iotube-feb-2026.md) | ✅ Fires | ⚠️ CIOTX below threshold | ❌ Admin upgrade, not router call | `CAUGHT (post-drain)` |
| [Hyperbridge Apr 2026](./007-hyperbridge-apr-2026.md) | ⚠️ Phase 1 below threshold | ✅ Fires (Phase 2, ~51×) | ❌ Different function class | `CAUGHT (post-drain)` |
| [Kelp DAO Apr 2026](./008-kelp-dao-apr-2026.md) | ✅ Fires (~116×) | ✅ Fires (~11.65×) | ✅ Fires (zero history) | `CAUGHT (post-drain)` |

### Reading the table

No single case fires all three vectors except Kelp. That is expected — the three
vectors correspond to three different attack execution patterns, and most real
exploits trigger one primary pattern.

The `—` entries in the Socket row are the most important distinction in the table.
They are not ❌ (signal absent). They mean the attack class doesn't operate on the
contracts or state this vector monitors at all. Socket drained user wallet approvals,
not a bridge reserve. The vector simply does not apply — that is a different answer
from "the vector applies but the signal was absent."

The `⚠️` entries mark real limitations. Hyperbridge Phase 1 (245 ETH drain) is a
genuine loss that falls below the 1,000 ETH Vector 1 threshold. IoTeX's CIOTX mint
falls below the 10,000 ETH Vector 2 threshold at sub-cent token prices. These are
not edge cases — they represent the known tradeoff between static thresholds and
real-world asset diversity. Oracle-backed dynamic thresholds are the production fix.

### The two genuine gaps

**Gap 1: Sub-threshold drains.** Hyperbridge Phase 1 (245 ETH) and CrossCurve's
per-chain losses (below 1,000 ETH individually) fall below the configured thresholds.
These are real losses the trap did not prevent. Static thresholds calibrated for
large-scale bridge exploits are the correct baseline for this PoC — but a protocol
with much lower normal volume (Hyperbridge vs. Multichain) warrants tighter thresholds
calibrated to actual baseline flow.

**Gap 2: Wrong attack surface (Socket).** The Socket exploit drained user wallet
approvals, not a bridge reserve. No reserve counter moved. No phantom tokens were
minted. The trap monitors protocol-level state, not distributed user approval state
across 231 wallets. This is not a calibration problem — it is a scope boundary. A
velocity circuit breaker on bridge reserves structurally cannot catch approval-draining
attacks against individual users.

---

## The Honest Numbers

Summing the damage assessments across all eight files:

| Case | Confirmed loss | Estimated preventable |
|---|---|---|
| [Multichain Jul 2023](./001-multichain-jul-2023.md) | ~$231M | ~$200M+ (multi-bridge full deployment) |
| [Orbit Chain Dec 2023](./002-orbit-chain-dec-2023.md) | ~$81.68M | ~$60.2M |
| [Socket Protocol Jan 2024](./003-socket-protocol-jan-2024.md) | ~$3.3M (net ~$1M after recovery) | **$0** (wrong attack surface) |
| [Force Bridge Jun 2025](./004-force-bridge-jun-2025.md) | ~$3.7M | ~$2.5M+ |
| [CrossCurve Feb 2026](./005-crosscurve-feb-2026.md) | ~$2.76M | ~$1.28M+ (Arbitrum, per-chain) |
| [IoTeX ioTube Feb 2026](./006-iotex-iotube-feb-2026.md) | ~$4.4M | ~$3M–$4M |
| [Hyperbridge Apr 2026](./007-hyperbridge-apr-2026.md) | ~$2.5M revised | ~$1.7M (incentive pools, multi-chain) |
| [Kelp DAO Apr 2026](./008-kelp-dao-apr-2026.md) | ~$292M | ~$200M (follow-on attempts) |
| **Total** | **~$621M** | **~$468M+ (within documented scope)** |

**What this table is and is not:**

It is a direct read from the damage assessment section of each case study,
aggregated. Every figure has a documented basis in the relevant file.

It is not a guarantee. The "preventable" figures assume: (a) the trap was correctly
deployed and monitoring the specific contracts exploited, (b) `min_operators = 3` was
active, (c) threshold configuration was appropriate for each protocol's baseline.
Not all eight protocols expose the precise state variables the trap reads in their
exact deployed form — production deployment requires per-protocol instrumentation work.

The Socket $0 figure is included and not minimized. A case study set that only
summed its successes would not be useful.

---

## One Sentence Per Case

For anyone reading the set and wanting the bottom line:

**Multichain:** Keys were stolen; the vault drained over hours — exactly the attack
profile velocity monitoring was built for; trap fires before 80% of funds leave.

**Orbit Chain:** Four hours of probe transactions, then five parallel asset drains —
trap fires on the first bulk withdrawal and protects $60M+ that would have left over
the subsequent 90 minutes.

**Socket Protocol:** User approvals drained, not a bridge reserve — the trap
monitors the wrong state for this attack class, and that is the correct assessment to make.

**Force Bridge:** Six hours of failed privileged calls preceded the successful drain —
the only case in the set where a different trap design would have fired with zero
dollars at risk.

**CrossCurve:** One missing access control check; one publicly callable function that
shouldn't be — the cleanest Vector 3 case, and a four-year repeat of the Nomad pattern.

**IoTeX ioTube:** One compromised key; one malicious upgrade; two contracts taken over —
Vector 1 fires but Vector 2 misses CIOTX's low denomination, highlighting that static
ETH-equivalent thresholds need oracle normalization in production.

**Hyperbridge:** A missing bounds check in an MMR library lets the attacker forge any
message — 1 billion phantom tokens minted but only $237K extracted due to thin liquidity;
the trap fires on the magnitude of the mint, not the realized extraction.

**Kelp DAO:** The largest single DeFi exploit of 2026; all three vectors fire; the only
thing the trap cannot prevent is the atomic first transaction and whatever the attacker
does with already-transferred tokens — which is the honest boundary of on-chain monitoring.

---

## Why These Eight

This is not a survey of DeFi hacks. There were thousands of exploits across 2023–2026.

These eight were selected because they share a specific structural property: execution
without validation producing a measurable on-chain velocity signal in bridge reserve or
minting contracts. That is the detection surface BridgeRouterGuard was built for. Every
case in this set — including Socket, where the trap partially fails — was chosen because
it tests a specific aspect of that detection surface.

The set is bounded by the trap's design, not by the size of the loss or the profile of
the attacker. A flash loan manipulation that opens and closes in one block produces no
cross-block velocity delta to measure — that is a different problem requiring a different
detection primitive, and is not in this set. A governance attack that passes a malicious
proposal over multiple days similarly produces no velocity signal in bridge reserves. This
trap is not designed for those classes. Neither the README nor these case studies claim
otherwise.

What this set does claim: for this specific pattern family — cross-chain bridges releasing
assets or minting tokens without validated inbound events — three vectors cover the
detectable signal profile, and eight real incidents validate that coverage is real.
