# 010 — Architecture and Extensions

**What BridgeRouterGuard monitors, why it is designed as it is,
where it reaches its limits, and what other trap designs would look like.**

This file draws on the eight case studies collectively. The observations here
are grounded in what the cases actually revealed — not speculation about future
attacks, but architectural implications of documented ones.

---

## Why the Trap Is Designed the Way It Is

BridgeRouterGuard monitors three specific state variables:

- `cumulativeWithdrawals` — cumulative outflow from the bridge reserve vault
- `phantomMinted` — cumulative supply of tokens minted without a corresponding validated lock
- `spoofedMessageExecuted` — boolean flag indicating an unauthorized router execution

These three were chosen because they are the observable on-chain consequences of
execution without validation — the invariant that all eight case studies share.
The design choices behind them are not arbitrary.

**Why cumulative counters, not event logs:**
Cumulative counters are readable as pure view calls. `collect()` is a view function
— it cannot process event logs or access historical state. Monitoring cumulative
state rather than individual transactions means the trap naturally aggregates across
whatever execution pattern the attacker uses: single large drain, chunked drains,
parallel multi-asset drains. All of them accumulate into the same counter.

**Why a velocity window rather than a single-block check:**
Single-block thresholds catch burst attacks but miss slow-drain attacks. Window-based
velocity detection catches both: a single massive transaction triggers the burst
detector; a series of sub-threshold transactions accumulates in the window. The
7-block window was chosen to balance detection latency against false-positive risk.
Shorter windows are more sensitive but more susceptible to noise. Longer windows
allow more damage before firing.

**Why three vectors rather than one:**
Each vector corresponds to a different execution path for the same underlying attack.
Vector 1 fires when the attacker drains a reserve (Multichain, Orbit Chain, Force
Bridge). Vector 2 fires when the attacker mints unbacked tokens (IoTeX, Hyperbridge,
Kelp). Vector 3 fires when the attacker executes a router call without gateway
validation (CrossCurve, Kelp). A single-vector design would miss any case where
the attack follows a different execution path. The three vectors together cover
the full attack surface of the execution-without-validation pattern class.

**Why Vector 3 requires no history:**
A forged router execution is a hard invariant violation — there is no legitimate
scenario where `spoofedMessageExecuted` is true. A single unauthorized execution
is one too many. Velocity history is irrelevant. This is the only case in the
trap where the response fires with zero prior baseline.

**Why the trap does not fire in-line with user transactions:**
The trap operates as a shadow monitor via Drosera's operator network, not as a
contract modifier or reentrancy guard. In-line monitoring adds gas overhead to
every user transaction and creates a dependency — if the monitor reverts, the user
transaction reverts. Out-of-band shadow monitoring adds zero gas overhead to normal
operations and can fail independently without affecting users.

---

## Where the Trap Reaches Its Limits

The eight case studies reveal four structural limits. These are not design flaws —
they are the known boundaries of a velocity-based out-of-band monitor.

### 1. The first atomic transaction

The trap fires on block N+1 after the drain. A single-block atomic attack completes
before the first `collect()` call. This constraint is fundamental: on-chain monitors
are reactive. The Kelp initial drain ($292M), the CrossCurve first chain drain
($1.3M), and Hyperbridge Phase 2 mint ($237K realized) are all examples. The trap
limits the damage window — it does not eliminate it.

The relevant question is not "can the trap stop the first transaction" but "how much
damage occurs after the first transaction, and can the trap stop that?" For Multichain
and Orbit Chain, the answer is most of the damage — because those attacks were
progressive, multi-transaction drains where the first transaction was far from the
last. For Kelp, the follow-on damage ($200M in two confirmed follow-up attempts)
was fully stopped.

### 2. Sub-threshold drains

Static thresholds calibrated for large-scale bridge exploits create a gap at the
bottom. Hyperbridge Phase 1 (245 ETH) and CrossCurve's per-chain losses (below
1,000 ETH individually) are real losses that fall below the configured thresholds.

This is not a trap failure — it is a threshold configuration problem. A production
deployment monitoring Hyperbridge should use thresholds calibrated to Hyperbridge's
baseline flow, not Multichain's. Dynamic thresholds derived from rolling baselines
automatically right-size to each protocol's actual traffic. This is the upgrade
documented in What's Next.

### 3. Wrong attack surface (Socket)

The Socket exploit drained distributed user wallet approvals, not a bridge reserve.
No single readable counter captures this signal. This is a scope boundary, not a
calibration problem. The trap was not designed for approval-draining attacks, and
no threshold adjustment would change that.

The Socket case is included in this analysis precisely because it is the correct
counterexample. A case study set that only includes successes is not useful.

### 4. Off-chain attack surface

MPC key compromise (Multichain), deployer key compromise (Force Bridge), Validator
key compromise (IoTeX), RPC poisoning with binary replacement (Kelp) — all of these
are off-chain before any transaction hits the chain. The trap cannot detect the
off-chain precondition; it detects the on-chain consequence. Six cases out of eight
have off-chain root causes. The trap is designed for the consequence, not the cause.

---

## What Other Traps Would Look Like

Four distinct trap concepts emerge from reading the eight section-9s as a group.
Each addresses a gap that BridgeRouterGuard does not cover. None of these are
speculative — each has at least two case studies providing independent evidence
of need.

### Trap 2 — Contract state ownership monitor

**Evidence from:** [IoTeX ioTube (006)](./006-iotex-iotube-feb-2026.md) and
[Hyperbridge (007)](./007-hyperbridge-apr-2026.md)

Two independent exploits via different root causes — a compromised upgrade key and a
forged MMR proof — both produced the same intermediate step: admin control over a
bridge token contract was transferred to an attacker address. Both section-9s
independently arrived at the same proposed monitor.

**What it would monitor:**

```
collect():        reads owner() on each monitored bridge token contract
shouldRespond():  fires if owner changes to any address outside known-authorized set
response:         pause minting authority on the affected token contract
```

**Why it fires earlier than BridgeRouterGuard:**
The ownership transfer happens in the same block as (or one block before) the
phantom mint. A BridgeRouterGuard deployment fires on the mint. An ownership
monitor fires on the transfer — before the first mint is submitted.

**The constraint:**
The trap must know the expected owner address. Legitimate upgrades require a brief
pause for human review. For protocols that upgrade infrequently, this tradeoff is
worth taking. The convergence of two independent cases on the same concept is the
argument for implementing it.

### Trap 3 — Pre-attack window monitor

**Evidence from:** [Orbit Chain (002)](./002-orbit-chain-dec-2023.md) and
[Force Bridge (004)](./004-force-bridge-jun-2025.md)

Orbit Chain had a 4-hour structured probe window (micro-transactions confirming
key access per asset) before any bulk drain. Force Bridge had a 6-hour window of
failed privileged function calls before the successful drain. Both produced
observable on-chain signals well before any funds moved.

Force Bridge is the stronger case: the failed attempts were the exact same restricted
function calls that later succeeded — actual drain attempts that reverted, not just
probes. Six hours of failed `unlock()` calls from a non-authorized address is a
specific, distinguishable signal.

**What it would monitor (Force Bridge variant):**

```
collect():        reads count of failed calls to restricted functions
                  (unlock(), release(), withdraw() with onlyOwner guard)
                  from addresses outside the authorized signer set
shouldRespond():  fires if N failed privileged calls occur within M blocks
                  from a non-authorized address
response:         pause the bridge and alert operators
```

**Why it is higher value than BridgeRouterGuard for this case:**
Every dollar of the Force Bridge $3.7M loss is preventable if the pause fires
during the failed-attempt window rather than after the successful drain. With
BridgeRouterGuard, ~$1M is lost before the threshold is crossed. With a pre-attack
window monitor, $0 would be lost — the bridge pauses during failed attempts.

**The implementation constraint:**
Most bridge contracts revert silently on unauthorized calls rather than emitting
events or incrementing counters. Exposing a failed-attempt counter requires
modifying the bridge contract or running an event-log monitor off-chain. The
concept is viable; the implementation requires coordination with the protocol.

### Trap 4 — Lifecycle-aware threshold adapter

**Evidence from:** [Force Bridge (004)](./004-force-bridge-jun-2025.md) specifically;
applies across all eight.

Force Bridge was attacked one day after announcing its sunset. The wind-down
announcement was the attack trigger — remaining TVL became a concentrated target
the moment normal user withdrawals began. A bridge in wind-down mode processes
minimal flow at lower volume. Static thresholds calibrated for normal operation
are systematically too high for a protocol in this state.

This is not a distinct trap — it is a configuration practice. Any deployment should
reassess thresholds whenever the protocol's operational posture changes materially:
launch, wind-down, major TVL growth or decline. A threshold appropriate for a
bridge processing $500M/day is not appropriate for the same bridge processing $5M/day.

**The mechanism:**
Dynamic thresholds tracking rolling 7-day average outflow automatically right-size:
- During normal operation: threshold reflects actual baseline, avoiding false positives
- During wind-down: threshold tightens as volume decreases, becoming more sensitive exactly when the remaining TVL is most concentrated

This is the oracle-backed dynamic threshold upgrade documented in the README's
What's Next section. Force Bridge is its clearest proof of need.

### Trap 5 — DVN attestation liveness monitor

**Evidence from:** [Kelp DAO (008)](./008-kelp-dao-apr-2026.md) specifically

The Kelp attack produced a ~6-hour window between DVN failover onto poisoned
endpoints and the actual drain. During this window, the DVN was making decisions
based on poisoned data for every query. Whether the resulting attestation pattern
was detectably anomalous relative to baseline depends on empirical data.

**What it would monitor:**

```
collect():        reads EndpointV2 for DVN attestation frequency and latency
                  per OApp pathway
shouldRespond():  fires if patterns deviate significantly from baseline —
                  unusual gaps, confirmation spikes, latency changes
                  consistent with failover onto different endpoints
response:         pause the OFT bridge pending manual review
```

**The honest uncertainty:**
Whether failover-induced attestation pattern changes are distinguishable from
normal DVN maintenance events requires empirical testing against real attestation
traffic. This is the most speculative of the four extensions. It is worth
describing precisely because the Kelp case provides the most severe evidence of
what happens when DVN infrastructure is compromised — but the detection mechanism
requires validation before claiming it would reliably catch this class.

---

## How These Traps Work Together

A realistic production security stack for a major OFT bridge, informed by the
eight cases, might combine:

**Layer 1 — BridgeRouterGuard (this implementation)**
Fires on: reserve drainage, phantom minting, unauthorized router execution
Timing: block N+1 after the drain or mint
Covers: Multichain, Orbit Chain, Force Bridge (Phase 2), CrossCurve, IoTeX (Vector 1), Hyperbridge (Phase 2), Kelp

**Layer 2 — Contract state ownership monitor**
Fires on: admin transfer to unauthorized address
Timing: same block as the ownership transfer — before any phantom mint is submitted
Covers: IoTeX (upgrade → takeover), Hyperbridge (forged admin grant)

**Layer 3 — Pre-attack window monitor**
Fires on: N failed restricted function calls from non-authorized address within M blocks
Timing: during the attacker's preparation phase, before any funds move
Covers: Force Bridge (6-hour failed attempt window), Orbit Chain (4-hour probe window)

**Layer 4 — DVN attestation liveness monitor** (higher uncertainty, higher value if it works)
Fires on: statistical deviation from baseline attestation patterns consistent with failover
Timing: during the infrastructure precondition phase, before any transaction
Covers: Kelp (6-hour DVN poisoning window) — if the signal is distinguishable

**What each layer covers in the attack chain:**

```
Off-chain preparation     → Layer 4 (DVN), Layer 3 (failed calls)
Intermediate takeover     → Layer 2 (ownership monitor)
First on-chain drain/mint → Layer 1 (BridgeRouterGuard) — always the backstop
Follow-on damage          → Layer 1 (already frozen)
```

No combination of layers catches the off-chain key compromise before any
transaction hits the chain. That boundary is structural. What the combination
provides is defense-in-depth that fires at multiple points in the attack chain
rather than only after the first successful drain.

Layer 1 is the implementation that exists today. Layers 2–4 are what the eight
cases collectively define as the natural extension of the same Drosera pattern
to earlier points in the attack chain. The composability of the Drosera model —
same operator network, same consensus mechanism, different `collect()` and
`shouldRespond()` per trap — means any of these can be added without changing the
existing deployment.

---

## The Composability Point

Every trap in the Drosera model has the same structure:
- `collect()` — reads specific on-chain state (view function)
- `shouldRespond()` — evaluates invariants against that state (pure function)
- A response function — executes on operator consensus

BridgeRouterGuard is one instantiation of this pattern. It monitors three specific
state variables on three specific contracts and calls `snapFreeze()` on consensus.

A different protocol with different risk surfaces defines a different `collect()` —
reading different on-chain state, applying different invariants, calling a different
response function. The operator network, consensus mechanism, and governance around
response authorization (operator allowlist, cooldown, two-step ownership) remain
the same.

What changes per deployment:
- Which contracts `collect()` reads
- Which invariants `shouldRespond()` applies
- What response function executes on consensus

The eight case studies collectively map the detection surface of one specific
implementation. The four extension concepts sketch what adjacent implementations
would look like. None of these are hypothetical architectures — they apply the
same pattern to different on-chain state that the cases showed is observable and
meaningful.
