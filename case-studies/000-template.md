# [Protocol Name] — [Month Year]

**Loss:** $[X]M confirmed · $[Y]M total exposure (if follow-on losses existed)
**Date:** [Full date, UTC where known]
**Vectors triggered:** [1 / 2 / 3 / combination]
**Trap verdict:** [one of the following]
  - `CAUGHT (pre-drain)`: trap fires before the majority of losses complete
  - `CAUGHT (post-drain)`: initial loss completes in one block; all follow-on damage preventable
  - `PARTIAL`: trap fires but signal arrives too late or from the wrong contracts for meaningful containment
  - `NOT CAUGHT`: exploit is structurally outside the trap's detection surface

---

## Production Assumption

This analysis assumes `min_number_of_operators = 3` as the production baseline.
The testnet deployment uses `min_number_of_operators = 1` as a PoC constraint,
documented in `drosera.toml`. A 3-operator quorum requires consensus across
independent nodes before `snapFreeze()` can execute. In the response timelines
below, this adds one block of latency in the worst case (~12 seconds), which
does not change any verdict in this analysis.

---

## 1. Incident Summary

- What the protocol was and what it did
- Exact date and UTC time of the exploit (or best known)
- Total confirmed loss and total exposure if follow-on attempts existed
- One paragraph — enough context to understand what follows, nothing more

---

## 2. Technical Root Cause

- The specific vulnerability: contract, function, or configuration that failed
- The exact attack sequence, step by step, in chronological order
- Key transaction hashes and block numbers where confirmed on-chain
- Attribution if confirmed (e.g. Lazarus Group, compromised key, etc.)
- No speculation. Only what post-mortems, audits, or on-chain data confirm.

---

## 3. On-Chain Signal Profile

The bridge between the real exploit and the trap's detection logic.

- What EVM state looked like before, during, and after the attack
- Which state variables moved, by how much, across how many blocks
- Whether the signal was single-block atomic or multi-block progressive
- What was visible on-chain vs. what happened off-chain before any transaction landed

This section determines whether and when each vector fires. Everything in
sections 4 and 5 follows from what is established here.

---

## 4. Design Envelope Assessment

Was this exploit within the trap's detection surface?

**A. Was the trap designed for this environment?**
State clearly whether the protocol architecture is the class BridgeRouterGuard
was built to monitor. If the root cause is at a layer the trap does not read,
say so directly.

**B. Does the on-chain consequence produce the detectable signal?**
Even if the root cause is off-chain, the exploit may still produce an on-chain
state change the trap can read. Distinguish between "not designed for the root
cause" and "not designed for the consequence."

**C. Which similar protocols or architectures would produce the same signal?**
Given the detected signal profile, describe the protocol characteristics that
make this trap applicable. Observable architecture traits only — not predictions.

---

## 5. Trap Vector Mapping

For each of the three vectors: does it fire, when, and at what magnitude?

**Symbol key:**
| Symbol | Meaning |
|---|---|
| ✅ | Fires — signal detected, threshold exceeded |
| ❌ | Does not fire — signal absent, this attack produces no output on this vector |
| ⚠️ | Signal present but below threshold, or only a partial architectural match |
| — | Out of scope — this vector monitors a different attack surface entirely |

For each vector that fires: cite the exact code path, state the threshold
and actual signal magnitude, state how many blocks after the drain it fires.

For each vector that does NOT fire: state precisely why —
signal not present, wrong chain, wrong architecture, below threshold, etc.

---

## 6. Simulated Response Timeline

All times UTC. Block time assumption stated upfront.

Format:
```
[Time UTC]   [Event]
             [State change]
             [WITH TRAP: what happens]
```

End with:
```
Trap exposure window:   [X seconds]
Actual exposure window: [Y minutes]
Compression factor:     [Z×]
```

---

## 7. Damage Assessment

| | Without Trap | With Trap (min_operators = 3) |
|---|---|---|
| Initial loss | $X | $X (unpreventable if single-block) |
| Follow-on losses | $Y | $0 or reduced |
| Total exposure window | X min | ~Y seconds |
| **Total preventable** | — | **$[estimate with basis]** |

Follow with one short paragraph explaining the reasoning behind any figure
that is not directly confirmed on-chain.

---

## 8. What the Trap Does Not Cover Here

Specific gaps that apply to THIS exploit only — not the generic README limitations.

- Off-chain attack surface that preceded the on-chain signal
- Specific architectural features of this protocol the trap cannot read
- Any edge case where the trap would have fired late, incorrectly, or not at all
- Single-block atomicity constraint if it applies here

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**
Could a modified threshold or additional state variable have caught the root cause?
Is that state variable on-chain and readable?

**Beyond BridgeRouterGuard (new trap pattern):**
If the gaps in section 8 require a different trap entirely, describe what it
would monitor. Name the state variable, the invariant, and the response.
Keep this concrete and grounded in what is actually observable on-chain.

---

## 10. Sources

- Primary sources only where available
- Format: [Publication/Source]: [Title] — [URL]
- Figures cited without a source must be labeled `[estimate]` inline
