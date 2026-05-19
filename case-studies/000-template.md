# [Protocol Name] — [Month Year]

**Loss:** $[X]M confirmed · $[Y]M total exposure (if follow-on losses existed)  
**Date:** [Full date, UTC where known]  
**Root Cause:** [Specific vulnerability / failure mode / compromise mechanism]  
**Primary Vector:** [Vector 1 / Vector 2 / Vector 3 / Vector 4 / combination / None]  
**Trap verdict:** `CAUGHT (pre-drain)` | `CAUGHT (post-drain)` | `PARTIAL` | `NOT CAUGHT`

---

## 1. Incident Summary

- What the protocol was and what it did
- Exact date and UTC time of the exploit (or best known)
- Total confirmed loss and total exposure if follow-on attempts existed
- One paragraph focusing on the structural failure mode relevant to bridge accounting invariants. No narrative fluff.

---

## 2. Technical Root Cause

- The specific vulnerability: contract, function, configuration, or key management failure
- Explicit mapping to which bridge component failed (vault, gateway, router, validation layer, or off-chain infrastructure)
- The exact attack sequence, step by step, in chronological order
- Key transaction hashes and block numbers where confirmed on-chain
- Attribution if confirmed (e.g., Lazarus Group, compromised key, insider). No speculation. Only what post-mortems, audits, or on-chain data confirm.

---

## 3. On-Chain Signal Profile

The bridge between the real exploit and the trap's detection logic.

- Map state changes explicitly to v3 `CollectOutput` fields: `executedWithdrawals`, `validatedInboundCredits`, `cumulativeMinted`, `validatedMintAuthorizations`, `executedMessages`, `gatewayValidatedMessages`, `vaultTokenBalance`
- Show exact delta computation per vector: `execGrowth - creditGrowth`, `mintGrowth - authGrowth`, `balanceDrop - execGrowth`, or `executedMessages - gatewayValidatedMessages`
- Clarify whether the signal was single-block atomic or multi-block progressive
- Distinguish what was visible on-chain vs. what happened off-chain before any transaction landed

This section determines whether and when each vector fires. Everything in sections 4 and 5 follows from what is established here.

---

## 4. Design Envelope Assessment

Was this exploit within the trap's detection surface? Write three cohesive, declarative paragraphs:

1. **Environment alignment:** State clearly whether the protocol architecture matches the class BridgeRouterGuard was built to monitor. If the root cause is at a layer the trap does not read, state it directly.
2. **Signal production:** Even if the root cause is off-chain, document whether the exploit produces an on-chain state change the trap can read. Distinguish between "not designed for the root cause" and "not designed for the consequence."
3. **Architectural parallels:** Given the detected signal profile, describe the protocol characteristics that make this trap applicable. Observable architecture traits only — no predictions or speculation.

Do not use Q&A formatting. State facts directly.

---

## 5. Trap Vector Mapping

For each of the four vectors: does it fire, when, and at what magnitude?

**Symbol key:**
| Symbol | Meaning |
|---|---|
| ✅ | Fires — signal detected, threshold exceeded or zero-backing invariant met |
| ❌ | Does not fire — signal absent, this attack produces no output on this vector |
| ⚠️ | Signal present but below threshold, or only a partial architectural match |
| — | Out of scope — this vector monitors a different attack surface entirely |

For each vector that fires: cite the exact v3 code path (`src/core/BridgeRouterGuardTrap.sol`), state the threshold vs actual signal magnitude, and state how many blocks after the drain it fires. Document intentional bypasses explicitly (e.g., Vector 2 partial authorization suppression).

For each vector that does NOT fire: state precisely why — signal not present, wrong chain, wrong architecture, below threshold, or validator deceived rather than bypassed.

---

## 6. Simulated Response Timeline

All times UTC. Block time assumption stated upfront. Timing reflects operator consensus latency, not deterministic contract guarantees.

Format:
```
[Time UTC]   [Event]
             [State change]
             [WITH TRAP: what happens]
```

End with:
```
Trap exposure window:   [X seconds/blocks]
Actual exposure window: [Y minutes]
```

Do not claim fixed containment timings. Frame latency around operator aggregation, P2P consensus, and on-chain cooldown state.

---

## 7. Damage Assessment

| | Without Trap | With Trap (production baseline) |
|---|---|---|
| Trigger event (initial loss) | $X | $X (unavoidable if single-block) |
| Follow-on losses | $Y | $0 or reduced |
| Total exposure window | X min | ~Y seconds/blocks |
| **Total preventable** | — | **$[estimate with on-chain basis]** |

Follow with one short paragraph explaining the reasoning behind any figure that is not directly confirmed on-chain. Explicitly separate the unavoidable trigger event from preventable follow-on damage. Label estimates as `[estimate]`.

---

## 8. What the Trap Does Not Cover Here

Specific gaps that apply to THIS exploit only — not the generic README limitations.

- Off-chain attack surface that preceded the on-chain signal
- Specific architectural features of this protocol the trap cannot read
- Any edge case where the trap would have fired late, incorrectly, or not at all
- Single-block atomicity constraint if it applies here
- Threshold strictness or partial-authorization bypass if materially relevant to this case

Do not repeat global design envelope boundaries. Keep this strictly case-specific.

---

## 9. Extending the Detection Surface

**Within BridgeRouterGuard:**
Could a modified threshold or additional state variable have caught the root cause? Is that state variable on-chain and readable? State engineering requirements plainly.

**Beyond BridgeRouterGuard:**
If the gaps in section 8 require a different trap entirely, describe what it would monitor. Name the state variable, the invariant, and the response. Ground extensions in implemented concept traps where applicable:
- [`OwnershipMonitorTrap`](./src/concepts/OwnershipMonitorTrap.sol)
- [`PreAttackMonitorTrap`](./src/concepts/PreAttackMonitorTrap.sol)
- [`PositionMonitorTrap`](./src/concepts/PositionMonitorTrap.sol)

Link to [010 — Architecture and Extensions](./010-architecture-and-extensions.md) for full designs. Keep this concrete and grounded in what is actually observable on-chain.

---

## 10. Sources

- Primary sources only where available
- Format: [Publication/Source]: [Title] — [URL]
- Include on-chain transaction links and official post-mortem reports where applicable
- Figures cited without a source must be labeled `[estimate]` inline

---

### 🔹 Key Improvements Applied
- Removed `Production Assumption` section entirely (operator/quorum latency is documented globally in README)
- Added `Root Cause` and `Primary Vector` header fields
- Flattened Section 4 from Q&A format into direct analytical prose
- Expanded vector mapping to 4 vectors with explicit code citation and threshold-vs-signal guidance
- Updated damage table to explicitly separate unavoidable trigger events from preventable follow-on losses
- Removed deterministic timing claims; framed containment around operator consensus latency
- Tightened Section 8 to case-specific gaps only, eliminating redundancy with README
- Grounded Section 9 extensions in v3 concept traps with direct file links
- Enforced strictly declarative, forensic tone throughout all instructional text

This template now matches the exact standard used in the upgraded case studies and will produce consistent, auditor-ready documentation for any future incident analysis. Ready for archival or immediate use.
