# BridgeRouterGuard  
### A guardrail for cross-chain execution without validation.  
  
> A time-series, velocity-tracking circuit breaker for the cross-chain validation failure pattern class. Deployed and verified live on Hoodi Testnet.
  
---  
  
## The Problem Didn't Change. Only the Bridges Did.  
  
From July 2023 through April 2026, cross-chain bridges collectively lost over $2.9B to a single failure mode: execution without validation.  
  
Every incident follows the same script: an off-chain validation layer — a multisig, an MPC cluster, a relayer, or a gateway contract — gets bypassed or compromised. The destination-chain router then executes a payload it has no business executing. Liquidity is drained. Unbacked tokens are minted. The bridge halts after the fact.
  
---  
  
## The Pattern Family: Unvalidated Cross-Chain Execution  
  
| Incident | Date | Loss | Root Cause | On-Chain Signal |  
| :--- | :--- | :--- | :--- | :--- |  
| Multichain | Jul 2023 | ~$231M | MPC keys compromised; router drained without deposit proofs | Unmatched mass withdrawal |  
| Orbit Chain | Dec 2023 | ~$81M | 7/10 multisig phished; vault drained in sequence | Unmatched vault outflow |  
| Socket Protocol | Jan 2024 | ~$3.3M | Flawed approval logic; infinite cross-chain execution | Unauthorized execute() calls |  
| Force Bridge | Jun 2025 | ~$3.7M | Compromised deployer key; multi-asset drain across endpoints | Drain without lock events |  
| CrossCurve | Feb 2026 | ~$3.0M | Missing access control on ReceiverAxelar; spoofed expressExecute | Unauthorized payload execution |  
| IoTeX ioTube | Feb 2026 | ~$4.4M | Validator upgrade bypassed signature checks; minted from MinterPool | Privilege escalation + phantom mint |  
| Hyperbridge | Apr 2026 | $237K (1B phantom) | MMR proof replay; forged message granted admin over bridged DOT | Unbacked mint spike |  
  
The attack vector evolves — MPC compromise in 2023, message spoofing in 2026 — but the invariant never changes: execution without validation.  
  
---  
  
## The Trap  

*The system watches how fast value is moving, not just how much — and freezes execution when that velocity breaks expected bounds.*

BridgeRouterGuard acts as a **stateful invariant guard**, enforcing a single rule across three execution layers:  
  
> **No high-value execution may occur without a validated inbound event.** It does this by continuously monitoring cumulative EVM state across a 7-block window. By calculating the velocity of abnormal capital movement, it catches both single massive drains and chunked attacks designed to evade static transaction limits.
  
### Three Vectors. One Response.  
  
**Vector 1 — High-Velocity Liquidity Drain** *(Statistical Signal — Velocity-Based)* · *Multichain, Orbit Chain, Force Bridge* Attackers often split large drains into smaller transactions to evade fixed safety limits. The trap tracks `cumulativeWithdrawals` across the `block_sample_size` window (7 blocks), computing the delta between the oldest and newest snapshot. A spike exceeding **1,000 ETH** in the window fires the response. Additionally, a per-block burst detector evaluates intervals where the single-block delta exceeds **400 ETH** — two consecutive intervals exceeding this burst threshold trigger containment independently of the window total.  
  
→ [`src/BridgeRouterGuardTrap.sol`](./src/BridgeRouterGuardTrap.sol) · [`src/mocks/MockBridgeVault.sol`](./src/mocks/MockBridgeVault.sol)  
  
**Vector 2 — Privilege Escalation & Phantom Mint** *(Statistical Signal — Velocity-Based)* · *IoTeX ioTube, Hyperbridge* Post-compromise, attackers frequently grant themselves admin rights and mint unbacked tokens. The trap monitors the `phantomMinted` cumulative state continuously. A delta exceeding **10,000 ETH** equivalent in the window triggers containment, regardless of whether the escalation occurred via a forged proof or a compromised key. A per-block burst threshold of **5,000 ETH** provides supplementary detection for chunked-minting strategies.  
  
→ [`src/BridgeRouterGuardTrap.sol`](./src/BridgeRouterGuardTrap.sol) · [`src/mocks/MockTokenGateway.sol`](./src/mocks/MockTokenGateway.sol)  
  
**Vector 3 — Forged Router Payload** *(Hard Invariant — Immediate Trigger)* · *Socket Protocol, CrossCurve* The most direct attack path: a payload executes on the router without passing through canonical gateway validation. This is enforced as a strict state invariant — if `spoofedMessageExecuted` becomes `true`, the response fires immediately. No velocity calculation. No history required. One unauthorized execution triggers absolute containment.  
  
→ [`src/BridgeRouterGuardTrap.sol`](./src/BridgeRouterGuardTrap.sol) · [`src/mocks/MockBridgeRouter.sol`](./src/mocks/MockBridgeRouter.sol)  
  
---  
  
## Architecture  
  
The trap operates entirely out-of-band across decentralized shadow nodes. It never sits in-line with user transactions and adds zero gas overhead to normal protocol operations.  
  
### How a Block Becomes a Containment  
  
1. Monitor — Shadow operators call collect() on every new block, reading cumulative state from Vault, Gateway, and Router simultaneously. Output is versioned via CollectOutput.schemaVersion.  
2. Evaluate — shouldRespond() computes velocity deltas and burst counts across the 7-block window. Delta above threshold or burst count ≥ 2 → true.  
3. Attest — The operator signs the result and gossips to the Drosera p2p network.  
4. Execute — On consensus, one operator pays gas to call snapFreeze(), which best-effort pauses all three infrastructure contracts with per-target event emission.  
5. Alert — shouldAlert() decodes severity into an AlertData struct, routed as a CRITICAL JSON payload to custom institutional telemetry endpoints (Node.js).  
  
### Bootstrap Safety  
  
shouldRespond() will not fire on velocity signals without at least 2 valid historical samples. A bridge with normal lifetime volume above the threshold would otherwise false-trigger immediately on cold start, operator restart, or reorg recovery.  
  
Exception: Vector 3 (the router boolean) fires immediately with zero history — it is a hard invariant that requires no baseline.  
  
### Freeze Semantics: Best-Effort Partial Containment  
  
snapFreeze() uses try/catch around each emergencyPause() call. If a target is already paused or reverts, the remaining targets are still attempted. Partial containment is strictly better than zero containment. Every target's pause result is emitted as a TargetPauseResult event for full off-chain visibility.  
  
---  
  
## Live Proof: The Incident Response Lifecycle  
  
To validate the Trap under real-world network latency and state mechanics, a sequential attack campaign was executed on the Hoodi Testnet. This exercise demonstrates the complete DevSecOps incident response lifecycle: **Compromise → Containment → Remediation → Resumption**.

### Phase 1: The Initial Compromise & Stateful Containment  
  
A multi-vector assault (Drain + Phantom Mint + Spoof) was initiated against the initial infrastructure using the unified campaign simulator (→ [`LiveHoodiExploit.s.sol`](./test/attack/LiveHoodiExploit.s.sol)).
* **Initial Vault:** [`0xac031158562D5834416b47A89143B9d3059a2589`](https://hoodi.etherscan.io/address/0xac031158562D5834416b47A89143B9d3059a2589)
* **Attack Execution:** 1,500 ETH drained, 15,000 phantom tokens minted, and a spoofed payload executed simultaneously ([Tx `0x56448...`](https://hoodi.etherscan.io/tx/0x56448692abf69a4cdbbe0eeee1e1292a525abad0d226fab440000edf540e7730)).
  
The Drosera operator network immediately detected the anomaly and executed `snapFreeze` (→ [`BridgeRouterGuardResponse.sol`](./src/BridgeRouterGuardResponse.sol)). Following the containment, telemetry revealed that the Trap remained in a sustained `ShouldRespond='true'` state across subsequent blocks for hours, accompanied by active 33-block cooldown suppressions to prevent redundant transaction spam.

Because the Trap functions as a stateful invariant guard, it monitors cumulative state rather than transient events (→ [`BridgeRouterGuardTrap.sol#collect()`](./src/BridgeRouterGuardTrap.sol)). The attacker permanently altered the blockchain state (phantom supply > 10,000 ETH and router spoof flag = true), leaving the mathematical invariant broken. Consequently, the Trap maintains a locked state until human intervention occurs.

### Phase 2: Incident Remediation (The Redeployment)
  
To test the remaining vectors in isolation, we had to simulate a real-world DevSecOps incident response: halting the bridge, patching the vulnerability, and redeploying the infrastructure proxy contracts to reset the corrupted state back to zero.

* **Patched Vault:** [`0x3bc95EcA084085E983d32b4D53c741c06594D6a6`](https://hoodi.etherscan.io/address/0x3bc95EcA084085E983d32b4D53c741c06594D6a6) (Deployed in [Tx `0xe1833...`](https://hoodi.etherscan.io/tx/0xe18336a07b232190a0bae99260d9deeb99c89e135bf7cf629b50a0690314576f))
* **Patched Gateway:** [`0xd971Cc78d84503c720587EcdE355d2fF54200f5b`](https://hoodi.etherscan.io/address/0xd971Cc78d84503c720587EcdE355d2fF54200f5b) (Deployed in [Tx `0xfb334...`](https://hoodi.etherscan.io/tx/0xfb3342a078646b6549f5e0e2122134858d4579b6571da8af153a06f676589f44))
* **Patched Router:** [`0x94abC47bE7002E2232bd4660fbEC18471547707e`](https://hoodi.etherscan.io/address/0x94abC47bE7002E2232bd4660fbEC18471547707e) (Deployed in [Tx `0xb3452...`](https://hoodi.etherscan.io/tx/0xb3452754c290f8a1ab943354a39fdfc527863a265a7f65ad698703155bbbadec))

Once the Trap was pointed to the clean addresses, it immediately returned to `ShouldRespond='false'`, restoring normal operations and proving the complete Incident Response lifecycle.

### Phase 3: Isolated Vector Validation

With the network state reset, the campaign resumed to validate the remaining vectors in isolation.

#### Vector 2 Verification: Phantom Mint
The attacker escalated privileges and minted 15,000 unbacked tokens to bypass the vault entirely (→ [`MockTokenGateway.sol#mintPhantom()`](./src/mocks/MockTokenGateway.sol)).

| Event | Transaction |  
| :--- | :--- |  
| **Phantom Mint Executed** | [`0xb58f6...`](https://hoodi.etherscan.io/tx/0xb58f6ce5d57026888b37af9c235329c71ad22f4b01a7b6d718bc59dca866aed5) |  
| **snapFreeze Triggered** | [`0x14d3a...`](https://hoodi.etherscan.io/tx/0x14d3a3c9b4ae7646c2247cb2235c2312c26e3c9b8ede468cd782b9a61a8c9903) |  

**Result:** The velocity delta breached the 10,000 ETH threshold, triggering containment upon the next block evaluation (→ [`BridgeRouterGuardTrap.sol#_evaluateVectors()`](./src/BridgeRouterGuardTrap.sol)).

#### Vector 1b: Testnet Discovery (The Sequencer Anomaly)
To bypass the 1,000 ETH window threshold, an extraction of 900 ETH was chunked into two 450 ETH transactions.

| Event | Transaction |  
| :--- | :--- |  
| **Chunk 1 Executed** | [`0x1ae86...`](https://hoodi.etherscan.io/tx/0x1ae86b0bb9d0fb97d4426d920950a9b1d1e7d93a9f0f5c614df231cab316cbf4) |  
| **Chunk 2 Executed** | [`0x88bdc...`](https://hoodi.etherscan.io/tx/0x88bdcc84165272892708501c19e313d87e006bc8b401a5cea807567ba8f7f6a3) |  

**Result (Evasion Successful):** Live testnet telemetry revealed that the L2 sequencer batched both transactions into the exact same block. Consequently, the Trap read a single 900 ETH spike for that specific interval. Because 900 ETH remains below the 1,000 ETH window threshold, and a single burst interval does not satisfy the `BURST_COUNT_TRIGGER = 2` requirement (→ [`BridgeRouterGuardTrap.sol#_countBursts()`](./src/BridgeRouterGuardTrap.sol)), the evasion succeeded. 
*Significance:* This anomaly demonstrates that rigid on-chain block intervals are vulnerable to network-level batching mechanics. This finding validates the architectural need for Off-Chain Statistical Processing (see [What's Next](## What's Next: Production Deployment Roadmap)).

#### Vector 1a Verification: Single Vault Drain
A massive, single-transaction extraction of 1,500 ETH was executed (→ [`MockBridgeVault.sol#removeLiquidity()`](./src/mocks/MockBridgeVault.sol)).

| Event | Transaction |  
| :--- | :--- |  
| **Malicious Drain Executed** | [`0xa1e3d...`](https://hoodi.etherscan.io/tx/0xa1e3dd81cf876be4354ba93f45154e92dc7ef20c137f9d3792d968410d8d563c) |  
| **snapFreeze Triggered** | [`0x9a537...`](https://hoodi.etherscan.io/tx/0x9a53728d71a97f68fbc9c8899f965223f1c6967c9b8ecbc5248a96acf6d335d3) |  

**Result:** Because 1,500 ETH exceeds the hard `VAULT_DRAIN_THRESHOLD`, the Trap triggered containment immediately on the subsequent block evaluation.

> **Note on containment timing:** The one-block result is a testnet observation with mock infrastructure. In production, actual containment timing depends on finality assumptions of the source chain, cross-chain message relay latency, destination chain execution windows, and bridge-specific design. The testnet result demonstrates the Drosera operator response pipeline works end-to-end. It does not guarantee equivalent timing across all production bridge designs.

### Extended Attack Campaign — All Vectors Verified On-Chain  
  
Beyond the primary containment sequences above, the following attack campaigns were executed on to independently verify each vector and multi-vector combination.
  
| Campaign | Why? | Amount | Block | Tx Hashes |  
| :--- | :--- | :--- | :--- | :--- |  
| Drain + Phantom Mint + Router Spoof | Simulates total system failure; tests protocol resilience against simultaneous, multi-vector asymmetric attacks (Vectors 1, 2, and 3). | 1,500 ETH drain · 15,000 ETH phantom · spoof | `2647748` | [`0x56448...`](https://hoodi.etherscan.io/tx/0x56448692abf69a4cdbbe0eeee1e1292a525abad0d226fab440000edf540e7730) [`0x254d6...`](https://hoodi.etherscan.io/tx/0x254d60c5767b0b7de3ac07c79662976f8a5d65279bb7224e328377c30597b96d) [`0x847ca...`](https://hoodi.etherscan.io/tx/0x847cab75a76b25932578fd02cdabf824f6fc5d483b163a5d1ce20157b2e3eb54) [`0xd8a8d...`](https://hoodi.etherscan.io/tx/0xd8a8d009f83a142a9027e4bc2bbcddfef44de55d039554ab71cbaa6893db4809) |  
| Vault drain (Multichain pattern) | Validates the primary window velocity threshold against a single massive liquidity extraction (Vector 1). | 1,500 ETH | `2647752` | [`0xafdfd...`](https://hoodi.etherscan.io/tx/0xafdfd8e3ce118f0c8abe14cf4840fbf325be90cda30045fc6a6ee2858daed208) |  
| Vault drain split across 2 txs (Orbit pattern) | Proves the per-block burst detector catches evasive chunking designed to bypass the main window threshold (Vector 1). | 2× 450 ETH | `2647756` | [`0xe586e...`](https://hoodi.etherscan.io/tx/0xe586ee057a72bba811282860fbcb5780ccb5c1a87940fa70fecbf008bbfb6715) [`0xe024a...`](https://hoodi.etherscan.io/tx/0xe024a04e7c089db9deb3728f7dfda2d0b266c8c7cbd752032eebd6487fa2ab2c) |  
| Privilege escalation + unbacked mint (IoTeX/Hyperbridge pattern) | Ensures downstream token minting triggers containment regardless of how the gateway was compromised (Vector 2). | 15,000 ETH phantom | `2647760` | [`0xafe3e...`](https://hoodi.etherscan.io/tx/0xafe3e689c941964f0efc6188ddc1b978d25fadd8d355fd0a9e29a0a0a54fba10) [`0x2f03f...`](https://hoodi.etherscan.io/tx/0x2f03fd3ef254c2b484755aeda672f08b61146417faa71d402dd8b1a343b8799e) |  
| Forged payload execution (CrossCurve/Socket pattern) | Verifies the hard boolean invariant fires immediately on unauthorized router execution without requiring velocity history (Vector 3). | — | `2647763` | [`0xa05c5...`](https://hoodi.etherscan.io/tx/0xa05c5056104d1509b287b2c843d128f37d08fea2561f667589e214732b6a9ce7) |  
| Phantom mint + router spoof simultaneously | Tests containment when an attacker bypasses the vault entirely to mint unbacked assets and immediately route them (Vectors 2 & 3). | 20,000 ETH phantom · spoof | `2647766` | [`0x3218c...`](https://hoodi.etherscan.io/tx/0x3218cf1da8fc072f3e9604cd16b3f66885a9f12718daa50a840497ce8a98ee75) [`0x15630...`](https://hoodi.etherscan.io/tx/0x15630079e7bef9af3d767a236c16b45d0288868a9da2b88e2bb73390450a82d6) [`0x90e1e...`](https://hoodi.etherscan.io/tx/0x90e1e5e1a574075cdfcc49dfab4b6ca83b3c6d554b46ce945089b96686c6cbbf) |  
| Sub-threshold drain + phantom mint (mixed pattern) | Demonstrates the trap correctly ignores a benign sub-threshold drain while catching the critical phantom mint spike (Vectors 1 & 2). | 800 ETH drain · 12,000 ETH phantom | `2647768` | [`0x56ec0...`](https://hoodi.etherscan.io/tx/0x56ec0e51bfe8bd44c3229b287579c16800e24ce98bc92a030ab8d40de4ed0c80) [`0x3a1a9...`](https://hoodi.etherscan.io/tx/0x3a1a9f1d7fbc6ab0e53e0a48806169d28f30f0b0ac5cc624652a66111bde0d62) [`0x62f28...`](https://hoodi.etherscan.io/tx/0x62f283c3b8f01f0bb63ab54e86e83e6cb801e1cf04bc5104cdc8aa5899f7a3e2) |  
  
---  
  
### The Circuit Breaker Argument  
  
> *If an attacker successfully drained 1,500 ETH or minted 15,000 phantom tokens to trigger the Trap, doesn't that mean the exploit was already successful?* 
> In single-chain DeFi, yes. In cross-chain interoperability, no.  
  
A cross-chain exploit is rarely a single atomic transaction; it is a multi-step sequence. Stealing from a vault on Chain A, or escalating privileges to mint on a Gateway on Chain B, is only step one. The attacker still requires cross-chain message finality, or subsequent router execution to swap those assets into native gas tokens (exit liquidity) before the hack is complete. That execution window is exactly where this architecture operates.  
  
By the time `snapFreeze` fires in the block immediately following the threshold breach, the entire infrastructure suite is neutralized. The router is paused, halting swaps. The gateway is frozen, preventing further mints. The attacker is left holding heavily monitored assets on a locked network with no path forward, securing the remaining protocol TVL.
  
*(See timing caveats above — actual containment outcomes depend on source-chain finality and relay latency for the specific bridge design.)* 

---  
  
## Design Envelope & Out-of-Scope Scenarios  

*This system is intentionally scoped for high-signal, high-velocity events. The following scenarios fall outside that scope by design.*
  
1. **Time-Based Threshold Evasions.** Static thresholds and fixed block windows are structurally vulnerable to time manipulation by sophisticated attackers. 
   * **Stretching Time ("Low and Slow"):** An attacker extracting 100 ETH/block over 15 blocks never trips the 400 ETH burst limit, and because the window is only 7 blocks wide, the 7-block sum never trips the 1,000 ETH limit.
   * **Compressing Time ("Sequencer Batching"):** As discovered during Hoodi testnet execution, attackers can broadcast chunked sub-threshold transactions simultaneously. If the L2 sequencer batches them into a single block, it completely bypasses consecutive-burst counters. Defeating both tactics requires dynamic time-weighted averages rather than strict block-to-block deltas (see [What's Next](## What's Next: Production Deployment Roadmap)).
  
2. Multi-asset split attacks. The trap operates on a single ETH-equivalent counter per vector. Simultaneously draining 400 ETH of Token A and 400 ETH of Token B doesn't trigger either threshold individually. Defending against this requires oracle-backed asset normalization into a unified risk value — a pure function constraint on Drosera's current architecture prevents native oracle calls (see [What's Next](## What's Next: Production Deployment Roadmap)).  
  
3. Threshold gaming by a well-informed attacker. An attacker who knows the constants and has patience can operate at exactly 499 ETH/block indefinitely. Static thresholds are a known tradeoff in all threshold-based systems. Dynamic thresholds derived from rolling baselines eliminate this surface entirely — that upgrade path is documented in [What's Next](## What's Next: Production Deployment Roadmap).  
  
4. Operator downtime during the trigger block. If no operator is online when the attack block is produced, detection is deferred until an operator comes back online and processes the catch-up window. This is an operator liveness concern, not a trap logic concern. Production deployments should maintain redundant operators — exactly why min_number_of_operators should be ≥ 3 on mainnet.  
  
5. Flash-loan-funded single-block manipulation. Velocity detection is inherently inter-block — it measures state *changes between* blocks. An attack that opens and closes within a single atomic transaction leaves no cross-block delta to measure. This trap is not designed for intra-block invariant monitoring; that requires a different detection primitive.  
  
6. Operator quorum is set to 1 for this testnet deployment. On the Hoodi testnet, independent operators are limited. In production, min_number_of_operators must be ≥ 3 so that no single key compromise can unilaterally trigger a freeze. This is a deployment configuration decision, not an architectural one.  
  
---  
  
## Local Test Suite  
  
forge test -vv    

### Summary

- Total Test Suites: 7
- Total Tests: 28
- Pass Rate: 100%
- Fuzz Runs: 1,024+ randomized inputs across critical thresholds
- Failures: 0

All detection vectors, edge cases, and response paths executed successfully under unit, adversarial, fuzz, and end-to-end conditions.

---

### What This Demonstrates

- Stable behavior around threshold boundaries  
  Sub-threshold activity did not trigger containment across tested scenarios, including randomized fuzz inputs.

- Consistent triggering above thresholds  
  Values exceeding configured velocity limits reliably triggered responses across all vectors in test conditions.

- Adversarial resilience (within tested scope)  
  Evaluated against chunked drains (burst evasion attempts), cold-start conditions, non-monotonic or malformed state, and threshold boundary probing.

- Fail-safe handling of invalid inputs  
  Malformed or unexpected data does not cause reverts or unsafe state transitions.

- Response-layer correctness  
  Operator authorization enforced. Cooldown constraints respected. Partial failures degrade safely (best-effort freeze).

- End-to-end execution path  
  Full pipeline validated: exploit → detection → operator consensus → snapFreeze → containment

---

### Property-Oriented Testing (Fuzz)

Across 1,024+ randomized inputs:

- Values ≤ threshold did not trigger responses in observed runs
- Values > threshold consistently triggered responses in observed runs

> Note on the fuzz run: testFuzz_SubThresholdNeverFires executed 256 randomised uint256 inputs, all below the 1,000 ETH threshold. Zero false triggers across all 256 runs is a property proof, not just a unit test.

---

### Test Coverage

[test/VaultDrain.t.sol](./test/VaultDrain.t.sol) — Vector 1: Vault Drain  
Velocity math fires on a drain spike. Normal deposit volume is correctly ignored.

[test/PhantomMint.t.sol](./test/PhantomMint.t.sol) — Vector 2: Phantom Mint  
Delta-based detection fires on unbacked minting. Sub-threshold mints pass without triggering.

[test/RouterSpoof.t.sol](./test/RouterSpoof.t.sol) — Vector 3: Router Spoof  
Hard invariant fires immediately on a spoofed payload. No velocity calculation or history required.

[test/ResponseAuth.t.sol](./test/ResponseAuth.t.sol) — Response Layer  
Unauthorized callers revert. Only the owner can set operators. Two-step ownership transfer verified. Cooldown boundary enforced.

[test/AdversarialAttack.t.sol](./test/AdversarialAttack.t.sol) — Adversarial Layer  
Threshold gaming at exact boundary. Chunked burst detection across the window. Cold-start false-positive protection. Non-monotonic counter safety.

[test/FuzzAndEdgeCases.t.sol](./test/FuzzAndEdgeCases.t.sol) — Fuzz & Edge Cases  
Property test: any value ≤ threshold never fires across 256 randomized runs. Malformed payloads fail safe. Schema version mismatches rejected without revert.

[test/FullExploitSequence.t.sol](./test/FullExploitSequence.t.sol) — Integration  
End-to-end pipeline: exploit → detection → operator consensus → snapFreeze → attacker blocked.

> Architecture note: The production trap uses hardcoded constant addresses (no constructor arguments, per Drosera stateless trap requirements). Tests use [TestableBridgeRouterGuardTrap.sol](./src/TestableBridgeRouterGuardTrap.sol) — same logic, constructor-injectable addresses for isolated CI. shouldRespond() and shouldAlert() are pure and address-independent; only collect() requires address injection.

> Full verbose test output available via forge test -vv for auditors and reviewers.

---
  
## Deployment  
  
### Live Contracts (Hoodi Testnet)  
  
| Contract | Address |  
| :--- | :--- |  
| **BridgeRouterGuardTrap** | [`0x1D880D83Ce107C6961495Ef767b8E4099A94F72E`](https://hoodi.etherscan.io/address/0x1D880D83Ce107C6961495Ef767b8E4099A94F72E) |  
| **BridgeRouterGuardResponse** | [`0x833c4F5CbE9CBf9f05ef44f99A69bb2487588685`](https://hoodi.etherscan.io/address/0x833c4F5CbE9CBf9f05ef44f99A69bb2487588685) |  
| **MockBridgeVault (Patched)** | [`0x3bc95EcA084085E983d32b4D53c741c06594D6a6`](https://hoodi.etherscan.io/address/0x3bc95EcA084085E983d32b4D53c741c06594D6a6) |  
| **MockTokenGateway (Patched)** | [`0xd971Cc78d84503c720587EcdE355d2fF54200f5b`](https://hoodi.etherscan.io/address/0xd971Cc78d84503c720587EcdE355d2fF54200f5b) |  
| **MockBridgeRouter (Patched)** | [`0x94abC47bE7002E2232bd4660fbEC18471547707e`](https://hoodi.etherscan.io/address/0x94abC47bE7002E2232bd4660fbEC18471547707e) |  
  
### Telemetry & Dependencies  
  
System Dependencies  
* Host Chain (Hoodi/EVM): Where the protocol contracts and Response contract live.  
* Drosera Network: The decentralized p2p network of shadow operators.  
* Alert Server & Web2 Command Center: Routes CRITICAL JSON payloads to custom institutional telemetry endpoints (Node.js).  
  
Live Testnet Configuration (drosera.toml)  
response_function        = "snapFreeze(uint256,uint256,bool)"  
block_sample_size        = 7        # raised from 3 — velocity traps need 5–8 blocks  
cooldown_period_blocks   = 33  
min_number_of_operators  = 1        # TESTNET ONLY — set >= 3 for production  
private_trap             = true    
  
---  
  
## Relevance to Production Infrastructure  
  
This architecture is directly applicable to any EVM-based bridge or interoperability protocol. The core invariant (**execution without validation**) and the three detection vectors map cleanly to production environments:  
  
- **LayerZero:** Abnormal `lzReceive()` execution velocity without a corresponding verified endpoint proof on the receiving `UltraLightNode` (maps to [Vector 1](./src/mocks/MockBridgeVault.sol)).  
- **Axelar:** `execute()` / `expressExecute()` call patterns on `AxelarGateway` bypassing `validateContractCall()` (maps exactly to our [Vector 3 mock](./src/mocks/MockBridgeRouter.sol)).  
- **Wormhole:** Guardian VAA replay or forged messages bypassing `verifyVM()`, leading to an unauthorized `completeTransfer()` mint (maps to [Vector 2](./src/mocks/MockTokenGateway.sol)).  
- **Across Protocol:** `SpokePool` outflow velocity without matching `HubPool` deposit events or proof finalization (maps to [Vector 1](./src/BridgeRouterGuardTrap.sol)).  
- **DeFi Integrations:** Any lending protocol accepting bridged collateral, where phantom-minted tokens are used to drain isolated lending pools before the source-chain compromise is detected.  
  
A production deployment replaces the mock addresses with live protocol contracts, tunes the velocity thresholds to match historical normal-flow baselines, and raises `min_number_of_operators` to ≥ 3.
  
---  
  
## What's Next: Production Deployment Roadmap
  
The current implementation successfully demonstrates the core velocity-tracking logic and containment pipeline. Transitioning this PoC to a production-grade mainnet deployment will require the following architectural upgrades:
  
- **Oracle-Injected Asset Normalization:** Drosera's strict requirement that `shouldRespond()` remains a `pure` function means the Trap cannot natively query external price oracles. Future iterations will require expanding the `collect()` payload to safely ingest cryptographically verified off-chain oracle data.  
- **Off-Chain Statistical Processing (Dynamic Thresholds):** As demonstrated by the [Vector 1b testnet sequencer anomaly](#vector-1b-testnet-discovery-the-sequencer-anomaly), rigid block-to-block limits are vulnerable to network batching. Replacing static thresholds with rolling-average math requires complex windowing that risks exceeding Drosera operator evaluation constraints. Production deployments must utilize Drosera's upcoming coprocessor to handle heavy statistical windowing off-chain.  
- **Mainnet Operator Quorum:** The current testnet environment limits the availability of independent operators. Upon mainnet release, `min_number_of_operators` must be raised to `≥ 3` with multisig execution enforcement on the Response contract to prevent unilateral operator griefing.  
- **Cross-Chain Relayer Expansion:** As the Drosera operator network officially expands its relayer support to Arbitrum, Base, and Optimism, this exact trap logic can be deployed cross-chain to monitor fragmented bridge endpoints natively.  
- **ZK Incident Response:** Integrate Drosera's zero-knowledge proof layer for optimistic claim disputes, ensuring that if an operator attempts a malicious `snapFreeze`, the protocol can mathematically challenge the evaluation payload.
  
---  
  
## Component Deep Dive  
  
- [**`src/BridgeRouterGuardTrap.sol`**](./src/BridgeRouterGuardTrap.sol) — Stateless sensor. Snapshots cumulative state from all three bridge components every block via `collect()`, then evaluates velocity deltas and per-block burst counts across a 7-block window in `shouldRespond()`. No state writes, no constructor args — fully Drosera-compliant.  
  
- [**`src/BridgeRouterGuardResponse.sol`**](./src/BridgeRouterGuardResponse.sol) — Circuit breaker. On operator consensus, `snapFreeze()` best-effort pauses all three infrastructure contracts via `try/catch`, ensuring partial containment even if one target is already frozen. Hardened with two-step ownership, operator allowlist, and a 33-block on-chain cooldown.  
  
- [**`src/TestableBridgeRouterGuardTrap.sol`**](./src/TestableBridgeRouterGuardTrap.sol) — CI shadow. Inherits all production logic unchanged. Overrides only `collect()` to accept injected addresses instead of constants, enabling isolated Foundry testing without touching production code.  
  
- [**`src/mocks/`**](./src/mocks/) — Vulnerable protocol simulation. Three contracts that deliberately replicate the structural weaknesses from real incidents: unmatched withdrawals (Multichain/Orbit), unverified admin and unbacked minting (IoTeX/Hyperbridge), unvalidated payload execution (CrossCurve/Socket).  
  
- [**`test/`**](./test/) — Three layers. Core unit tests confirm threshold boundaries per vector. [`AdversarialAttack.t.sol`](./test/AdversarialAttack.t.sol) and [`FuzzAndEdgeCases.t.sol`](./test/FuzzAndEdgeCases.t.sol) pressure-test against threshold gaming, chunked drains, cold-start conditions, malformed inputs, and schema mismatches. [`FullExploitSequence.t.sol`](./test/FullExploitSequence.t.sol) runs the complete pipeline end-to-end: exploit → detection → operator response → attacker blocked.  
  
- [**`test/attack/LiveHoodiExploit.s.sol`**](./test/attack/LiveHoodiExploit.s.sol) — Unified modular campaign script. Accepts vault amount, chunk count, phantom amount, and router spoof flag via `--sig` to execute any attack combination against live testnet mocks.  
  
- [**`drosera.toml`**](./drosera.toml) — Operator rules of engagement: block sampling window, cooldown, response function signature, quorum settings, and webhook routing.  
  
- [**`alert-server.js`**](./alert-server.js) — Node.js telemetry bridge. Decodes `AlertData` payloads from the Drosera network and routes Vault Velocity, Phantom Velocity, and Router Spoof flag to Slack or any configured webhook endpoint.  

---
  
## Repository Structure  
  
```text
bridge-router-guard/
├── src/
│   ├── BridgeRouterGuardTrap.sol          # Stateless sensor: collect() + shouldRespond() + shouldAlert()
│   ├── BridgeRouterGuardResponse.sol      # Circuit breaker: snapFreeze() with try/catch + two-step ownership
│   ├── TestableBridgeRouterGuardTrap.sol  # CI shadow: inherits all logic, overrides collect() for injection
│   └── mocks/
│       ├── MockBridgeVault.sol            # Vector 1: unmatched withdrawal model (Multichain/Orbit)
│       ├── MockTokenGateway.sol           # Vector 2: unverified admin + unbacked mint model (IoTeX/Hyperbridge)
│       └── MockBridgeRouter.sol           # Vector 3: unvalidated payload execution model (CrossCurve/Socket)
├── test/
│   ├── VaultDrain.t.sol                   # Unit: velocity threshold fires on drain spike
│   ├── PhantomMint.t.sol                  # Unit: delta detection fires on unbacked mint
│   ├── RouterSpoof.t.sol                  # Unit: boolean invariant fires immediately on spoof
│   ├── ResponseAuth.t.sol                 # Auth: operator/owner access control + cooldown boundary
│   ├── AdversarialAttack.t.sol            # Adversarial: threshold gaming, chunked bursts, cold start, counter reset
│   ├── FuzzAndEdgeCases.t.sol             # Property: fuzz sub-threshold, malformed input, schema mismatch
│   ├── FullExploitSequence.t.sol          # Integration: end-to-end exploit → detection → snapFreeze → blocked
│   ├── attack/
│   │   └── LiveHoodiExploit.s.sol         # Live simulator: unified multi-vector campaign script for Hoodi
│   └── utils/
│       └── BridgeTestBase.t.sol           # Shared setUp: deploys all mocks + trap + response for reuse
├── script/
│   ├── DeployMocks.sol                    # Deploys MockVault, MockGateway, MockRouter to any EVM
│   └── DeployResponse.sol                 # Deploys BridgeRouterGuardResponse with env-injected addresses
├── lib/
├── drosera.toml                           # Shadow node config: sampling window, cooldown, response fn, webhooks
└── alert-server.js                        # Node.js telemetry: decodes AlertData → routes to Slack/webhook
```
  
---  
  
*Deployed on Hoodi Testnet. All transactions verifiable on-chain.*
