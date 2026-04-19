# BridgeRouterGuard  
### A guardrail for cross-chain execution without validation.  
  
> A time-series, velocity-tracking circuit breaker for the cross-chain validation failure pattern class. Deployed and verified live on Hoodi Testnet.
  
---  
  
## The Problem Didn't Change. Only the Bridges Did.  
  
From July 2023 through April 2026, cross-chain bridges collectively lost over **$2.9B** to a single failure mode: **execution without validation**.  
  
Every incident follows the same script: an off-chain validation layer — a multisig, an MPC cluster, a relayer, or a gateway contract — gets bypassed or compromised. The destination-chain router then executes a payload it has no business executing. Liquidity is drained. Unbacked tokens are minted. The bridge halts after the fact.
  
---  
  
## The Pattern Family: Unvalidated Cross-Chain Execution  
  
| Incident | Date | Loss | Root Cause | On-Chain Signal |  
| :--- | :--- | :--- | :--- | :--- |  
| [**Multichain**](https://www.halborn.com/blog/post/explained-the-multichain-hack-july-2023) | Jul 2023 | ~$231M | MPC keys compromised; router drained without deposit proofs | Unmatched mass withdrawal |  
| [**Orbit Chain**](https://www.halborn.com/blog/post/explained-the-orbit-bridge-hack-december-2023) | Dec 2023 | ~$81M | 7/10 multisig phished; vault drained in sequence | Unmatched vault outflow |  
| [**Socket Protocol**](https://www.halborn.com/blog/post/explained-the-socket-protocol-hack-january-2024) | Jan 2024 | ~$3.3M | Flawed approval logic; infinite cross-chain execution | Unauthorized `execute()` calls |  
| [**Force Bridge**](https://www.halborn.com/blog/post/explained-the-force-bridge-hack-june-2025) | Jun 2025 | ~$3.7M | Compromised deployer key; multi-asset drain across endpoints | Drain without lock events |  
| [**CrossCurve**](https://www.halborn.com/blog/post/explained-the-crosscurve-hack-february-2026) | Feb 2026 | ~$3.0M | Missing access control on `ReceiverAxelar`; spoofed `expressExecute` | Unauthorized payload execution |  
| [**IoTeX ioTube**](https://www.halborn.com/blog/post/explained-the-iotex-hack-february-2026) | Feb 2026 | ~$4.4M | Validator upgrade bypassed signature checks; minted from MinterPool | Privilege escalation + phantom mint |  
| [**Hyperbridge**](https://www.coindesk.com/tech/2026/04/13/attacker-mints-usd1-billion-polkadot-tokens-on-ethereum-ends-up-stealing-just-usd250-000) | Apr 2026 | $237K (1B phantom) | MMR proof replay; forged message granted admin over bridged DOT | Unbacked mint spike |  
  
The attack vector evolves — MPC compromise in 2023, message spoofing in 2026 — but the invariant never changes: **execution without validation**.  
  
---  
  
## The Trap  

*The system watches how fast value is moving, not just how much — and freezes execution when that velocity breaks expected bounds.*

BridgeRouterGuard enforces a single invariant across three execution layers:  
  
> **No high-value execution may occur without a validated inbound event.**  
  
It does this by monitoring EVM state across a 7-block window and calculating the **velocity** of abnormal capital movement — catching both single large drains and chunked attacks designed to stay below static thresholds.  
  
### Three Vectors. One Response.  
  
**Vector 1 — High-Velocity Liquidity Drain** *(Statistical Signal — Velocity-Based)* · *Multichain, Orbit Chain, Force Bridge*  
  
Attackers often split large drains into smaller transactions to evade fixed thresholds. The trap tracks `cumulativeWithdrawals` across the `block_sample_size` window (7 blocks), computing the delta between oldest and newest snapshot. A spike exceeding **1,000 ETH** in the window fires the response. Additionally, a per-block burst detector counts intervals where the single-block delta exceeds **400 ETH** — two consecutive bursts trigger independently of the window total.  
  
→ [`src/BridgeRouterGuardTrap.sol`](./src/BridgeRouterGuardTrap.sol) · [`src/mocks/MockBridgeVault.sol`](./src/mocks/MockBridgeVault.sol)  
  
**Vector 2 — Privilege Escalation & Phantom Mint** *(Statistical Signal — Velocity-Based)* · *IoTeX ioTube, Hyperbridge*  
  
Post-compromise, attackers grant themselves admin rights and mint unbacked tokens. The trap monitors `phantomMinted` state continuously. A delta exceeding **10,000 ETH** equivalent in the window triggers containment, regardless of whether the escalation was via forged proof or key compromise. A per-block burst threshold of **5,000 ETH** provides additional chunked-mint detection.  
  
→ [`src/BridgeRouterGuardTrap.sol`](./src/BridgeRouterGuardTrap.sol) · [`src/mocks/MockTokenGateway.sol`](./src/mocks/MockTokenGateway.sol)  
  
**Vector 3 — Forged Router Payload** *(Hard Invariant — Immediate Trigger)* · *Socket Protocol, CrossCurve*  
  
The most direct attack: a payload executes on the router without passing through canonical gateway validation. This is a **strict boolean invariant** — if `spoofedMessageExecuted` is true, the response fires immediately. No velocity calculation. No history required. One unauthorized execution is one too many.  
  
→ [`src/BridgeRouterGuardTrap.sol`](./src/BridgeRouterGuardTrap.sol) · [`src/mocks/MockBridgeRouter.sol`](./src/mocks/MockBridgeRouter.sol)  
  
---  
  
## Architecture  
  
The trap operates entirely out-of-band across decentralized shadow nodes. It never sits in-line with user transactions and adds zero gas overhead to normal protocol operations.  
  
### How a Block Becomes a Containment  
  
1. **Monitor** — Shadow operators call `collect()` on every new block, reading cumulative state from Vault, Gateway, and Router simultaneously. Output is versioned via `CollectOutput.schemaVersion`.  
2. **Evaluate** — `shouldRespond()` computes velocity deltas and burst counts across the 7-block window. Delta above threshold or burst count ≥ 2 → `true`.  
3. **Attest** — The operator signs the result and gossips to the Drosera p2p network.  
4. **Execute** — On consensus, one operator pays gas to call `snapFreeze()`, which best-effort pauses all three infrastructure contracts with per-target event emission.  
5. **Alert** — `shouldAlert()` decodes severity into an `AlertData` struct, routed as a `CRITICAL` JSON payload to custom institutional telemetry endpoints (Node.js).  
  
### Bootstrap Safety  
  
`shouldRespond()` will **not** fire on velocity signals without at least 2 valid historical samples. A bridge with normal lifetime volume above the threshold would otherwise false-trigger immediately on cold start, operator restart, or reorg recovery.  
  
Exception: Vector 3 (the router boolean) fires immediately with zero history — it is a hard invariant that requires no baseline.  
  
### Freeze Semantics: Best-Effort Partial Containment  
  
`snapFreeze()` uses try/catch around each `emergencyPause()` call. If a target is already paused or reverts, the remaining targets are still attempted. Partial containment is strictly better than zero containment. Every target's pause result is emitted as a `TargetPauseResult` event for full off-chain visibility.  
  
---  
  
## Live Proof  
  
### The Exercise  
  
A Multichain-pattern attack was simulated on Hoodi Testnet — 1,500 ETH drained from the live MockBridgeVault in a single transaction, exceeding the 1,000 ETH velocity threshold. The Drosera operator network was live and monitoring.  
  
### What Happened  
  
| Event | Transaction | Block |  
| :--- | :--- | :--- |  
| **Malicious drain executed** | [`0x251125db...a0586f`](https://hoodi.etherscan.io/tx/0x251125db5b8c3b374feed0cad564e78433a424b6a00890cb5a505b30e5a0586f) | `2643162` |  
| **snapFreeze triggered by operator** | [`0x67a68d99...6ca05`](https://hoodi.etherscan.io/tx/0x67a68d998c5b209f757252d36ba3b600af1eceb64718ad3c236692991a56ca05) | `2643163` |  
  
Attack at block `2643162`. Containment at block `2643163`. 
  
> **Note on containment timing:** The one-block result is a testnet observation with mock infrastructure. In production, actual containment timing depends on finality assumptions of the source chain, cross-chain message relay latency, destination chain execution windows, and bridge-specific design. The testnet result demonstrates the Drosera operator response pipeline works end-to-end. It does not guarantee equivalent timing across all production bridge designs.  
  
### Extended Attack Campaign — All Vectors Verified On-Chain  
  
Beyond the primary containment demo, six additional attack campaigns were executed on Hoodi Testnet to independently verify each vector and multi-vector combination. Every transaction is verifiable on-chain.  
  
| Campaign | Vectors Activated | Amount | Block | Tx Hashes |  
| :--- | :--- | :--- | :--- | :--- |  
| **All three simultaneously** | Drain + Phantom Mint + Router Spoof | 1,500 ETH drain · 15,000 ETH phantom · spoof | `2647748` | [`0x56448...`](https://hoodi.etherscan.io/tx/0x56448692abf69a4cdbbe0eeee1e1292a525abad0d226fab440000edf540e7730) [`0x254d6...`](https://hoodi.etherscan.io/tx/0x254d60c5767b0b7de3ac07c79662976f8a5d65279bb7224e328377c30597b96d) [`0x847ca...`](https://hoodi.etherscan.io/tx/0x847cab75a76b25932578fd02cdabf824f6fc5d483b163a5d1ce20157b2e3eb54) [`0xd8a8d...`](https://hoodi.etherscan.io/tx/0xd8a8d009f83a142a9027e4bc2bbcddfef44de55d039554ab71cbaa6893db4809) |  
| **Vector 1 only — single drain** | Vault drain (Multichain pattern) | 1,500 ETH | `2647752` | [`0xafdfd...`](https://hoodi.etherscan.io/tx/0xafdfd8e3ce118f0c8abe14cf4840fbf325be90cda30045fc6a6ee2858daed208) |  
| **Vector 1 only — chunked burst** | Vault drain split across 2 txs (Orbit pattern) | 2× 450 ETH | `2647756` | [`0xe586e...`](https://hoodi.etherscan.io/tx/0xe586ee057a72bba811282860fbcb5780ccb5c1a87940fa70fecbf008bbfb6715) [`0xe024a...`](https://hoodi.etherscan.io/tx/0xe024a04e7c089db9deb3728f7dfda2d0b266c8c7cbd752032eebd6487fa2ab2c) |  
| **Vector 2 only — phantom mint** | Privilege escalation + unbacked mint (IoTeX/Hyperbridge pattern) | 15,000 ETH phantom | `2647760` | [`0xafe3e...`](https://hoodi.etherscan.io/tx/0xafe3e689c941964f0efc6188ddc1b978d25fadd8d355fd0a9e29a0a0a54fba10) [`0x2f03f...`](https://hoodi.etherscan.io/tx/0x2f03fd3ef254c2b484755aeda672f08b61146417faa71d402dd8b1a343b8799e) |  
| **Vector 3 only — router spoof** | Forged payload execution (CrossCurve/Socket pattern) | — | `2647763` | [`0xa05c5...`](https://hoodi.etherscan.io/tx/0xa05c5056104d1509b287b2c843d128f37d08fea2561f667589e214732b6a9ce7) |  
| **Vectors 2 + 3 combined** | Phantom mint + router spoof simultaneously | 20,000 ETH phantom · spoof | `2647766` | [`0x3218c...`](https://hoodi.etherscan.io/tx/0x3218cf1da8fc072f3e9604cd16b3f66885a9f12718daa50a840497ce8a98ee75) [`0x15630...`](https://hoodi.etherscan.io/tx/0x15630079e7bef9af3d767a236c16b45d0288868a9da2b88e2bb73390450a82d6) [`0x90e1e...`](https://hoodi.etherscan.io/tx/0x90e1e5e1a574075cdfcc49dfab4b6ca83b3c6d554b46ce945089b96686c6cbbf) |  
| **Vectors 1 + 2 combined** | Sub-threshold drain + phantom mint (mixed pattern) | 800 ETH drain · 12,000 ETH phantom | `2647768` | [`0x56ec0...`](https://hoodi.etherscan.io/tx/0x56ec0e51bfe8bd44c3229b287579c16800e24ce98bc92a030ab8d40de4ed0c80) [`0x3a1a9...`](https://hoodi.etherscan.io/tx/0x3a1a9f1d7fbc6ab0e53e0a48806169d28f30f0b0ac5cc624652a66111bde0d62) [`0x62f28...`](https://hoodi.etherscan.io/tx/0x62f283c3b8f01f0bb63ab54e86e83e6cb801e1cf04bc5104cdc8aa5899f7a3e2) |  
  
Every vector combination fires and resolves cleanly. The unified `executeCampaign()` script handled all seven runs without modification, demonstrating parametric flexibility across asymmetric attack scenarios.  
  
---  
  
### The Circuit Breaker Argument  
  
> *If the attacker drained 1,500 ETH, doesn't that mean the exploit was successful?*  
  
In single-chain protocols, yes. Cross-chain infrastructure is different.  
  
Stealing from a vault on Chain A is step one. The attacker still needs cross-chain message finality before the router on Chain B releases the funds. That finality window is exactly where Drosera operates.  
  
By the time `snapFreeze` fires at block `2643163`, the cross-chain messages are already in the process of being invalidated. The router is paused. The gateway can't mint. The attacker has 1,500 ETH of heavily monitored assets on a frozen chain and no path forward. The remaining TVL never moves.  
  
*(See timing caveats above — actual outcome depends on source-chain finality and relay latency for the specific bridge design.)*  
  
This is the detection signal that saves everything else.  
  
---  
  
## Design Envelope & Out-of-Scope Scenarios  

*This system is intentionally scoped for high-signal, high-velocity events. The following scenarios fall outside that scope by design.*
  
1. **Sub-threshold single-block drains.** The 1,000 ETH window threshold and 500 ETH burst threshold are intentionally set to avoid false triggers on normal whale activity. A 999 ETH withdrawal in isolation is not a detectable attack signal at this sensitivity level — it's noise. Deployments protecting lower-TVL bridges should tune these constants to match their specific baseline flow.  
  
2. **"Low and slow" drip extraction.** This trap monitors velocity across a 7-block window. An attacker extracting 100 ETH/block over many blocks is a different threat model — one that requires statistical anomaly detection over a much longer observation window, not a velocity circuit breaker. That requires a different detection primitive. The `block_sample_size` can be extended, but drip detection at scale requires dynamic baselines (see [What's Next](#whats-next-overcoming-infrastructure-constraints)).  
  
3. **Multi-asset split attacks.** The trap operates on a single ETH-equivalent counter per vector. Simultaneously draining 400 ETH of Token A and 400 ETH of Token B doesn't trigger either threshold individually. Defending against this requires oracle-backed asset normalization into a unified risk value — a `pure` function constraint on Drosera's current architecture prevents native oracle calls (see [What's Next](#whats-next-overcoming-infrastructure-constraints)).  
  
4. **Threshold gaming by a well-informed attacker.** An attacker who knows the constants and has patience can operate at exactly 499 ETH/block indefinitely. Static thresholds are a known tradeoff in all threshold-based systems. Dynamic thresholds derived from rolling baselines eliminate this surface entirely — that upgrade path is documented in [What's Next](#whats-next-overcoming-infrastructure-constraints).  
  
5. **Operator downtime during the trigger block.** If no operator is online when the attack block is produced, detection is deferred until an operator comes back online and processes the catch-up window. This is an operator liveness concern, not a trap logic concern. Production deployments should maintain redundant operators — exactly why `min_number_of_operators` should be ≥ 3 on mainnet.  
  
6. **Flash-loan-funded single-block manipulation.** Velocity detection is inherently inter-block — it measures state *changes between* blocks. An attack that opens and closes within a single atomic transaction leaves no cross-block delta to measure. This trap is not designed for intra-block invariant monitoring; that requires a different detection primitive.  
  
7. **Operator quorum is set to 1 for this testnet deployment.** On the Hoodi testnet, independent operators are limited. In production, `min_number_of_operators` must be ≥ 3 so that no single key compromise can unilaterally trigger a freeze. This is a deployment configuration decision, not an architectural one.  
  
---  
  
## Local Test Suite  
  
```bash  
forge test -vv  
```  

### Summary

- **Total Test Suites:** 7
- **Total Tests:** 28
- **Pass Rate:** 100%
- **Fuzz Runs:** 1,024+ randomized inputs across critical thresholds
- **Failures:** 0

All detection vectors, edge cases, and response paths executed successfully under unit, adversarial, fuzz, and end-to-end conditions.

---

### What This Demonstrates

- **Stable behavior around threshold boundaries**  
  Sub-threshold activity did not trigger containment across tested scenarios, including randomized fuzz inputs.

- **Consistent triggering above thresholds**  
  Values exceeding configured velocity limits reliably triggered responses across all vectors in test conditions.

- **Adversarial resilience (within tested scope)**  
  Evaluated against chunked drains (burst evasion attempts), cold-start conditions, non-monotonic or malformed state, and threshold boundary probing.

- **Fail-safe handling of invalid inputs**  
  Malformed or unexpected data does not cause reverts or unsafe state transitions.

- **Response-layer correctness**  
  Operator authorization enforced. Cooldown constraints respected. Partial failures degrade safely (best-effort freeze).

- **End-to-end execution path**  
  Full pipeline validated: `exploit → detection → operator consensus → snapFreeze → containment`

---

### Property-Oriented Testing (Fuzz)

Across 1,024+ randomized inputs:

- Values ≤ threshold did not trigger responses in observed runs
- Values > threshold consistently triggered responses in observed runs

> **Note on the fuzz run:** `testFuzz_SubThresholdNeverFires` executed 256 randomised `uint256` inputs, all below the 1,000 ETH threshold. Zero false triggers across all 256 runs is a property proof, not just a unit test.

---

### Test Coverage

**[`test/VaultDrain.t.sol`](./test/VaultDrain.t.sol) — Vector 1: Vault Drain**  
Velocity math fires on a drain spike. Normal deposit volume is correctly ignored.

**[`test/PhantomMint.t.sol`](./test/PhantomMint.t.sol) — Vector 2: Phantom Mint**  
Delta-based detection fires on unbacked minting. Sub-threshold mints pass without triggering.

**[`test/RouterSpoof.t.sol`](./test/RouterSpoof.t.sol) — Vector 3: Router Spoof**  
Hard invariant fires immediately on a spoofed payload. No velocity calculation or history required.

**[`test/ResponseAuth.t.sol`](./test/ResponseAuth.t.sol) — Response Layer**  
Unauthorized callers revert. Only the owner can set operators. Two-step ownership transfer verified. Cooldown boundary enforced.

**[`test/AdversarialAttack.t.sol`](./test/AdversarialAttack.t.sol) — Adversarial Layer**  
Threshold gaming at exact boundary. Chunked burst detection across the window. Cold-start false-positive protection. Non-monotonic counter safety.

**[`test/FuzzAndEdgeCases.t.sol`](./test/FuzzAndEdgeCases.t.sol) — Fuzz & Edge Cases**  
Property test: any value ≤ threshold never fires across 256 randomized runs. Malformed payloads fail safe. Schema version mismatches rejected without revert.

**[`test/FullExploitSequence.t.sol`](./test/FullExploitSequence.t.sol) — Integration**  
End-to-end pipeline: `exploit → detection → operator consensus → snapFreeze → attacker blocked`.

> **Architecture note:** The production trap uses hardcoded `constant` addresses (no constructor arguments, per Drosera stateless trap requirements). Tests use [`TestableBridgeRouterGuardTrap.sol`](./src/TestableBridgeRouterGuardTrap.sol) — same logic, constructor-injectable addresses for isolated CI. `shouldRespond()` and `shouldAlert()` are pure and address-independent; only `collect()` requires address injection.

> Full verbose test output available via `forge test -vv` for auditors and reviewers.

---
  
## Deployment  
  
### Live Contracts (Hoodi Testnet)  
  
| Contract | Address |  
| :--- | :--- |  
| **BridgeRouterGuardTrap** | [`0x1D880D83Ce107C6961495Ef767b8E4099A94F72E`](https://hoodi.etherscan.io/address/0x1D880D83Ce107C6961495Ef767b8E4099A94F72E) |  
| **BridgeRouterGuardResponse** | [`0x833c4F5CbE9CBf9f05ef44f99A69bb2487588685`](https://hoodi.etherscan.io/address/0x833c4F5CbE9CBf9f05ef44f99A69bb2487588685) |  
| **MockBridgeVault** | [`0xac031158562D5834416b47A89143B9d3059a2589`](https://hoodi.etherscan.io/address/0xac031158562D5834416b47A89143B9d3059a2589) |  
| **MockTokenGateway** | [`0xe629cC7b2ceB14380FA6c8c0C1431171AF411184`](https://hoodi.etherscan.io/address/0xe629cC7b2ceB14380FA6c8c0C1431171AF411184) |  
| **MockBridgeRouter** | [`0xF6C17127BBB5Cbc9234146A78B081ed68D0b8904`](https://hoodi.etherscan.io/address/0xF6C17127BBB5Cbc9234146A78B081ed68D0b8904) |  
  
### Telemetry & Dependencies  
  
**System Dependencies**  
* **Host Chain (Hoodi/EVM):** Where the protocol contracts and Response contract live.  
* **Drosera Network:** The decentralized p2p network of shadow operators.  
* **Alert Server & Web2 Command Center:** Routes `CRITICAL` JSON payloads to custom institutional telemetry endpoints (Node.js).  
  
**Live Testnet Configuration (`drosera.toml`)**  
```toml  
response_function        = "snapFreeze(uint256,uint256,bool)"  
block_sample_size        = 7        # raised from 3 — velocity traps need 5–8 blocks  
cooldown_period_blocks   = 33  
min_number_of_operators  = 1        # TESTNET ONLY — set >= 3 for production  
private_trap             = true  
```  
  
---  
  
## Relevance to Production Infrastructure  
  
This trap pattern is directly applicable to any EVM bridge or interoperability protocol. The invariant (**execution without validation**) and the three detection vectors map cleanly to:  
  
- **LayerZero** — abnormal `lzReceive()` execution velocity without a corresponding verified endpoint proof on the receiving `UltraLightNode`  
- **Axelar** — `execute()` / `expressExecute()` call patterns on `AxelarGateway` bypassing `validateContractCall()` (the exact CrossCurve vector)  
- **Wormhole** — Guardian VAA replay or forged message bypassing `verifyVM()` leading to unauthorized `completeTransfer()` mint  
- **Across Protocol** — `SpokePool` outflow velocity without matching `HubPool` deposit events or proof finalization  
- **Any lending protocol accepting bridged collateral** — phantom minted tokens used as collateral before the source-chain drain is detected  
  
A production deployment replaces the mock addresses with live protocol contracts, tunes the velocity thresholds to match historical normal flow baselines, and raises `min_number_of_operators` to ≥ 3.  
  
---  
  
## What's Next: Overcoming Infrastructure Constraints  
  
The following upgrades represent the production deployment roadmap. Each is a deliberate architectural decision — either blocked by a Drosera network constraint that is actively being addressed, or a feature that goes beyond the scope of a velocity circuit breaker into a distinct detection primitive:  
  
- **Oracle-Injected Asset Normalization:** Drosera's strict requirement that `shouldRespond()` remains a `pure` function means the Trap cannot natively query external price oracles. Future iterations will require expanding the `collect()` payload to safely ingest cryptographically verified off-chain oracle data.  
- **Off-Chain Statistical Processing (Dynamic Thresholds):** Replacing static thresholds with rolling-average math requires complex windowing that risks exceeding Drosera operator evaluation constraints. Production deployment will explore using Drosera's upcoming coprocessor to handle heavy statistical windowing.  
- **Mainnet Operator Quorum:** The current testnet environment limits the availability of independent operators. Upon mainnet release, `min_number_of_operators` must be raised to ≥ 3 with multisig execution enforcement on the Response contract to prevent unilateral operator griefing.  
- **Cross-Chain Relayer Expansion:** As the Drosera operator network officially expands its relayer support to Arbitrum, Base, and Optimism, this exact trap logic can be deployed cross-chain to monitor fragmented bridge endpoints natively.  
- **ZK Incident Response:** Integrate Drosera's zero-knowledge proof layer for optimistic claim disputes, ensuring that if an operator attempts a malicious `snapFreeze`, the protocol can mathematically challenge the evaluation payload.  
  
---  
  
## Component Deep Dive  
  
**`src/BridgeRouterGuardTrap.sol`** — Stateless sensor. Snapshots cumulative state from all three bridge components every block via `collect()`, then evaluates velocity deltas and per-block burst counts across a 7-block window in `shouldRespond()`. No state writes, no constructor args — fully Drosera-compliant.  
  
**`src/BridgeRouterGuardResponse.sol`** — Circuit breaker. On operator consensus, `snapFreeze()` best-effort pauses all three infrastructure contracts via try/catch, ensuring partial containment even if one target is already frozen. Hardened with two-step ownership, operator allowlist, and a 33-block on-chain cooldown.  
  
**`src/TestableBridgeRouterGuardTrap.sol`** — CI shadow. Inherits all production logic unchanged. Overrides only `collect()` to accept injected addresses instead of constants, enabling isolated Foundry testing without touching production code.  
  
**`src/mocks/`** — Vulnerable protocol simulation. Three contracts that deliberately replicate the structural weaknesses from real incidents: unmatched withdrawals (Multichain/Orbit), unverified admin and unbacked minting (IoTeX/Hyperbridge), unvalidated payload execution (CrossCurve/Socket).  
  
**`test/`** — Three layers. Core unit tests confirm threshold boundaries per vector. `AdversarialAttack.t.sol` and `FuzzAndEdgeCases.t.sol` pressure-test against threshold gaming, chunked drains, cold-start conditions, malformed inputs, and schema mismatches. `FullExploitSequence.t.sol` runs the complete pipeline end-to-end: exploit → detection → operator response → attacker blocked.  
  
**`test/attack/LiveHoodiExploit.s.sol`** — Unified modular campaign script. Accepts vault amount, chunk count, phantom amount, and router spoof flag via `--sig` to execute any attack combination against live testnet mocks.  
  
**`drosera.toml`** — Operator rules of engagement: block sampling window, cooldown, response function signature, quorum settings, and webhook routing.  
  
**`alert-server.js`** — Node.js telemetry bridge. Decodes `AlertData` payloads from the Drosera network and routes Vault Velocity, Phantom Velocity, and Router Spoof flag to Slack or any configured webhook endpoint.  
  
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

