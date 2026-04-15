# BridgeRouterGuard
### A guardrail for cross-chain execution without validation.

> A time-series, velocity-tracking circuit breaker for the cross-chain validation failure pattern class. Deployed and verified live on Hoodi Testnet.

---

## The Problem Didn't Change. Only the Bridges Did.

From July 2023 through April 2026, cross-chain bridges collectively lost over **$2.9B** to a single failure mode: **execution without validation**.

Every incident follows the same script: an off-chain validation layer — a multisig, an MPC cluster, a relayer, or a gateway contract — gets bypassed or compromised. The destination-chain router then executes a payload it has no business executing. Liquidity disappears. Phantom tokens appear. Weeks later, the bridge pauses.

---

## The Pattern Family: Unvalidated Cross-Chain Execution

Cross-chain bridge failures over the past three years follow a consistent pattern: **execution without validation**.

| Incident | Date | Loss | Root Cause | On-Chain Signal |
| :--- | :--- | :--- | :--- | :--- |
| [**Multichain**](https://www.halborn.com/blog/post/explained-the-multichain-hack-july-2023) | Jul 2023 | ~$231M | MPC keys compromised; router drained without deposit proofs | Unmatched mass withdrawal |
| [**Orbit Chain**](https://www.halborn.com/blog/post/explained-the-orbit-bridge-hack-december-2023) | Dec 2023 | ~$81M | 7/10 multisig signers phished; vault drained in sequence | Unmatched vault outflow |
| [**Socket Protocol**](https://www.halborn.com/blog/post/explained-the-socket-protocol-hack-january-2024) | Jan 2024 | ~$3.3M | Flawed approval logic; infinite cross-chain execution | Unauthorized `execute()` calls |
| [**Force Bridge**](https://www.halborn.com/blog/post/explained-the-force-bridge-hack-june-2025) | Jun 2025 | ~$3.7M | Compromised deployer key; multi-asset drain across endpoints | Drain without lock events |
| [**CrossCurve**](https://www.halborn.com/blog/post/explained-the-crosscurve-hack-february-2026) | Feb 2026 | ~$3.0M | Missing access control on `ReceiverAxelar`; spoofed `expressExecute` | Unauthorized payload execution |
| [**IoTeX ioTube**](https://www.halborn.com/blog/post/explained-the-iotex-hack-february-2026) | Feb 2026 | ~$4.4M | Validator upgrade bypassed signature checks; minted from MinterPool | Privilege escalation + phantom mint |
| [**Hyperbridge**](https://www.coindesk.com/tech/2026/04/13/attacker-mints-usd1-billion-polkadot-tokens-on-ethereum-ends-up-stealing-just-usd250-000) | Apr 2026 | $237K (1B phantom) | MMR proof replay; forged message granted admin control over bridged DOT | Unbacked mint spike |

The attack vector evolves — MPC compromise in 2023, message spoofing in 2026 — but the invariant never changes: **execution without validation**.

---

## The Trap

BridgeRouterGuard enforces a single invariant across three execution layers:

> **Execution without validation must never occur.**

It does this by monitoring the EVM state across a multi-block window and calculating the **velocity** of abnormal capital movement — catching both single large drains and chunked attacks designed to stay below static thresholds.

### Three Vectors. One Response.

**Vector 1 — High-Velocity Liquidity Drain** *(Multichain, Orbit Chain, Force Bridge)*

Attackers typically break large drains into smaller transactions to evade fixed thresholds. The trap tracks `cumulativeWithdrawals` across the `block_sample_size` window, computing the delta between the oldest and newest snapshot. A spike exceeding **1,000 ETH** in the window fires the response.

→ [`src/BridgeRouterGuardTrap.sol#L37-L38`](./src/BridgeRouterGuardTrap.sol#L37-L38) · [`src/mocks/MockBridgeVault.sol#L5-L10`](./src/mocks/MockBridgeVault.sol#L5-L10)

**Vector 2 — Privilege Escalation & Phantom Mint** *(IoTeX ioTube, Hyperbridge)*

Post-compromise, attackers grant themselves admin rights and mint unbacked tokens. The trap monitors `phantomMinted` state continuously. A delta exceeding **10,000 ETH** equivalent in a single window triggers containment, regardless of whether the escalation was via forged proof or key compromise.

→ [`src/BridgeRouterGuardTrap.sol#L39`](./src/BridgeRouterGuardTrap.sol#L39) · [`src/mocks/MockTokenGateway.sol#L12-L15`](./src/mocks/MockTokenGateway.sol#L12-L15)

**Vector 3 — Forged Router Payload** *(Socket Protocol, CrossCurve)*

The most direct attack: a payload executes on the router without passing through canonical gateway validation. This is a strict boolean invariant — if `spoofedMessageExecuted` is true, the response fires immediately, no velocity calculation needed.

→ [`src/BridgeRouterGuardTrap.sol#L40`](./src/BridgeRouterGuardTrap.sol#L40) · [`src/mocks/MockBridgeRouter.sol#L8-L12`](./src/mocks/MockBridgeRouter.sol#L8-L12)

---

## Architecture

The trap operates entirely out-of-band across decentralized shadow nodes. It never sits in-line with user transactions and adds zero gas overhead to normal protocol operations.

### How a Block Becomes a Containment

1. **Monitor** — Shadow operators call [`collect()`](./src/BridgeRouterGuardTrap.sol#L21-L27) on every new block, reading cumulative state from Vault, Gateway, and Router simultaneously.
2. **Evaluate** — [`shouldRespond()`](./src/BridgeRouterGuardTrap.sol#L29-L48) computes velocity deltas across the 3-block window. Delta above threshold → `true`.
3. **Attest** — The operator signs the result and gossips to the Drosera p2p network.
4. **Execute** — On consensus, one operator pays gas to call [`snapFreeze()`](./src/BridgeRouterGuardResponse.sol#L26-L31), pausing all three infrastructure contracts atomically.
5. **Alert** — [`shouldAlert()`](./src/BridgeRouterGuardTrap.sol#L52-L61) decodes the severity into an `AlertData` struct, routed as a `CRITICAL` JSON payload to protocol-configured Slack or Discord endpoints.

---

## Live Proof

### The Exercise

A Multichain-pattern attack was simulated on Hoodi Testnet — 1,500 ETH drained from the live MockBridgeVault in a single transaction, exceeding the 1,000 ETH velocity threshold. The Drosera operator network was live and monitoring.

### What Happened

| Event | Transaction | Block |
| :--- | :--- | :--- |
| **Malicious drain executed** | [`0x33925e5b...a079c1`](https://hoodi.etherscan.io/tx/0x33925e5b8e05a4ec19bb90933542c1cee8e635cd567737d435e8941585a079c1) | `2617548` |
| **snapFreeze triggered by operator** | [`0x6d96fcbc...044e1`](https://hoodi.etherscan.io/tx/0x6d96fcbcfca40a72905970889ab4f0b028c4077346b168edd66626df403044e1) | `2617549` |

Attack at block `2617548`. Containment at block `2617549`. **One block. ~12 seconds.**

### The Circuit Breaker Argument

> *If the attacker drained 1,500 ETH, doesn't that mean the exploit was successful?*

In single-chain protocols, yes. Cross-chain infrastructure is different.

Stealing from a vault on Chain A is step one. The attacker still needs cross-chain message finality before the router on Chain B releases the funds. That finality window is exactly where Drosera operates.

By the time `snapFreeze` fires at block `2617549`, the cross-chain messages are already dead. The router is paused. The gateway can't mint. The attacker has 1,500 ETH of heavily monitored assets on a frozen chain and no path forward. The remaining TVL, (the $197M, or $81M, or $231M), never moves.

This is the detection signal that saves everything else.

---

## Local Test Suite

```bash
forge test -vv
```

Full coverage across four test contracts:

| Test File | What It Proves |
| :--- | :--- |
| [`test/VaultDrain.t.sol`](./test/VaultDrain.t.sol) | Velocity math fires on spike; ignores normal volume; catches chunked drains |
| [`test/PhantomMint.t.sol`](./test/PhantomMint.t.sol) | Delta detection fires on phantom mint; ignores sub-threshold mints |
| [`test/RouterSpoof.t.sol`](./test/RouterSpoof.t.sol) | Boolean invariant fires immediately on spoofed payload |
| [`test/ResponseAuth.t.sol`](./test/ResponseAuth.t.sol) | Unauthorized callers revert; only owner can set operators |

> **Architecture note:** The production trap uses hardcoded `constant` addresses (no constructor arguments, per Drosera stateless trap requirements). Tests use [`TestableBridgeRouterGuardTrap.sol`](./src/TestableBridgeRouterGuardTrap.sol) — same logic, constructor-injectable addresses for isolated CI.

---

## Deployment

### Live Contracts (Hoodi Testnet)

| Contract | Address |
| :--- | :--- |
| **BridgeRouterGuardTrap** | [`0x1D880D83Ce107C6961495Ef767b8E4099A94F72E`](https://hoodi.etherscan.io/address/0x1D880D83Ce107C6961495Ef767b8E4099A94F72E) |
| **BridgeRouterGuardResponse** | [`0x1Ec29Ad65831CB73929CB75949a7EC9E15a1E60e`](https://hoodi.etherscan.io/address/0x1Ec29Ad65831CB73929CB75949a7EC9E15a1E60e) |
| **MockBridgeVault** | [`0x83c9e182b10aC6B62C559F9092C0Cfc12394Ab1E`](https://hoodi.etherscan.io/address/0x83c9e182b10aC6B62C559F9092C0Cfc12394Ab1E) |
| **MockTokenGateway** | [`0x544fFbCde66A95b24829EB6a5e803d27E7737Dc1`](https://hoodi.etherscan.io/address/0x544fFbCde66A95b24829EB6a5e803d27E7737Dc1) |
| **MockBridgeRouter** | [`0xca324202c796Aa8A5d8Ddcac384852854A253D66`](https://hoodi.etherscan.io/address/0xca324202c796Aa8A5d8Ddcac384852854A253D66) |

### Telemetry & Dependencies

**System Dependencies**
* **Host Chain (Hoodi/EVM):** Where the protocol contracts and Response contract live.
* **Drosera Network:** The decentralized p2p network of shadow operators.
* **Alert Server & Web2 Command Center:** Routes `CRITICAL` JSON payloads directly to institutional Slack/Discord endpoints.

**Live Testnet Configuration (`drosera.toml`)**
```toml
response_function = "snapFreeze(uint256,uint256,bool)"
block_sample_size = 3
cooldown_period_blocks = 33
private_trap = true
slack = { slack_channel = "#general" }
```

---

## Relevance to Production Infrastructure

This trap pattern is directly applicable to any EVM bridge or interoperability protocol — not just the mock infrastructure used here. The invariant (**execution without validation**) and the three detection vectors map cleanly to:

- **LayerZero** — `lzReceive()` execution without valid endpoint proof
- **Axelar** — `execute()` / `expressExecute()` bypass on gateway contracts (the exact CrossCurve vector)
- **Wormhole** — Guardian VAA replay or forged message leading to unauthorized mint
- **Across Protocol** — Spoke pool drain without matching hub pool deposit events
- **Any lending protocol accepting bridged collateral** — phantom minted tokens used as collateral before the drain is detected

The mock contracts in this PoC deliberately replicate the structural vulnerabilities found in these real systems. A production deployment replaces the mock addresses with live protocol contracts and tunes the velocity thresholds to match historical normal flow baselines.

---

## What's Next

- **Dynamic thresholds** — Replace static ETH values with standard-deviation-based limits calculated from rolling block history, eliminating threshold-gaming attacks entirely.
- **Multi-chain operator coverage** — As Drosera expands to additional EVM L2s, this trap can be replicated across Arbitrum, Base, and Optimism bridge infrastructure without logic changes.
- **ZK incident response** — Integrate Drosera's zero-knowledge proof layer for optimistic claim disputes in multi-operator environments.

---

---

## Repository Structure & Core Components

```text
bridge-router-guard/
├── src/                                  # Production defense contracts
│   ├── BridgeRouterGuardTrap.sol         # The core velocity-tracking state machine
│   ├── BridgeRouterGuardResponse.sol     # The execution contract for `snapFreeze` containment
│   ├── TestableBridgeRouterGuardTrap.sol # CI/CD shadow contract allowing constructor injection
│   └── mocks/                            # Protocol simulation infrastructure
│       ├── MockBridgeVault.sol
│       ├── MockTokenGateway.sol
│       └── MockBridgeRouter.sol
├── test/                                 # Mathematical proofs and isolation tests
│   ├── VaultDrain.t.sol                  # Validates math for the chunked withdrawal attack vector
│   ├── PhantomMint.t.sol                 # Validates invariant checks for privilege escalation
│   ├── RouterSpoof.t.sol                 # Validates instantaneous detection of skipped validation
│   ├── ResponseAuth.t.sol                # Verifies RBAC so only Drosera Operators can pause
│   ├── attack/                           # Exploit simulation scripts and live network proofs
│   │   └── LiveHoodiExploit.s.sol
│   └── utils/
│       └── BridgeTestBase.t.sol
├── script/                               # Deployment configuration
│   ├── DeployMocks.sol
│   └── DeployResponse.sol
├── lib/                                  # Standard Foundry dependencies (forge-std, drosera-contracts)
├── drosera.toml                          # Mesh configuration, block sampling, and Operator thresholds
└── alertserver.js                        # Node.js webhook listener parsing on-chain telemetry to Web2
```

### Component Deep Dive

* **`src/` & `mocks/` (The Defense Mesh):** Contains the core active defense logic. The Trap processes historical arrays to calculate capital flight velocity, while the Response holds the operator logic to instantly freeze infrastructure. The `mocks/` directory simulates a standard, vulnerable cross-chain protocol (Vault, Gateway, Router) to safely validate containment against live vectors.
* **`test/` (The Proofs):** Divided into two layers. The core `.t.sol` files are isolated unit tests confirming strict mathematical boundaries (ensuring zero false positives). The `attack/` subdirectory contains full execution scripts that perfectly mirror the Multichain, CrossCurve, and Hyperbridge exploits.
* **`drosera.toml`:** The operational config file. It dictates the shadow nodes' rules of engagement, defining block sampling bounds, cooldown periods, and the required response function signatures.
* **`alertserver.js`:** The Web2 telemetry bridge. Catches off-chain Trap events and routes the decoded JSON payload (Vault Velocity, Phantom Mint Spikes, Router Spoofs) directly to institutional Slack or Discord channels.

---

*Deployed on Hoodi Testnet. All transactions verifiable on-chain.*
