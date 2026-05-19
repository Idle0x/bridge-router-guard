# BridgeRouterGuard

A stateless accounting-reconciliation trap for cross-chain bridge infrastructure, enforced by the [Drosera](https://drosera.io) decentralized operator network.

*Deployed and verified on Hoodi Testnet. All transactions verifiable on-chain.*

---

## The Problem

Between July 2023 and April 2026, eight cross-chain bridge exploits produced over $620M in confirmed losses. Every incident follows the same script: an off-chain validation layer gets compromised or bypassed.

The mechanisms varied — compromised MPC keys, poisoned DVN infrastructure, missing access control, forged cryptographic proofs — but the consequence did not vary. In every case, the destination chain released assets or minted tokens without a corresponding validated event on the source chain.

The same failure mode has been repeated across multiple incidents: execution without validation.

---

## The Enforced Invariants

Four accounting equalities are monitored across every evaluation window:

```
executedWithdrawals     == validatedInboundCredits      (Vector 1)
cumulativeMinted        == validatedMintAuthorizations   (Vector 2)
executedMessages        == gatewayValidatedMessages      (Vector 3)
vaultTokenBalance       >= executedWithdrawals           (Vector 4)
```

Any deviation — any execution without the corresponding validation — triggers the response. Vectors 1, 2, and 4 evaluate deltas across a 7-block trailing window assembled by the operator runtime. Vector 3 is a hard invariant: a single unauthorized execution fires immediately from a single sample, with no prior history required.

---

## The Pattern Family

These incidents were selected not for size or notoriety, but because they share the same structural invariant and collectively test the full detection boundaries of the trap.

| Incident | Date | Loss | Root Cause | Primary Vector | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [Multichain](./case-studies/001-multichain-jul-2023.md) | Jul 2023 | ~$231M | MPC keys seized; vault drained over 4 hours without deposit proofs | Vector 1 | `CAUGHT (pre-drain)` |
| [Orbit Chain](./case-studies/002-orbit-chain-dec-2023.md) | Dec 2023 | ~$81.68M | 7-of-10 multisig compromised; five parallel asset streams | Vector 1 | `CAUGHT (pre-drain)` |
| [Socket Protocol](./case-studies/003-socket-protocol-jan-2024.md) | Jan 2024 | ~$3.3M | Calldata injection draining user approvals via unsanitized router | — | `PARTIAL` |
| [Force Bridge](./case-studies/004-force-bridge-jun-2025.md) | Jun 2025 | ~$3.7M | Compromised deployer key; 6-hour pre-attack window on-chain | Vector 1 | `CAUGHT (pre-drain)` |
| [CrossCurve](./case-studies/005-crosscurve-feb-2026.md) | Feb 2026 | ~$2.76M | Missing access control on `expressExecute()`; forged payloads across 9 chains | Vector 3 | `CAUGHT (post-drain)` |
| [IoTeX ioTube](./case-studies/006-iotex-iotube-feb-2026.md) | Feb 2026 | ~$4.4M | Single-key Validator ownership; malicious upgrade seized TokenSafe and MintPool | Vector 1 | `CAUGHT (post-drain)` |
| [Hyperbridge](./case-studies/007-hyperbridge-apr-2026.md) | Apr 2026 | ~$2.5M | MMR proof bounds-check gap; forged message granted admin over bridged DOT | Vector 1 & Vector 2 | `CAUGHT (post-drain)` |
| [Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md) | Apr 2026 | ~$292M | 1-of-1 DVN poisoned via RPC node compromise; forged `lzReceive()` drained rsETH reserve | Vector 1 | `CAUGHT (post-drain)` |

Socket Protocol is the correct counterexample: approval-draining attacks against individual user wallets produce no signal in any of the four bridge accounting invariants. Every detection claim in the other seven rows is more credible because this one is stated plainly.

### Verdict Labels

| Verdict | Meaning |
| :--- | :--- |
| `CAUGHT (pre-drain)` | Trap fires before the majority of losses complete; attack was progressive (multi-transaction, multi-block) |
| `CAUGHT (post-drain)` | Initial loss completes in one block or one transaction (unavoidable); all follow-on damage contained |
| `PARTIAL` | Trap fires but monitors wrong contracts or wrong state for this attack class |
| `NOT CAUGHT` | Exploit is structurally outside the trap's detection surface |

For synthesis across all eight cases and the aggregate damage estimates, see [009 — What This Work Revealed](./case-studies/009-what-this-work-revealed.md).

---

## The Trap

### Vector 1 — Vault Drain Mismatch

*Enforces: `executedWithdrawals == validatedInboundCredits`*

*References: [Multichain](./case-studies/001-multichain-jul-2023.md) · [Orbit Chain](./case-studies/002-orbit-chain-dec-2023.md) · [Force Bridge](./case-studies/004-force-bridge-jun-2025.md) · [IoTeX ioTube](./case-studies/006-iotex-iotube-feb-2026.md) · [Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md)*

Fires when withdrawal execution outpaces validated inbound credit. Two paths:

**Zero-backing hard trigger** — any execution growth against zero credit growth fires immediately, regardless of amount. This covers every case where the authorization layer was bypassed or compromised entirely. `validatedInboundCredits` never moves when the source-chain deposit never happened.

```solidity
if (execGrowth > 0 && creditGrowth == 0) {
    return (true, abi.encode(execGrowth, uint256(0), uint256(0), uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol) · [`src/mocks/core/MockBridgeVault.sol`](./src/mocks/core/MockBridgeVault.sol)

**Threshold path** — partial-backing scenarios where some credit exists but execution exceeded it by more than `VAULT_DRAIN_THRESHOLD`. Evaluates `execGrowth - creditGrowth` across the 7-block window.

---

### Vector 2 — Gateway Phantom Mint Mismatch

*Enforces: `cumulativeMinted == validatedMintAuthorizations`*

*References: [IoTeX ioTube](./case-studies/006-iotex-iotube-feb-2026.md) · [Hyperbridge](./case-studies/007-hyperbridge-apr-2026.md) · [Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md)*

Fires when minted token supply outpaces validated mint authorizations. Same two-path structure as Vector 1: zero-backing triggers immediately on any mint against zero authorization; threshold path evaluates `mintGrowth - authGrowth` against `PHANTOM_MINT_THRESHOLD`.

The IoTeX CIOTX mint (~656 ETH equivalent) falls below the 10,000 ETH static threshold. Vector 1 fires independently and is sufficient. The gap documents the known limitation of static ETH-equivalent thresholds for low-denomination tokens — oracle-backed asset normalization is the production fix. The Hyperbridge 1B DOT mint (~511,000 ETH equivalent) exceeds threshold by ~51×.

→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol) · [`src/mocks/core/MockTokenGateway.sol`](./src/mocks/core/MockTokenGateway.sol)

---

### Vector 3 — Router Unauthorized Execution

*Enforces: `executedMessages == gatewayValidatedMessages`*

*References: [CrossCurve](./case-studies/005-crosscurve-feb-2026.md)*

Hard invariant. Fires on any gap between executed messages and gateway-validated messages. A single unauthorized execution fires immediately on the same block — no prior sample needed, no threshold.

```solidity
if (newest.executedMessages > newest.gatewayValidatedMessages) {
    uint256 unauthorizedExecs = newest.executedMessages - newest.gatewayValidatedMessages;
    return (true, abi.encode(uint256(0), uint256(0), unauthorizedExecs, uint256(0)));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol) · [`src/mocks/core/MockBridgeRouter.sol`](./src/mocks/core/MockBridgeRouter.sol)

This vector fires for CrossCurve — `expressExecute()` was called directly without touching the gateway validation layer, leaving `gatewayValidatedMessages` at zero while `executedMessages` grew by 1. It does **not** fire for Kelp DAO: the poisoned DVN deceived the validator rather than bypassing it, causing both counters to increment together. Kelp DAO is caught by Vector 1 instead. This distinction is documented in [008 — Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md) and [009](./case-studies/009-what-this-work-revealed.md#the-corrections-that-changed-the-case-studies).

---

### Vector 4 — Reserve Reconciliation

*Enforces: `vaultTokenBalance >= executedWithdrawals`*

Backstop for counter-bypass attacks. If an attacker moves tokens through a path that does not update `executedWithdrawals` — such as a direct token transfer function that bypasses the accounting layer — Vectors 1, 2, and 3 produce zero signal. Vector 4 catches it by comparing `vaultTokenBalance` directly against execution counter growth: if the balance dropped more than the counter grew, funds moved without any accounting record.

```solidity
uint256 balanceDrop = oldest.vaultTokenBalance > newest.vaultTokenBalance
    ? oldest.vaultTokenBalance - newest.vaultTokenBalance : 0;
uint256 reserveDrain = balanceDrop > execGrowth ? balanceDrop - execGrowth : 0;
if (reserveDrain > VAULT_DRAIN_THRESHOLD) {
    return (true, abi.encode(uint256(0), uint256(0), uint256(0), reserveDrain));
}
```
→ [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol) · [`src/mocks/core/MockBridgeVault.sol`](./src/mocks/core/MockBridgeVault.sol)

---

## Architecture

The trap is stateless on-chain. All temporal mechanics are handled by the operator runtime.

| Function | Location | Responsibility |
| :--- | :--- | :--- |
| `collect()` | On-Chain Trap | Reads 8 accounting fields from vault, gateway, router. Outputs versioned `CollectOutput`. |
| `shouldRespond()` | On-Chain Trap | Stateless delta evaluation across sample array. Returns `(bool, bytes)`. No storage writes. |
| `shouldAlert()` | On-Chain Trap | Decodes 4-tuple mismatch payload into `AlertData` for telemetry routing. |
| 7-Block Trailing Window | Operator Runtime | Assembles rolling sample array. Maintains `true` state for N+1 to N+6 after a trigger. |
| 33-Block Cooldown | Operator + Response Contract | Suppresses duplicate submissions after successful `snapFreeze()`. Enforced on-chain. |
| P2P Consensus / Race Sync | Operator Network | Gossips attestations, aggregates signatures, selects submitter, syncs cooldown on race loss. |
| `snapFreeze()` | On-Chain Response | Executes best-effort `emergencyPause()` on vault, gateway, router via `try/catch`. |

### How a Block Becomes a Containment

1. Every operator node calls `collect()` independently on each new block, reading `executedWithdrawals`, `validatedInboundCredits`, `cumulativeMinted`, `validatedMintAuthorizations`, `executedMessages`, `gatewayValidatedMessages`, and `vaultTokenBalance` simultaneously. Output is versioned via `CollectOutput.schemaVersion`.
2. Each node evaluates `shouldRespond()` against the assembled 7-block window. Schema version mismatch between samples returns a zeroed struct — treated as no signal rather than a trigger.
3. If `shouldRespond()` returns true, nodes broadcast their signed attestation via P2P.
4. Once the operator threshold is reached, one node submits the transaction calling `snapFreeze()` on [`BridgeRouterGuardResponse`](./src/core/BridgeRouterGuardResponse.sol).
5. `snapFreeze()` pauses vault, gateway, and router via `emergencyPause()` on each target — best-effort with `try/catch`, so a partially-paused target does not block the others.
6. `AttackPrevented` is emitted with actual mismatch deltas: `drainDelta`, `mintDelta`, `unauthorizedExecs`, `reserveDrain`.
7. The 33-block cooldown activates. Further submissions are suppressed until `cooldownBlock + 33`.

### Bootstrap Safety

`shouldRespond()` requires at least 2 samples for Vectors 1, 2, and 4 before firing on velocity signals. A bridge with normal lifetime volume above the threshold would false-trigger on cold start or operator restart without this guard. Vector 3 is exempt — any `executedMessages > gatewayValidatedMessages` is an invariant violation from the first sample.

### Freeze Semantics

`snapFreeze()` uses `try/catch` around each `emergencyPause()` call. If a target is already paused or reverts, the remaining targets are still attempted. Partial containment is strictly better than zero containment. Every target's pause result is emitted as a `TargetPauseResult` event for full off-chain visibility.

---

## Testnet Validation

The campaign ran on Hoodi Testnet across blocks [2801234](https://hoodi.etherscan.io/tx/0x3bbd4ac8b81d2ea8359e3ff0c57cd8aa4e0dc18df1c34a49581f92ccc5a0435a)–[2801814](https://hoodi.etherscan.io/tx/0xe5e6276d2f145bd2020bc7f8d7a25b19328b2edfe5cc3e3c88ed21e6a2bb8082). What the campaign validates that the local suite cannot: contracts deploy correctly to a real chain, the Drosera operator network reaches consensus and calls `snapFreeze()` for real, cooldown is enforced by real block numbers, and attacker transactions revert against frozen contracts with real gas spent.

### Baseline Invariant & Zero-Backing Detection

The first exploitation ran at block [2801240](https://hoodi.etherscan.io/tx/0x3bbd4ac8b81d2ea8359e3ff0c57cd8aa4e0dc18df1c34a49581f92ccc5a0435a): 250 ETH drained from the vault with zero credit growth. 250 ETH is below `VAULT_DRAIN_THRESHOLD`, but the zero-backing path fires regardless of amount. The operator network confirmed `shouldRespond = true` within three blocks, establishing the baseline invariant: any execution against zero validated credit triggers immediately.

| Event | Tx Hash | Block |
| :--- | :--- | :--- |
| Zero-backing drain trigger | [`0x3bbd4ac8...`](https://hoodi.etherscan.io/tx/0x3bbd4ac8b81d2ea8359e3ff0c57cd8aa4e0dc18df1c34a49581f92ccc5a0435a) | 2801240 |

### Threshold Precision & Boundary Behavior

Precision boundaries were validated immediately after. Campaigns at blocks [2801246](https://hoodi.etherscan.io/tx/0x0c6aa55b583e6faeda0126e24a27ce3b1fb6033e5384ab0da78f36b06d700cd5), [2801255](https://hoodi.etherscan.io/tx/0x58fe0ade5dbf1687a27ab3cb6810bcab441000e06eee512d2e93871fef2b3a78), [2801259](https://hoodi.etherscan.io/tx/0x8092aec0bfa254a68a76c862447964bb727ee2292be6ab41dc73ddd6b1bfd073), and [2801264](https://hoodi.etherscan.io/tx/0x6d2786646dde7201eb825eb174a56e1954441f5b07c26e1828cc2e39a784a9d3) correctly returned `shouldRespond = false`. Partial backing was present, amounts sat exactly at or below threshold, and the trap did not false-positive. The threshold is strictly `>`, not `>=`. This precision is intentional: a circuit breaker that alerts on legitimate high-volume activity or exact-boundary math is operationally useless.

| Block | Campaign | Why no trigger |
| :--- | :--- | :--- |
| [2801246](https://hoodi.etherscan.io/tx/0x0c6aa55b583e6faeda0126e24a27ce3b1fb6033e5384ab0da78f36b06d700cd5) | `executeCampaign(C=2500e18, D=100e18)` — 2,400 ETH V2 net mismatch | Partial backing present; below `PHANTOM_MINT_THRESHOLD` (10,000 ETH) |
| [2801255](https://hoodi.etherscan.io/tx/0x58fe0ade5dbf1687a27ab3cb6810bcab441000e06eee512d2e93871fef2b3a78) | `silentDrainCampaign(400e18)` | 400 ETH below `VAULT_DRAIN_THRESHOLD` (1,000 ETH) |
| [2801259](https://hoodi.etherscan.io/tx/0x8092aec0bfa254a68a76c862447964bb727ee2292be6ab41dc73ddd6b1bfd073) | `executeCampaign(A=1100e18, B=100e18)` — 1,000 ETH net drain | `drainDelta = 1,000 ETH`; threshold is `> 1,000 ETH`, not `≥` |
| [2801264](https://hoodi.etherscan.io/tx/0x6d2786646dde7201eb825eb174a56e1954441f5b07c26e1828cc2e39a784a9d3) | `executeCampaign(C=10100e18, D=100e18)` — 10,000 ETH net mint | `mintDelta = 10,000 ETH`; threshold is `> 10,000 ETH`, not `≥` |

### Window Behavior & State Persistence

A 1,500 ETH zero-backing drain executed at block [2801307](https://hoodi.etherscan.io/tx/0xd7cc7905a0e379dfa1137205ead35faa940228b3813208af7dd861c3bc1cf103) triggered `shouldRespond = true`. The operator network reached consensus and `snapFreeze()` executed at block [2801308](https://hoodi.etherscan.io/tx/0x730e9e7a95c5870bd878d07deaae8881d6cb0e9069571c1198535e2f30e206f5), demonstrating a consistent 1-block latency between trigger detection and on-chain freeze execution when no cooldown is active.

Once `executedWithdrawals` exceeds `validatedInboundCredits`, the mismatch does not self-correct. There is no mechanism that increases `validatedInboundCredits` without a real source-chain oracle event. The trap remains in a sustained `true` state until contracts are redeployed with fresh state. The campaign executed three deployment cycles for this exact reason: after exploits permanently altered state, redeployment was required to reset context and test subsequent vectors in isolation. This matches real incident response workflows — detect, freeze, redeploy clean contracts, resume monitoring.

| Contract Deployed | Address |
| :--- | :--- |
| MockBridgeVault (Cycle 1) | [`0xF71028B003F9450EAd5B1Eb6043E6907a4dB9398`](https://hoodi.etherscan.io/address/0xF71028B003F9450EAd5B1Eb6043E6907a4dB9398) |
| MockTokenGateway (Cycle 1) | [`0xE6c0C96a28788343b89cF7dfD47f9D9E5c3ecdeC`](https://hoodi.etherscan.io/address/0xE6c0C96a28788343b89cF7dfD47f9D9E5c3ecdeC) |
| MockBridgeRouter (Cycle 1) | [`0xC66C4Eabc73a1C05625e43707974969DcBeb260D`](https://hoodi.etherscan.io/address/0xC66C4Eabc73a1C05625e43707974969DcBeb260D) |
| BridgeRouterGuardResponse (Cycle 1) | [`0xBFC4fB3865Cd56Cb776d6CE7070dA919f851eBdA`](https://hoodi.etherscan.io/address/0xBFC4fB3865Cd56Cb776d6CE7070dA919f851eBdA) |

*Each deployment cycle rotated mock ERC20 token reserves to simulate fresh liquidity environments. Token contracts used across the campaign: `0x5e5B0F232B5f598e82bd4dBfDA6b8925958B1628` (Cycle 0), `0x0A7a34DC2Ed2C645a59E3df85780f3842dA5E3A1` (Cycle 1), `0x5170e921dfa7f79F823da053D76262F34a7a88FF` (Cycles 2–3).*

### Vector 2: Phantom Mint & Cooldown Enforcement

Following the first context reset, Vector 2 was validated at block [2801692](https://hoodi.etherscan.io/tx/0x46c32899c846291d7c8af1735add32ef647962667dbba0367118c2a78ccf5da0): 15,000 ETH equivalent minted with zero authorization. `shouldRespond = true` fired correctly. The campaign ran this test during an active cooldown period from block [2801685](https://hoodi.etherscan.io/tx/0x2ec7505fd644908a8e0ba12c33dbf657d24537b4ca34f9294e6ee306f6cb6196), so no second `snapFreeze()` transaction was submitted. Cooldown suppression is the correct operator behavior, not a detection failure. The intentional partial-authorization bypass (where `authGrowth > 0` suppresses the trigger to avoid false positives on legitimate cross-chain minting) remains documented as a precision-over-recall tradeoff.

### Vector 3: Router Hard Invariant

Vector 3 was validated at block [2801814](https://hoodi.etherscan.io/tx/0xe5e6276d2f145bd2020bc7f8d7a25b19328b2edfe5cc3e3c88ed21e6a2bb8082): a single unauthorized `expressExecute()` with `Flag=true`. `executedMessages` grew by 1, `gatewayValidatedMessages` stayed at zero. The hard invariant fired immediately from a single sample. The operator network aggregated attestations and reached signature threshold without engaging the 33-block cooldown lock, confirming the flag bypass behavior used for attestation-only telemetry.

| Event | Tx Hash | Block | Timestamp (UTC) |
| :--- | :--- | :--- | :--- |
| Router hard invariant trigger | [`0xe5e6276d...`](https://hoodi.etherscan.io/tx/0xe5e6276d2f145bd2020bc7f8d7a25b19328b2edfe5cc3e3c88ed21e6a2bb8082) | 2801814 | May-12-2026 10:48:12 PM |

### Vector 4: Reserve Reconciliation

Vector 4 was validated across blocks [2801651](https://hoodi.etherscan.io/tx/0x2d316c2d31dcdee327eeb20d06883786e5f6d44aebcaf316338b23a082a9acb1) and [2801682](https://hoodi.etherscan.io/tx/0x2ec7505fd644908a8e0ba12c33dbf657d24537b4ca34f9294e6ee306f6cb6196). 1,200 ETH moved via `directTokenTransfer()` without touching `executedWithdrawals`. The balance drop was not reflected in the execution counter, producing `reserveDrain = 1,200 ETH`. Due to an active 33-block cooldown from a prior trigger and P2P operator selection sync, `snapFreeze()` executed at block [2801686](https://hoodi.etherscan.io/tx/0x1d2f6d2b6ed81d8a78b7dcfcfcb0557ef3cb70452dda6672ace7cc8143a26c9d), demonstrating a 4-block latency when cooldown constraints are active. This proves the backstop catches counter-bypass drains that Vectors 1, 2, and 3 cannot see, and confirms real cooldown enforcement on-chain.

| Event | Tx Hash | Block | Timestamp (UTC) |
| :--- | :--- | :--- | :--- |
| Silent drain trigger | [`0x2ec7505f...`](https://hoodi.etherscan.io/tx/0x2ec7505fd644908a8e0ba12c33dbf657d24537b4ca34f9294e6ee306f6cb6196) | 2801682 | May-12-2026 10:19:24 PM |
| `snapFreeze()` execution | [`0x1d2f6d2b...`](https://hoodi.etherscan.io/tx/0x1d2f6d2b6ed81d8a78b7dcfcfcb0557ef3cb70452dda6672ace7cc8143a26c9d) | 2801686 | May-12-2026 10:20:12 PM |

### Multi-Vector & Consecutive Execution

Rapid successive violations were tested at blocks [2801698](https://hoodi.etherscan.io/tx/0x421289baa6949c2c7691d9b3f02718b576c12b2d5d8063967fcd45aa8572853a)/[2801699](https://hoodi.etherscan.io/tx/0x70191ddcdc59a6ba7a167ac0647a005ae0dae296efde60d3dd0588643a1641ac) and [2801729](https://hoodi.etherscan.io/tx/0x33284ed9579f2f6063e5439b462e68c045b72a02e87505d4b37ab4fdb3581a52)/[2801730](https://hoodi.etherscan.io/tx/0x65883a094d15a6165cbbc64ab5749b3fcfe649bad8d0cea37f5ca2db25781277). Silent drains and counter drains fired within 1-block gaps. The 7-block trailing window chained correctly across consecutive triggers, the 33-block cooldown enforced submission suppression without state corruption, and `snapFreeze()` executed at block [2801731](https://hoodi.etherscan.io/tx/0x2faf74b408f14aa2f0b5b944e919f31e58984f4c24f56b21c5dfe4d5b00be28c), returning to the baseline 1-block latency once cooldown constraints cleared. The trap handles overlapping signals deterministically.

### Scope Boundary: Pre-Attack Signals

The scope boundary was validated at block [2801775](https://hoodi.etherscan.io/tx/0x666910091398ac83a1e32f0f0e118df11bff10518b063024ad6466f0e47a9865): `preAttackCampaign` executed 3 transactions against `MockPrivilegedBridge`. `BridgeRouterGuard` returned `shouldRespond = false` because no accounting mismatch occurred. `PreAttackMonitorTrap` correctly registered `failedAttemptCount = 5`. BridgeRouterGuard monitors accounting divergence. Pre-attack state manipulation requires a different detection primitive. Neither substitutes for the other.

| Event | Tx Hash | Block | Timestamp (UTC) |
| :--- | :--- | :--- | :--- |
| Pre-attack probe 1 | [`0x66691009...`](https://hoodi.etherscan.io/tx/0x666910091398ac83a1e32f0f0e118df11bff10518b063024ad6466f0e47a9865) | 2801775 | May-12-2026 10:39:36 PM |
| Pre-attack probe 2 | [`0x9d0882e1...`](https://hoodi.etherscan.io/tx/0x9d0882e1ac7e6a0cddedb6459b01e21433cb6a50bd603a26ec72bc9c078ab71d) | 2801775 | May-12-2026 10:39:36 PM |
| Pre-attack probe 3 | [`0x6ae6ace2...`](https://hoodi.etherscan.io/tx/0x6ae6ace20863d1687f79898a4bfd1004738c2cde51c71378adac23632a8bb085) | 2801775 | May-12-2026 10:39:36 PM |

---

## The Circuit Breaker Argument

Cross-chain attacks are a process, not a single transaction. The initial drain is step one. The attacker still needs to move, swap, or mint on another chain to exit with real value — and that window is where containment operates.

For [Multichain](./case-studies/001-multichain-jul-2023.md) and [Orbit Chain](./case-studies/002-orbit-chain-dec-2023.md) the argument is straightforward: both were progressive drains spanning hours. Multichain drained over 4 hours. Orbit Chain ran five asset streams across 90 minutes. The trap fires on the first threshold breach — everything still in the bridge after that point has block numbers.

[Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md) is the clearest case for post-drain containment. The initial drain ($292M) completed in one transaction and cannot be stopped — the trap fires on block N+1. But the attacker returned at 18:26 and 18:28 UTC with two follow-up attempts worth ~$100M each. Both reverted against Kelp's manual pause 46 minutes after the drain. With the trap, both revert within blocks of the initial drain. The 46-minute gap is also where the Aave bad debt happened — the attacker deposited stolen rsETH as collateral and borrowed ~$236M in real ETH during that window.

BridgeRouterGuard handles the bridge reserve, gateway, and router layer. What happens to funds that already left the bridge, and what happens in downstream protocols, requires additional traps watching those surfaces. See [010 — Architecture and Extensions](./case-studies/010-architecture-and-extensions.md) for the full layered stack.

---

## Design Envelope and Out-of-Scope Scenarios

*This system is scoped for accounting-invariant violations on bridge reserve contracts. The following fall outside that scope by design.*

**Atomic single-block drains as trigger events.** The transaction that fires the trap is already confirmed on-chain before `snapFreeze()` executes. This applies to Kelp DAO's 116,500 rsETH drain, CrossCurve's per-chain drains, and any exploit that completes in one transaction. Containment operates on everything after the trigger event.

**Approval-draining attacks against user wallets.** [Socket Protocol](./case-studies/003-socket-protocol-jan-2024.md) demonstrates this precisely: no bridge reserve was touched, no accounting counter moved. The four vectors have nothing to evaluate.

**Off-chain attack precursors.** Key compromise, RPC poisoning, social engineering — none of these produce on-chain signals before funds move. The trap detects the on-chain consequence.

**Sub-threshold partial-backing violations.** An attacker who provides partial credit backing and keeps the net mismatch below threshold passes the threshold check. The zero-backing path catches any execution with zero credit at any amount.

**Multi-chain deployment gaps.** A single deployment monitors one set of contract addresses on one chain. CrossCurve's 9-chain drain and Kelp DAO's 20+ L2 minting require independent deployments per chain.

**Operator downtime during the trigger block.** If no operator is online when the attack block is produced, detection is deferred. Production deployments require `min_number_of_operators ≥ 3`.

---

## Concept Traps

Four additional traps extend the detection surface to points in the attack chain that BridgeRouterGuard does not cover. All four are implemented, tested, and demonstrated in the testnet campaign. Full design and test coverage in [010 — Architecture and Extensions](./case-studies/010-architecture-and-extensions.md).

| Trap | Monitors | Catches |
| :--- | :--- | :--- |
| [`OwnershipMonitorTrap`](./src/concepts/OwnershipMonitorTrap.sol) | `owner()` / `implementation()` on bridge token contracts | Admin changes before phantom minting — IoTeX, Hyperbridge |
| [`PreAttackMonitorTrap`](./src/concepts/PreAttackMonitorTrap.sol) | `failedAttemptCount` on privileged bridge functions | Failed privileged calls before successful drain — Force Bridge, Orbit Chain |
| [`PositionMonitorTrap`](./src/concepts/PositionMonitorTrap.sol) | Collateral composition and utilization in lending pools | Stolen bridge token collateral concentration — Kelp DAO / Aave |

A fourth concept (DVN attestation liveness monitoring) is described in [010](./case-studies/010-architecture-and-extensions.md#trap-4--dvn-attestation-liveness-monitor) without implementation — the empirical data needed to calibrate it against false positives does not yet exist.

---

## Local Test Suite

```bash
forge test -vv
```

| Metric | Result |
| :--- | :--- |
| Test Suites | 8 |
| Total Tests | 83 |
| Pass Rate | 100% |
| Fuzz Runs | 1,024+ across critical thresholds |
| Failures | 0 |

### Test Coverage

| File | Coverage |
| :--- | :--- |
| [`test/core/VaultDrain.t.sol`](./test/core/VaultDrain.t.sol) | Vector 1: zero-backing trigger, threshold boundary, post-freeze containment |
| [`test/core/PhantomMint.t.sol`](./test/core/PhantomMint.t.sol) | Vector 2: authorized mint (no trigger), unauthorized mint (trigger) |
| [`test/core/RouterSpoof.t.sol`](./test/core/RouterSpoof.t.sol) | Vector 3: single unauthorized exec; Kelp DAO poisoned-DVN path (no V3 trigger) |
| [`test/core/AdversarialAttack.t.sol`](./test/core/AdversarialAttack.t.sol) | Adversarial: threshold gaming, chunked drains, cold start, counter reset |
| [`test/core/FuzzAndEdgeCases.t.sol`](./test/core/FuzzAndEdgeCases.t.sol) | Property: balanced counters never trigger; super-threshold always triggers |
| [`test/core/ResponseAuth.t.sol`](./test/core/ResponseAuth.t.sol) | Auth: operator access control, two-step ownership, cooldown boundary, payload semantics |
| [`test/concepts/OwnershipMonitor.t.sol`](./test/concepts/OwnershipMonitor.t.sol) | Admin/implementation change detection |
| [`test/concepts/PreAttackMonitor.t.sol`](./test/concepts/PreAttackMonitor.t.sol) | Failed privileged call accumulation |
| [`test/concepts/PositionMonitor.t.sol`](./test/concepts/PositionMonitor.t.sol) | Bridge-token collateral concentration in lending pool |

**Fuzz results:**

`testFuzz_balancedCounters_neverTrigger` — counters set equal across 256 randomized inputs bounded to `[0, type(uint128).max]`. Zero triggers. The trap does not fire on large absolute values — only on gaps.

`testFuzz_superThresholdDrainMismatch_alwaysTriggers` — drain mismatch bounded to `[VAULT_DRAIN_THRESHOLD + 1, type(uint128).max]`. Every input triggered.

`testFuzz_anyUnauthorizedExec_alwaysTriggers` — unauthorized execution counts bounded to `[1, 1,000]`. Every count triggered immediately. The Vector 3 hard invariant holds for any non-zero unauthorized execution count.

> Architecture note: The production trap uses hardcoded constant addresses (no constructor arguments, per Drosera stateless trap requirements). Tests use [`TestableBridgeRouterGuardTrap.sol`](./src/core/TestableBridgeRouterGuardTrap.sol) — same logic, constructor-injectable addresses for isolated CI. `shouldRespond()` and `shouldAlert()` are pure and address-independent; only `collect()` requires address injection.

---

## Deployment

### Live Contracts (Hoodi Testnet — Cycle 3, Final)

| Contract | Address |
| :--- | :--- |
| BridgeRouterGuardTrap | [`0x1D880D83Ce107C6961495Ef767b8E4099A94F72E`](https://hoodi.etherscan.io/address/0x1D880D83Ce107C6961495Ef767b8E4099A94F72E) |
| BridgeRouterGuardResponse | [`0x698517e438710F6496827B44B14DAC75C5D878F2`](https://hoodi.etherscan.io/address/0x698517e438710F6496827B44B14DAC75C5D878F2) |

### Live Configuration ([`drosera.toml`](./drosera.toml))

```toml
response_function        = "snapFreeze(uint256,uint256,uint256,uint256)"
block_sample_size        = 7        # sufficient for velocity accumulation (V1, V2, V4)
cooldown_period_blocks   = 33       # ~396s on Hoodi; enforced on-chain in BridgeRouterGuardResponse
min_number_of_operators  = 1        # testnet only — production baseline is ≥ 3
private_trap             = true
```

### System Dependencies

- **Host Chain (Hoodi/EVM):** Protocol contracts and Response contract.
- **Drosera Network:** Decentralized p2p network of shadow operators executing `collect()`, `shouldRespond()`, and `snapFreeze()`.
- **Alert Server:** [`alert-server/alert-server.js`](./alert-server/alert-server.js) — Node.js telemetry receiver. Decodes `AlertData` payloads from the Drosera network and routes `drainDelta`, `mintDelta`, `unauthorizedExecs`, and `reserveDrain` values to Slack or any configured webhook endpoint.

---

## Relevance to Production Infrastructure

BridgeRouterGuard maps to real production protocols because the attack pattern it monitors — execution without validation — is structurally identical across all of them:

- **LayerZero:** `lzReceive()` execution without a verified source-chain deposit in the oracle. The Kelp DAO exploit is the direct instantiation. See [008 — Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md).
- **Axelar:** `execute()` / `expressExecute()` on `AxelarGateway` bypassing `validateContractCall()` — exactly the CrossCurve pattern. See [005 — CrossCurve](./case-studies/005-crosscurve-feb-2026.md).
- **Wormhole:** Guardian VAA replay or forged messages bypassing `verifyVM()`, leading to unauthorized `completeTransfer()` mint (Vector 2).
- **Across Protocol:** `SpokePool` outflow without matching `HubPool` deposit events or proof finalization (Vector 1).

A production deployment replaces mock addresses with live protocol contracts, calibrates velocity thresholds against historical normal-flow baselines for that specific protocol, and raises `min_number_of_operators` to ≥ 3. Threshold calibration matters for the partial-backing path — the zero-backing path requires none. The full picture of what a layered production stack looks like is in [010 — Architecture and Extensions](./case-studies/010-architecture-and-extensions.md).

---

## What's Next: Production Deployment Roadmap

**Extending the trap stack.** BridgeRouterGuard covers the bridge reserve and execution layer. The gaps documented across eight case studies — admin-level takeovers, pre-attack observable windows, downstream lending protocol exposure, DVN infrastructure preconditions — each have a corresponding trap design. The architecture for building that full stack is in [010 — Architecture and Extensions](./case-studies/010-architecture-and-extensions.md).

**Oracle-Injected Asset Normalization.** `shouldRespond()` must remain a pure function — Drosera's architecture requires it. Monitoring low-denomination tokens like CIOTX ([006 — IoTeX](./case-studies/006-iotex-iotube-feb-2026.md)) requires expanding the `collect()` payload to ingest cryptographically verified off-chain oracle data for normalized asset valuation.

**Dynamic Thresholds via Off-Chain Processing.** Static block-to-block thresholds are vulnerable to sub-threshold split attacks and L2 sequencer batching. Rolling-average math requires windowing logic too complex for on-chain evaluation. Production deployments need Drosera's coprocessor to handle that processing off-chain.

**Mainnet Operator Quorum.** `min_number_of_operators` must be raised to ≥ 3 on mainnet with multisig execution enforcement on the Response contract.

**Cross-Chain Deployment.** As Drosera's operator network expands to Arbitrum, Base, and Optimism, the same trap logic deploys cross-chain to monitor fragmented bridge endpoints natively. The [CrossCurve](./case-studies/005-crosscurve-feb-2026.md) and [Kelp DAO](./case-studies/008-kelp-dao-apr-2026.md) cases both showed that multi-chain attacks require per-chain deployments.

**ZK Incident Response.** Integration with Drosera's zero-knowledge proof layer for optimistic claim disputes — ensuring that if an operator attempts a malicious `snapFreeze`, the protocol can mathematically challenge the evaluation payload.

---

## Component Deep Dive

- [`src/core/BridgeRouterGuardTrap.sol`](./src/core/BridgeRouterGuardTrap.sol) — Stateless sensor. Snapshots all eight accounting fields from vault, gateway, and router on every block via `collect()`, then evaluates mismatch deltas across a 7-block window in `shouldRespond()`. No state writes, no constructor args — fully Drosera-compliant.

- [`src/core/BridgeRouterGuardResponse.sol`](./src/core/BridgeRouterGuardResponse.sol) — Circuit breaker. On operator consensus, `snapFreeze()` best-effort pauses all three infrastructure contracts via `try/catch`, ensuring partial containment even if one target is already frozen. Hardened with two-step ownership, operator allowlist, and a 33-block on-chain cooldown enforced on-chain rather than in the operator runtime.

- [`src/core/TestableBridgeRouterGuardTrap.sol`](./src/core/TestableBridgeRouterGuardTrap.sol) — CI shadow. Inherits all production logic unchanged. Overrides only `collect()` to accept injected addresses instead of constants, enabling isolated Foundry testing without touching production code.

- [`src/mocks/core/`](./src/mocks/core/) — Vulnerable protocol simulation. Contracts that deliberately replicate the structural weaknesses documented in the case studies: [`MockBridgeVault`](./src/mocks/core/MockBridgeVault.sol) (unmatched withdrawals — Multichain, Orbit Chain), [`MockTokenGateway`](./src/mocks/core/MockTokenGateway.sol) (unverified admin and unbacked minting — IoTeX, Hyperbridge), [`MockBridgeRouter`](./src/mocks/core/MockBridgeRouter.sol) (unvalidated payload execution — CrossCurve, Socket). [`MockSourceChainOracle`](./src/mocks/core/MockSourceChainOracle.sol) provides source-chain ground truth with PENDING→CONFIRMED→CONSUMED status tracking. [`MockMessageValidator`](./src/mocks/core/MockMessageValidator.sol) consumes oracle events and registers validated credits.

- [`src/concepts/`](./src/concepts/) — Concept traps for attack surface extension: [`OwnershipMonitorTrap`](./src/concepts/OwnershipMonitorTrap.sol), [`PreAttackMonitorTrap`](./src/concepts/PreAttackMonitorTrap.sol), [`PositionMonitorTrap`](./src/concepts/PositionMonitorTrap.sol).

- [`test/`](./test/) — Three layers. Core unit tests in [`test/core/`](./test/core/) confirm invariant boundaries per vector. [`AdversarialAttack.t.sol`](./test/core/AdversarialAttack.t.sol) and [`FuzzAndEdgeCases.t.sol`](./test/core/FuzzAndEdgeCases.t.sol) pressure-test threshold gaming, cold-start, malformed inputs, and schema mismatches. Concept trap tests in [`test/concepts/`](./test/concepts/). Shared setup in [`test/utils/BridgeTestBase.t.sol`](./test/utils/BridgeTestBase.t.sol).

- [`test/attack/LiveHoodiExploit.s.sol`](./test/attack/LiveHoodiExploit.s.sol) — Modular campaign script. Accepts vault amount, silent drain amount, phantom mint amount, credit amount, and router spoof flag via `--sig` to execute any attack combination against live testnet mocks: `executeCampaign`, `silentDrainCampaign`, `preAttackCampaign`, `stolenCollateralCampaign`.

- [`drosera.toml`](./drosera.toml) — Operator rules of engagement: block sampling window, cooldown, response function signature, quorum settings, operator whitelist, and webhook routing.

- [`alert-server/alert-server.js`](./alert-server/alert-server.js) — Node.js telemetry receiver. Decodes `drainDelta`, `mintDelta`, `unauthorizedExecs`, and `reserveDrain` from `AttackPrevented` events and routes to Slack or any configured webhook.

---

## Repository Structure

```
bridge-router-guard/
├── src/
│   ├── core/
│   │   ├── BridgeRouterGuardTrap.sol          # Stateless sensor: collect() + shouldRespond() + shouldAlert()
│   │   ├── BridgeRouterGuardResponse.sol      # Circuit breaker: snapFreeze() with try/catch + two-step ownership
│   │   └── TestableBridgeRouterGuardTrap.sol  # CI shadow: inherits all logic, overrides collect() for injection
│   ├── mocks/
│   │   ├── core/
│   │   │   ├── MockERC20.sol                  # Real ERC20 token — balances transfer on drain simulations
│   │   │   ├── MockSourceChainOracle.sol      # Source-chain ground truth — PENDING→CONFIRMED→CONSUMED
│   │   │   ├── MockMessageValidator.sol       # Verifier layer — consumes oracle events, registers credits
│   │   │   ├── MockBridgeVault.sol            # Vector 1/4: executeWithdrawal (proof required) / directTokenTransfer (exploit)
│   │   │   ├── MockTokenGateway.sol           # Vector 2: mint with authorization / mintPhantom without
│   │   │   ├── MockBridgeRouter.sol           # Vector 3: executeValidated (gateway required) / expressExecute (bypass)
│   │   │   ├── MockPrivilegedBridge.sol       # Pre-attack concept — exposes failedAttemptCount
│   │   │   ├── MockUpgradeableGateway.sol     # Ownership concept — exposes owner() and implementation()
│   │   │   └── MockLendingPool.sol            # Position concept — exposes collateral composition and utilization
│   │   └── concepts/
│   │       ├── PreAttackMonitorTrap.sol
│   │       ├── OwnershipMonitorTrap.sol
│   │       └── PositionMonitorTrap.sol
├── test/
│   ├── core/
│   │   ├── VaultDrain.t.sol
│   │   ├── PhantomMint.t.sol
│   │   ├── RouterSpoof.t.sol
│   │   ├── AdversarialAttack.t.sol
│   │   ├── FuzzAndEdgeCases.t.sol
│   │   └── ResponseAuth.t.sol
│   ├── concepts/
│   │   ├── OwnershipMonitor.t.sol
│   │   ├── PreAttackMonitor.t.sol
│   │   └── PositionMonitor.t.sol
│   ├── attack/
│   │   └── LiveHoodiExploit.s.sol
│   └── utils/
│       └── BridgeTestBase.t.sol
├── script/
│   ├── DeployMocks.s.sol
│   └── DeployResponse.s.sol
├── alert-server/
│   └── alert-server.js
├── case-studies/
│   ├── 001-multichain-jul-2023.md
│   ├── 002-orbit-chain-dec-2023.md
│   ├── 003-socket-protocol-jan-2024.md
│   ├── 004-force-bridge-jun-2025.md
│   ├── 005-crosscurve-feb-2026.md
│   ├── 006-iotex-iotube-feb-2026.md
│   ├── 007-hyperbridge-apr-2026.md
│   ├── 008-kelp-dao-apr-2026.md
│   ├── 009-what-this-work-revealed.md
│   └── 010-architecture-and-extensions.md
├── lib/
├── drosera.toml
├── foundry.toml
└── alert-server.js
```

---

## Quick Start

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Install Drosera CLI
# Follow official Drosera documentation for your environment
curl -L https://app.drosera.io/install | bash

# Install dependencies
forge install

# Build
forge build

# Test
forge test -vv

# Deploy mocks (set PRIVATE_KEY and RPC in .env)
forge script script/DeployMocks.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast

# Deploy response contract (set VAULT_ADDR, GATEWAY_ADDR, ROUTER_ADDR in .env)
forge script script/DeployResponse.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast

# Register trap
drosera apply
```

---

*Deployed on Hoodi Testnet. All transactions verifiable on-chain.*
