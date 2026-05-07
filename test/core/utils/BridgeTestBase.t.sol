// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// ─── Core Contracts (v3 paths) ────────────────────────────────────────────────
import "src/core/TestableBridgeRouterGuardTrap.sol";
import "src/core/BridgeRouterGuardResponse.sol";

// ─── Mock Infrastructure (v3 paths) ──────────────────────────────────────────
import "src/mocks/core/MockERC20.sol";
import "src/mocks/core/MockSourceChainOracle.sol";
import "src/mocks/core/MockMessageValidator.sol";
import "src/mocks/core/MockBridgeVault.sol";
import "src/mocks/core/MockTokenGateway.sol";
import "src/mocks/core/MockBridgeRouter.sol";

// ─────────────────────────────────────────────────────────────────────────────
// BridgeTestBase  (v3)
//
// Shared setUp() for all core trap tests. Deploys the full v3 mock infrastructure
// and wires it to the trap and response contracts.
//
// ARCHITECTURAL NOTE:
//   Unlike v1/v2 where mocks were standalone simulations, v3 mocks are
//   interconnected. The Validator calls back into the Vault/Gateway to register
//   credits. The Trap reads state from the Vault/Gateway/Router.
//   This base class ensures that wiring is identical for every test.
//
// INTERFACE CONTRACT (read by BridgeRouterGuardTrap.collect()):
//   Vault:   executedWithdrawals(), validatedInboundCredits(), vaultTokenBalance()
//   Gateway: cumulativeMinted(), validatedMintAuthorizations(), gatewayTokenSupply()
//   Router:  executedMessages(), gatewayValidatedMessages()
//
// Test addresses:
//   attacker  = 0xBAD  — unauthorized caller for exploit tests
//   operator  = 0xBEEF — authorized operator for snapFreeze() tests
//   legitUser = 0xA11CE — legitimate user for normal-flow tests
//
// Vault seed: 5,000 ether of MockERC20 "Bridged ETH" (bETH).
// This is sufficient to cover all test drains without additional minting.
//
// PRODUCTION DEPLOYMENT NOTE:
//   This is a test base class. Real deployments do not use these mocks.
//   The trap assumes minimal instrumentation: public execution/validation
//   counters and readable reserve balances. No state writes occur in the trap.
// ─────────────────────────────────────────────────────────────────────────────
abstract contract BridgeTestBase is Test {
    MockERC20                     internal token;
    MockSourceChainOracle         internal oracle;    MockMessageValidator          internal validator;
    MockBridgeVault               internal vault;
    MockTokenGateway              internal gateway;
    MockBridgeRouter              internal router;
    TestableBridgeRouterGuardTrap internal trap;
    BridgeRouterGuardResponse     internal response;

    address internal constant attacker  = address(0xBAD);
    address internal constant operator  = address(0xBEEF);
    address internal constant legitUser = address(0xA11CE);

    uint256 internal constant VAULT_SEED = 5_000 ether;

    function setUp() public virtual {
        // ── Deploy core mocks ────────────────────────────────────────────────
        token     = new MockERC20("Bridged ETH", "bETH", 18);
        oracle    = new MockSourceChainOracle();
        validator = new MockMessageValidator(address(oracle), 1);

        // ── CRITICAL WIRING: bind validator as authorized relayer ────────────
        // The oracle enforces `onlyRelayer` on register/confirm/consume calls.
        // In v3 architecture, the validator represents the relayer execution surface.
        // Without this binding, legitimate flows revert with "Oracle: not relayer".
        // This mirrors production wiring where the validator is an authorized oracle client.
        oracle.addRelayer(address(validator));

        // ── FIX: Authorize test contract as relayer for helper functions ─────
        // The helpers _legitimateWithdrawal/Mint/RouterMessage call oracle.register/confirm.
        // During tests, msg.sender is the test contract, not the validator.
        // Without this, helpers revert with "Oracle: not relayer".
        oracle.addRelayer(address(this));

        vault     = new MockBridgeVault(address(token), address(validator));
        gateway   = new MockTokenGateway(address(token), address(validator));
        router    = new MockBridgeRouter(address(validator));

        // ── Wire validator → bridge contracts ────────────────────────────────
        // Validator needs addresses to call back and register credits/authorizations.
        validator.setVault(address(vault));
        validator.setGateway(address(gateway));
        validator.setRouter(address(router));

        // ── Authorize token minters ─────────────────────────────────────────
        // Test contract must be a minter to seed liquidity.
        // Vault and Gateway are authorized for legitimate flows.
        token.addMinter(address(this));   // Test contract
        token.addMinter(address(vault));  // Vault for withdrawals
        token.addMinter(address(gateway)); // Gateway for mints

        // ── Seed vault with initial liquidity ───────────────────────────────
        // In a real bridge, this represents user deposits/locked assets.
        // 5,000 ETH is sufficient to cover all test drains without additional minting.        token.mint(address(this), VAULT_SEED);
        token.mint(address(this), VAULT_SEED);
        token.approve(address(vault), VAULT_SEED);
        vault.seedLiquidity(VAULT_SEED);

        // ── Deploy trap and response ────────────────────────────────────────
        // Testable trap uses constructor-injected addresses; production uses constants.
        trap = new TestableBridgeRouterGuardTrap(
            address(vault), address(gateway), address(router)
        );
        // Response contract is deployed with target addresses and operator authorization.
        response = new BridgeRouterGuardResponse(
            address(vault), address(gateway), address(router)
        );
        response.setOperator(operator, true);

        // ── Advance past deployment block ───────────────────────────────────
        // Ensures tests start with a clean block history for window-based logic.
        vm.roll(40);
        vm.warp(block.timestamp + 25 hours); // Clear operator timelock for tests
    }

    // ─── Window builders ──────────────────────────────────────────────────────
    // These helpers construct the `bytes[]` data that `shouldRespond()` expects.
    // They simulate the Drosera relay passing historical `collect()` outputs.
    // All 8 parameters match the v3 CollectOutput struct exactly.

    function _buildWindow(
        uint256 oldExecW, uint256 oldCredW, uint256 oldMinted, uint256 oldAuth, uint256 oldExecM, uint256 oldValidM, uint256 oldBal, uint256 oldSupply,
        uint256 newExecW, uint256 newCredW, uint256 newMinted, uint256 newAuth, uint256 newExecM, uint256 newValidM, uint256 newBal, uint256 newSupply
    ) internal pure returns (bytes[] memory data) {
        data    = new bytes[](2);
        data[0] = _enc(newExecW, newCredW, newMinted, newAuth, newExecM, newValidM, newBal, newSupply);
        data[1] = _enc(oldExecW, oldCredW, oldMinted, oldAuth, oldExecM, oldValidM, oldBal, oldSupply);
    }

    function _buildBurstWindow(
        uint256 oldExecW, uint256 oldCredW, uint256 oldMinted, uint256 oldAuth,
        uint256 midExecW, uint256 midCredW, uint256 midMinted, uint256 midAuth,
        uint256 newExecW, uint256 newCredW, uint256 newMinted, uint256 newAuth
    ) internal pure returns (bytes[] memory data) {
        // Burst tests focus on Vectors 1-2 (vault/gateway). Router fields and reserve balances are zeroed.
        data    = new bytes[](3);
        data[0] = _enc(newExecW, newCredW, newMinted, newAuth, 0, 0, 0, 0);
        data[1] = _enc(midExecW, midCredW, midMinted, midAuth, 0, 0, 0, 0);
        data[2] = _enc(oldExecW, oldCredW, oldMinted, oldAuth, 0, 0, 0, 0);
    }

    function _enc(
        uint256 execW, uint256 credW, uint256 minted, uint256 auth, uint256 execM, uint256 validM, uint256 balance, uint256 supply
    ) internal pure returns (bytes memory) {
        return abi.encode(CollectOutput({
            schemaVersion:               3,
            executedWithdrawals:         execW,
            validatedInboundCredits:     credW,
            cumulativeMinted:            minted,
            validatedMintAuthorizations: auth,
            executedMessages:            execM,
            gatewayValidatedMessages:    validM,
            vaultTokenBalance:           balance,
            gatewayTokenSupply:          supply
        }));
    }

    // ─── Happy-path helpers ───────────────────────────────────────────────────
    // Simulates the legitimate flow: Oracle → Validator → Bridge Contract.
    // These helpers are used in tests to establish baseline state before exploits.

    function _makeHash(uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("src-chain", nonce));
    }

    function _legitimateWithdrawal(bytes32 eventHash, uint256 amount, address recipient) internal {
        // Step 1: Oracle registers and confirms the source event
        oracle.registerSourceEvent(eventHash, address(token), amount, recipient, block.number - 1);
        oracle.confirmSourceEvent(eventHash);
        // Step 2: Validator validates and registers credit in vault
        validator.validateWithdrawal(eventHash, amount, recipient);
    }

    function _legitimateMint(bytes32 eventHash, uint256 amount, address recipient) internal {
        // Step 1: Oracle registers and confirms the source event
        oracle.registerSourceEvent(eventHash, address(token), amount, recipient, block.number - 1);
        oracle.confirmSourceEvent(eventHash);
        // Step 2: Validator validates and registers mint authorization in gateway
        validator.validateMint(eventHash, amount, recipient);
        // Step 3: Gateway mints with authorization (legitimate admin path)
        gateway.mintWithAuthorization(eventHash);
    }

    function _legitimateRouterMessage(bytes32 eventHash, bytes32 messageHash) internal {
        // Step 1: Oracle registers and confirms the source event
        oracle.registerSourceEvent(eventHash, address(token), 1 ether, address(this), block.number - 1);
        oracle.confirmSourceEvent(eventHash);
        // Step 2: Validator validates and registers message in router
        validator.validateRouterMessage(eventHash, messageHash);
        // Step 3: Router executes the validated message
        router.executeMessage(messageHash, "");
    }
}
