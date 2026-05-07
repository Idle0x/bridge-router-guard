// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./MockSourceChainOracle.sol";

// ─────────────────────────────────────────────────────────────────────────────
// MockMessageValidator
//
// The verifier layer between source-chain events and destination-chain execution.
// This is the contract that was bypassed, compromised, or poisoned in every
// exploit in this case study set.
//
// Real-world equivalents:
//   Multichain         -- MPC node set
//   Orbit Chain        -- 7/10 multisig
//   Force Bridge       -- privileged relayer/deployer key
//   CrossCurve         -- Axelar gateway validateContractCall()
//   IoTeX ioTube       -- TransferValidatorWithPayload (upgradeable)
//   Hyperbridge        -- MerkleMountainRange.CalculateRoot()
//   Kelp DAO           -- LayerZero DVN (1-of-1 external verifier)
//
// In this system, MockMessageValidator sits between MockSourceChainOracle and
// the three bridge contracts. Normal execution:
//   1. Source event occurs -> Oracle registers and confirms
//   2. Validator reads Oracle: isConfirmed() == true
//   3. Validator consumes event (replay protection)
//   4. Validator registers credit/auth/message in destination contract
//   5. Destination executes against that credit
//
// In exploit scenarios, the validator is placed into a compromise mode:
//   NONE      -- normal operation, all steps enforced
//   BYPASSED  -- skips oracle check entirely; registers credits freely
//               (CrossCurve expressExecute no-auth, Force Bridge deployer key)
//   POISONED  -- checks oracle, but oracle lies
//               (Kelp DVN RPC poisoning, Hyperbridge MMR bounds bypass)
//   UPGRADED  -- implementation replaced; approves everything unconditionally
//               (IoTeX malicious upgrade)
//
// The trap does NOT monitor this contract. It monitors the destination contracts.
// The mismatch IS the invariant. The validator being bypassed is what creates it.
// ─────────────────────────────────────────────────────────────────────────────
contract MockMessageValidator {
    enum CompromiseMode { NONE, BYPASSED, POISONED, UPGRADED }
    CompromiseMode public compromiseMode;

    MockSourceChainOracle public immutable oracle;
    address public vault;
    address public gateway;
    address public router;
    address public owner;
    mapping(address => bool) public isSigner;
    uint256 public requiredSigners;
    uint256 public signerCount;

    event CreditRegistered(bytes32 indexed eventHash, uint256 amount, address recipient);
    event MintAuthorizationRegistered(bytes32 indexed eventHash, uint256 amount, address recipient);
    event RouterMessageValidated(bytes32 indexed messageHash);
    event ValidatorCompromised(CompromiseMode mode);
    event SignerAdded(address signer);

    constructor(address _oracle, uint256 _requiredSigners) {
        require(_oracle != address(0), "Validator: zero oracle");
        require(_requiredSigners > 0, "Validator: zero quorum");
        oracle = MockSourceChainOracle(_oracle);
        requiredSigners = _requiredSigners;
        owner = msg.sender;
        isSigner[msg.sender] = true;
        signerCount = 1;
    }

    modifier onlyOwner() { require(msg.sender == owner, "Validator: not owner"); _; }
    modifier onlySigner() { require(isSigner[msg.sender], "Validator: not signer"); _; }

    function setVault(address _vault) external onlyOwner { vault = _vault; }
    function setGateway(address _gateway) external onlyOwner { gateway = _gateway; }
    function setRouter(address _router) external onlyOwner { router = _router; }

    function addSigner(address signer) external onlyOwner {
        require(!isSigner[signer], "Validator: already signer");
        isSigner[signer] = true;
        signerCount++;
        emit SignerAdded(signer);
    }

    function compromiseBypassed() external onlyOwner {
        compromiseMode = CompromiseMode.BYPASSED;
        emit ValidatorCompromised(CompromiseMode.BYPASSED);
    }
    function compromisePoisoned() external onlyOwner {
        compromiseMode = CompromiseMode.POISONED;
        emit ValidatorCompromised(CompromiseMode.POISONED);
    }
    function compromiseUpgraded() external onlyOwner {
        compromiseMode = CompromiseMode.UPGRADED;
        emit ValidatorCompromised(CompromiseMode.UPGRADED);
    }
    function restoreValidator() external onlyOwner {
        compromiseMode = CompromiseMode.NONE;
    }
    // validateWithdrawal: called before vault releases funds.
    function validateWithdrawal(bytes32 eventHash, uint256 amount, address recipient) external onlySigner returns (bool) {
        require(vault != address(0), "Validator: vault not set");
        if (compromiseMode == CompromiseMode.NONE) {
            require(oracle.isConfirmed(eventHash), "Validator: not confirmed");
            require(!oracle.isConsumed(eventHash), "Validator: already consumed");
            oracle.consumeSourceEvent(eventHash);
        } else if (compromiseMode == CompromiseMode.BYPASSED) {
            // skip oracle check entirely
        } else if (compromiseMode == CompromiseMode.POISONED) {
            require(oracle.isConfirmed(eventHash), "Validator: oracle rejected");
            if (!oracle.isConsumed(eventHash)) oracle.consumeSourceEvent(eventHash);
        } else if (compromiseMode == CompromiseMode.UPGRADED) {
            // unconditional approval
        }
        IValidatable(vault).registerInboundCredit(eventHash, amount, recipient);
        emit CreditRegistered(eventHash, amount, recipient);
        return true;
    }

    // validateMint: called before gateway mints bridge-wrapped tokens.
    function validateMint(bytes32 eventHash, uint256 amount, address recipient) external onlySigner returns (bool) {
        require(gateway != address(0), "Validator: gateway not set");
        if (compromiseMode == CompromiseMode.NONE) {
            require(oracle.isConfirmed(eventHash), "Validator: not confirmed");
            require(!oracle.isConsumed(eventHash), "Validator: already consumed");
            oracle.consumeSourceEvent(eventHash);
        } else if (compromiseMode == CompromiseMode.BYPASSED) {
            // skip
        } else if (compromiseMode == CompromiseMode.POISONED) {
            require(oracle.isConfirmed(eventHash), "Validator: oracle rejected");
            if (!oracle.isConsumed(eventHash)) oracle.consumeSourceEvent(eventHash);
        } else if (compromiseMode == CompromiseMode.UPGRADED) {
            // unconditional
        }
        IValidatable(gateway).registerMintAuthorization(eventHash, amount, recipient);
        emit MintAuthorizationRegistered(eventHash, amount, recipient);
        return true;
    }

    // validateRouterMessage: called before router executes cross-chain message.
    function validateRouterMessage(bytes32 eventHash, bytes32 messageHash) external onlySigner returns (bool) {
        require(router != address(0), "Validator: router not set");
        if (compromiseMode == CompromiseMode.NONE) {
            require(oracle.isConfirmed(eventHash), "Validator: not confirmed");
            require(!oracle.isConsumed(eventHash), "Validator: already consumed");
            oracle.consumeSourceEvent(eventHash);
        } else if (compromiseMode == CompromiseMode.BYPASSED) {
            // skip
        } else if (compromiseMode == CompromiseMode.POISONED) {            require(oracle.isConfirmed(eventHash), "Validator: oracle rejected");
            if (!oracle.isConsumed(eventHash)) oracle.consumeSourceEvent(eventHash);
        } else if (compromiseMode == CompromiseMode.UPGRADED) {
            // unconditional
        }
        IValidatable(router).registerValidatedMessage(messageHash);
        emit RouterMessageValidated(messageHash);
        return true;
    }
}

// Minimal interfaces for callback registration (avoids circular imports)
interface IValidatable {
    function registerInboundCredit(bytes32 eventHash, uint256 amount, address recipient) external;
    function registerMintAuthorization(bytes32 eventHash, uint256 amount, address recipient) external;
    function registerValidatedMessage(bytes32 messageHash) external;
}
