// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// MockBridgeRouter
//
// The destination-side message execution contract. Receives cross-chain
// messages and executes their payloads.
//
// ARCHITECTURAL CHANGE FROM v1/v2:
//   BEFORE: `spoofedMessageExecuted` boolean flag. Self-aware oracle-like truth.
//           If the router could know a message was spoofed, it would revert.
//   AFTER:  `executedMessages` vs `gatewayValidatedMessages` -- two counters.
//           The router executes messages. The question is: was each execution
//           preceded by gateway validation? The gap is the signal.
//
// Normal operation:
//   1. Gateway validates message (Axelar validateContractCall / DVN quorum)
//   2. Validator calls registerValidatedMessage()
//   3. User calls executeMessage() referencing validated hash
//   4. Both counters increment -> mismatch = 0
//
// Exploit operation (CrossCurve/Socket):
//   expressExecute() called directly. No prior registerValidatedMessage().
//   executedMessages increments. gatewayValidatedMessages does not.
//   Mismatch = 1 (or more). Trap fires immediately. Zero history needed.
//
// Exploit operation (Kelp poisoned DVN):
//   Validator registers message (poisoned path). Both counters increment.
//   Router mismatch = 0. Vault drain mismatch fires instead (Vector 1).
//   See case study 008 for the precise distinction.
//
// The router is innocent. The validation layer failed upstream.
// ─────────────────────────────────────────────────────────────────────────────
contract MockBridgeRouter {
    uint256 public executedMessages;
    uint256 public gatewayValidatedMessages;

    mapping(bytes32 => bool) public validatedMessageHashes;
    mapping(bytes32 => bool) public executedMessageHashes;

    address public immutable validator;
    bool    public paused;

    event MessageValidationRegistered(bytes32 indexed messageHash);
    event MessageExecuted(bytes32 indexed messageHash, address indexed executor, bool wasValidated);
    event UnauthorizedExecution(bytes32 indexed messageHash, address indexed attacker);
    event EmergencyPaused(address by);

    constructor(address _validator) {        require(_validator != address(0), "zero validator");
        validator = _validator;
    }

    modifier notPaused() { require(!paused, "Router paused"); _; }
    modifier onlyValidator() { require(msg.sender == validator, "not validator"); _; }

    // Called ONLY by validator after oracle confirmation.
    function registerValidatedMessage(bytes32 messageHash) external onlyValidator {
        require(!validatedMessageHashes[messageHash], "already validated");
        validatedMessageHashes[messageHash] = true;
        gatewayValidatedMessages++;
        emit MessageValidationRegistered(messageHash);
    }

    // LEGITIMATE PATH: requires prior registration by validator.
    function executeMessage(bytes32 messageHash, bytes calldata /*payload*/) external notPaused {
        require(validatedMessageHashes[messageHash], "not validated");
        require(!executedMessageHashes[messageHash], "already executed");
        executedMessageHashes[messageHash] = true;
        executedMessages++;
        emit MessageExecuted(messageHash, msg.sender, true);
    }

    // EXPLOIT PATH A: direct unauthorized execution (CrossCurve/Socket pattern)
    // Publicly callable. No gateway validation. No prior registration.
    function expressExecute(bytes calldata /*payload*/, bytes32 /*commandId*/) external notPaused {
        bytes32 fakeHash = keccak256(abi.encodePacked(block.number, msg.sender, executedMessages));
        executedMessageHashes[fakeHash] = true;
        executedMessages++;
        emit UnauthorizedExecution(fakeHash, msg.sender);
    }

    // EXPLOIT PATH B: execution after poisoned validation (Kelp pattern)
    // Message appears validated (poisoned validator registered it).
    // Router counters look balanced. Vault drain mismatch fires instead.
    function executePoisonedMessage(bytes32 messageHash, bytes calldata /*payload*/) external notPaused {
        require(validatedMessageHashes[messageHash], "not in registry");
        require(!executedMessageHashes[messageHash], "already executed");
        executedMessageHashes[messageHash] = true;
        executedMessages++;
        emit MessageExecuted(messageHash, msg.sender, true);
    }

    function getUnauthorizedExecutions() external view returns (uint256) {
        return executedMessages > gatewayValidatedMessages
            ? executedMessages - gatewayValidatedMessages : 0;
    }

    function emergencyPause() external {        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}
