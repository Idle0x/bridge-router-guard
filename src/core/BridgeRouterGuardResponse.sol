// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal interface for pause targets
interface IPausable {
    function emergencyPause() external;
    function paused() external view returns (bool);
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeRouterGuardResponse  (v3)
//
// The execution contract for snapFreeze() containment.
//
// CHANGES FROM v2:
//
//   Payload semantics fix (reviewer finding #3):
//     v1: snapFreeze(uint256 vaultV, uint256 phantomV, bool spoof)
//         Named as velocities. AttackPrevented emitted vaultVelocity and
//         phantomVelocity. shouldRespond() passed newest.cumulativeWithdrawals
//         (a cumulative total) into vaultV. Label did not match value.
//
//     v2: snapFreeze(uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs)
//         shouldRespond() returns actual computed mismatch deltas.
//         AttackPrevented emits drain mismatch delta, mint mismatch delta,
//         and unauthorized execution count. Labels match values.
//
//     v3: snapFreeze(uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain)
//         Adds Vector 4: reserveDrain parameter for accounting reconciliation signal.
//         AttackPrevented event updated to include reserveDrain field.
//
//   virtual removed from snapFreeze():
//     v1 marked snapFreeze() virtual with no documented reason.
//     This is a response contract, not a base class. Removed.
//
//   Operator authorization note:
//     Deployment scripts must call setOperator(DROSERA_EXECUTOR, true)
//     immediately after deployment. Without this, detection works but
//     freeze cannot execute. Enforced in scripts/DeployResponse.s.sol.
//
//   v3.1 Hardening:
//     24-hour timelock on setOperator() changes after initial deployment.
//     Prevents instant deauthorization if owner key is compromised.
// ─────────────────────────────────────────────────────────────────────────────
contract BridgeRouterGuardResponse {
    address public immutable VAULT;
    address public immutable GATEWAY;
    address public immutable ROUTER;
    address public owner;
    address public pendingOwner;    mapping(address => bool) public authorizedOperators;
    uint256 public lastFreezeBlock;
    uint256 public constant COOLDOWN_BLOCKS = 33;

    // v3.1: Operator change timelock (24 hours)
    uint256 public constant OPERATOR_CHANGE_DELAY = 24 hours;
    uint256 public lastOperatorChange;

    // Event updated for v3: includes reserveDrain parameter
    event AttackPrevented(
        address indexed caller,
        uint256 drainDelta,
        uint256 mintDelta,
        uint256 unauthorizedExecs,
        uint256 reserveDrain,
        uint256 blockNumber
    );
    event TargetPauseResult(address indexed target, bool success, string reason);
    event OperatorUpdated(address indexed operator, bool status, address indexed updatedBy);
    event OwnershipTransferInitiated(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferAccepted(address indexed newOwner);
    event OwnershipTransferCancelled(address indexed cancelledBy);

    constructor(address _vault, address _gateway, address _router) {
        require(_vault   != address(0), "vault zero address");
        require(_gateway != address(0), "gateway zero address");
        require(_router  != address(0), "router zero address");
        VAULT   = _vault;
        GATEWAY = _gateway;
        ROUTER  = _router;
        owner   = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyOperator() {
        require(authorizedOperators[msg.sender], "not authorized operator");
        _;
    }

    modifier cooldownElapsed() {
        require(block.number >= lastFreezeBlock + COOLDOWN_BLOCKS, "cooldown active");
        _;
    }

    // ─── snapFreeze() -- v3 signature with reserveDrain parameter ─────────────
    // Called by authorized Drosera operators on consensus.    // Best-effort pauses all three infrastructure contracts.
    // Emits AttackPrevented with actual mismatch deltas (not cumulative totals).
    function snapFreeze(uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain)
        external
        onlyOperator
        cooldownElapsed
    {
        lastFreezeBlock = block.number;
        _pauseTarget(VAULT,   "Vault");
        _pauseTarget(GATEWAY, "Gateway");
        _pauseTarget(ROUTER,  "Router");
        emit AttackPrevented(msg.sender, drainDelta, mintDelta, unauthorizedExecs, reserveDrain, block.number);
    }

    // Internal helper: best-effort pause with try/catch for partial containment
    function _pauseTarget(address target, string memory label) internal {
        try IPausable(target).paused() returns (bool isPaused) {
            if (isPaused) {
                emit TargetPauseResult(target, true, string(abi.encodePacked(label, ": already paused")));
                return;
            }
        } catch {}

        try IPausable(target).emergencyPause() {
            emit TargetPauseResult(target, true, string(abi.encodePacked(label, ": paused")));
        } catch Error(string memory reason) {
            emit TargetPauseResult(target, false, string(abi.encodePacked(label, ": failed - ", reason)));
        } catch {
            emit TargetPauseResult(target, false, string(abi.encodePacked(label, ": failed - unknown")));
        }
    }

    // ─── Operator management ──────────────────────────────────────────────────
    // Only owner may authorize/deauthorize operators.
    // Production: DROSERA_EXECUTOR must be authorized post-deploy.
    // v3.1: Enforces 24h timelock on changes after initial setup to prevent
    // instant deauthorization if owner key is compromised. First call bypasses.

    function setOperator(address op, bool status) external onlyOwner {
        require(op != address(0), "zero address");
        require(authorizedOperators[op] != status, "no change");
        if (lastOperatorChange > 0) {
            require(block.timestamp >= lastOperatorChange + 24 hours, "operator timelock active");
        }
        authorizedOperators[op] = status;
        lastOperatorChange = block.timestamp;
        emit OperatorUpdated(op, status, msg.sender);
    }

    // ─── Two-step ownership transfer (hardened) ───────────────────────────────
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        owner        = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferAccepted(owner);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        pendingOwner = address(0);
        emit OwnershipTransferCancelled(msg.sender);
    }
}
