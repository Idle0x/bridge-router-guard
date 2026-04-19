// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPausable {
    function emergencyPause() external;
    function paused() external view returns (bool);
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeRouterGuardResponse
//
// The execution contract for snapFreeze() containment.
// ─────────────────────────────────────────────────────────────────────────────
contract BridgeRouterGuardResponse {

    address public immutable VAULT;
    address public immutable GATEWAY;
    address public immutable ROUTER;

    address public owner;
    address public pendingOwner;
    mapping(address => bool) public authorizedOperators;

    uint256 public lastFreezeBlock;
    uint256 public constant COOLDOWN_BLOCKS = 33;

    event AttackPrevented(
        address indexed caller,
        uint256 vaultVelocity,
        uint256 phantomVelocity,
        bool routerSpoofed,
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
        require(
            block.number >= lastFreezeBlock + COOLDOWN_BLOCKS,
            "cooldown active"
        );
        _;
    }

    function snapFreeze(uint256 vaultV, uint256 phantomV, bool spoof)
        external
        virtual
        onlyOperator
        cooldownElapsed
    {
        lastFreezeBlock = block.number;

        _pauseTarget(VAULT,   "Vault");
        _pauseTarget(GATEWAY, "Gateway");
        _pauseTarget(ROUTER,  "Router");

        emit AttackPrevented(msg.sender, vaultV, phantomV, spoof, block.number);
    }

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

    function setOperator(address op, bool status) external onlyOwner {
        require(op != address(0), "zero address");
        authorizedOperators[op] = status;
        emit OperatorUpdated(op, status, msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferAccepted(owner);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        pendingOwner = address(0);
        emit OwnershipTransferCancelled(msg.sender);
    }
}
