// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPausable {
    function emergencyPause() external;
}

contract BridgeRouterGuardResponse {
    address public constant VAULT = 0x83c9e182b10aC6B62C559F9092C0Cfc12394Ab1E;
    address public constant GATEWAY = 0x544fFbCde66A95b24829EB6a5e803d27E7737Dc1;
    address public constant ROUTER = 0xca324202c796Aa8A5d8Ddcac384852854A253D66;

    address public owner;
    mapping(address => bool) public authorizedOperators;

    event AttackPrevented(uint256 vaultVelocity, uint256 phantomVelocity, bool routerSpoofed);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOperator() {
        require(authorizedOperators[msg.sender], "not authorized");
        _;
    }

    function setOperator(address op, bool status) external {
        require(msg.sender == owner, "not owner");
        authorizedOperators[op] = status;
    }

    function snapFreeze(uint256 vaultV, uint256 phantomV, bool spoof) external virtual onlyOperator {
        IPausable(VAULT).emergencyPause();
        IPausable(GATEWAY).emergencyPause();
        IPausable(ROUTER).emergencyPause();
        emit AttackPrevented(vaultV, phantomV, spoof);
    }
}
