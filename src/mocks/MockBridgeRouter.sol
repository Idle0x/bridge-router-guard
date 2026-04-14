// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockBridgeRouter {
    bool public spoofedMessageExecuted;
    bool public paused;

    // Added back to support RouterSpoof.t.sol
    function expressExecute(bytes calldata payload, bytes32 proof) external {
        require(!paused, "Router paused");
        spoofedMessageExecuted = true;
    }

    function emergencyPause() external {
        paused = true;
    }
}
