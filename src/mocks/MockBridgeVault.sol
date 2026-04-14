// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockBridgeVault {
    uint256 public cumulativeWithdrawals;
    bool public paused; // Changed from isPaused to paused

    function removeLiquidity(uint256 amount) external {
        require(!paused, "Vault paused");
        cumulativeWithdrawals += amount;
    }

    function withdraw(uint256 amount) external {
        require(!paused, "Vault paused");
        cumulativeWithdrawals += amount;
    }

    function emergencyPause() external {
        paused = true;
    }
}
