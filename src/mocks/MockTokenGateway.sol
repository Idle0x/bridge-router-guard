// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockTokenGateway {
    uint256 public phantomMinted;
    bool public paused;

    function changeAdmin(address newAdmin, bytes calldata proof) external {
        // Mock privilege escalation
    }

    function mintPhantom(uint256 amount) external {
        require(!paused, "Gateway paused");
        phantomMinted += amount;
    }

    function simulateMint(uint256 amount) external {
        require(!paused, "Gateway paused");
        phantomMinted += amount;
    }

    function emergencyPause() external {
        paused = true;
    }
}
