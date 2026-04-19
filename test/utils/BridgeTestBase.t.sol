// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/TestableBridgeRouterGuardTrap.sol";
import "../../src/BridgeRouterGuardResponse.sol";
import "../../src/mocks/MockBridgeVault.sol";
import "../../src/mocks/MockTokenGateway.sol";
import "../../src/mocks/MockBridgeRouter.sol";

// ─────────────────────────────────────────────────────────────────────────────
// BridgeTestBase
//
// Core fixture for all tests. Instantiates mocks and the Trap once.
// Provides heavily optimized data-building helpers for window/burst simulation.
// ─────────────────────────────────────────────────────────────────────────────
contract BridgeTestBase is Test {
    TestableBridgeRouterGuardTrap trap;
    MockBridgeVault vault;
    MockTokenGateway gateway;
    MockBridgeRouter router;
    BridgeRouterGuardResponse response;

    address internal operator = address(0xBEEF);

    function setUp() public virtual {
        vault    = new MockBridgeVault();
        gateway  = new MockTokenGateway();
        router   = new MockBridgeRouter();

        trap     = new TestableBridgeRouterGuardTrap(address(vault), address(gateway), address(router));
        response = new BridgeRouterGuardResponse(address(vault), address(gateway), address(router));
        
        response.setOperator(operator, true);
        vm.roll(40); // Fast-forward past initial cooldown
    }

    // Standard 2-block window builder
    function _buildWindow(
        uint256 oldW, uint256 oldP, bool oldS,
        uint256 newW, uint256 newP, bool newS
    ) internal pure returns (bytes[] memory data) {
        data = new bytes[](2);
        data[0] = abi.encode(CollectOutput({schemaVersion: 1, cumulativeWithdrawals: newW, phantomMinted: newP, spoofedMessageExecuted: newS}));
        data[1] = abi.encode(CollectOutput({schemaVersion: 1, cumulativeWithdrawals: oldW, phantomMinted: oldP, spoofedMessageExecuted: oldS}));
    }

    // 3-block burst window builder
    function _buildBurstWindow(
        uint256 oldestW, uint256 oldestP, bool oldestS,
        uint256 midW,    uint256 midP,    bool midS,
        uint256 newW,    uint256 newP,    bool newS
    ) internal pure returns (bytes[] memory data) {
        data = new bytes[](3);
        data[0] = abi.encode(CollectOutput({schemaVersion: 1, cumulativeWithdrawals: newW, phantomMinted: newP, spoofedMessageExecuted: newS}));
        data[1] = abi.encode(CollectOutput({schemaVersion: 1, cumulativeWithdrawals: midW, phantomMinted: midP, spoofedMessageExecuted: midS}));
        data[2] = abi.encode(CollectOutput({schemaVersion: 1, cumulativeWithdrawals: oldestW, phantomMinted: oldestP, spoofedMessageExecuted: oldestS}));
    }
}
