// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TestableBridgeRouterGuardTrap.sol";
import "../src/mocks/MockBridgeVault.sol";
import "../src/mocks/MockTokenGateway.sol";
import "../src/mocks/MockBridgeRouter.sol";

contract RouterSpoofTest is Test {
    TestableBridgeRouterGuardTrap trap;
    MockBridgeVault vault;
    MockTokenGateway gateway;
    MockBridgeRouter router;

    function setUp() public {
        vault = new MockBridgeVault();
        gateway = new MockTokenGateway();
        router = new MockBridgeRouter();
        trap = new TestableBridgeRouterGuardTrap(address(vault), address(gateway), address(router));
    }

    function test_routerSpoof_CrossCurveExploit() public {
        // [EXPLOIT MODEL: CrossCurve Feb 2026 / Socket Protocol Jan 2024]
        // Attacker bypasses the gateway's validation logic entirely and 
        // executes a malicious payload directly on the router.

        // [EXPLOIT EXECUTION] 
        // Attacker calls expressExecute with a forged payload and invalid proof.
        // Because of missing access control, the router blindly executes it.
        router.expressExecute(hex"deadbeef", bytes32(0));

        // We simulate the Drosera nodes capturing the block window (Oldest vs Newest)
        bytes[] memory data = new bytes[](2);

        // Newest block sample (Post-Exploit)
        data[0] = abi.encode(CollectOutput({
            schemaVersion: 1,
            cumulativeWithdrawals: 0,
            phantomMinted: 0,
            spoofedMessageExecuted: router.spoofedMessageExecuted() // true
        }));

        // Oldest block sample (Pre-Exploit)
        data[1] = abi.encode(CollectOutput({
            schemaVersion: 1,
            cumulativeWithdrawals: 0,
            phantomMinted: 0,
            spoofedMessageExecuted: false
        }));

        // [NEUTRALIZED BY] BridgeRouterGuardTrap.sol shouldRespond():
        // The logic evaluates: if (newest.spoofedMessageExecuted) -> true
        // This is a hard boolean invariant. It fires immediately regardless of velocity.
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);

        // Assert the trap successfully fired
        assertTrue(trigger, "Trap failed to detect CrossCurve-style router spoof");

        // Assert the payload exactly matches the snapFreeze(uint256,uint256,bool) signature
        (uint256 vaultV, uint256 phantomV, bool spoof) = abi.decode(payload, (uint256, uint256, bool));
        assertEq(vaultV, 0, "Vault velocity mismatch");
        assertEq(phantomV, 0, "Phantom velocity mismatch");
        assertEq(spoof, true, "Spoof boolean mismatch");
    }
}
