// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TestableBridgeRouterGuardTrap.sol";
import "../src/mocks/MockBridgeVault.sol";
import "../src/mocks/MockTokenGateway.sol";
import "../src/mocks/MockBridgeRouter.sol";

// Note: CollectOutput is automatically imported from the Trap contract.

contract VaultDrainTest is Test {
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

    function test_vaultDrain_MultichainExploit() public {
        // [EXPLOIT MODEL: Multichain Jul 2023 / Orbit Chain Dec 2023]
        // The attacker bypasses off-chain validation and directly drains 
        // the vault without a matching inbound deposit proof.
        
        // [EXPLOIT EXECUTION] Attacker calls removeLiquidity to drain 1500 ETH.
        vault.removeLiquidity(1500 ether);
        
        // We simulate the Drosera nodes capturing the block window (Oldest vs Newest)
        bytes[] memory data = new bytes[](2);
        
        // Newest block sample (Post-Exploit)
        data[0] = abi.encode(CollectOutput({
            schemaVersion: 1,
            cumulativeWithdrawals: vault.cumulativeWithdrawals(), // 1500 ETH
            phantomMinted: 0,
            spoofedMessageExecuted: false
        }));
        
        // Oldest block sample (Pre-Exploit)
        data[1] = abi.encode(CollectOutput({
            schemaVersion: 1,
            cumulativeWithdrawals: 0,
            phantomMinted: 0,
            spoofedMessageExecuted: false
        }));
        
        // [NEUTRALIZED BY] BridgeRouterGuardTrap.sol shouldRespond():
        // The logic evaluates: vaultWindowDrained = (1500e18 > 0) && (1500e18 > 1000e18) -> true
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        
        assertTrue(trigger, "Trap failed to detect Multichain-style vault drain");
        
        (uint256 vaultV, uint256 phantomV, bool spoof) = abi.decode(payload, (uint256, uint256, bool));
        assertEq(vaultV, 1500 ether, "Vault velocity payload mismatch");
        assertEq(phantomV, 0, "Phantom velocity payload mismatch");
        assertEq(spoof, false, "Spoof boolean mismatch");
    }
}
