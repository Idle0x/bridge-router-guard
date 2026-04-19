// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TestableBridgeRouterGuardTrap.sol";
import "../src/mocks/MockBridgeVault.sol";
import "../src/mocks/MockTokenGateway.sol";
import "../src/mocks/MockBridgeRouter.sol";

contract PhantomMintTest is Test {
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

    function test_phantomMint_HyperbridgeExploit() public {
        // [EXPLOIT MODEL: IoTeX ioTube Feb 2026 / Hyperbridge Apr 2026]
        // Attacker escalates privileges (e.g. MMR proof replay) to become admin,
        // then mints unbacked tokens on the destination chain.

        address attacker = address(0xBAD);

        // [EXPLOIT EXECUTION - Step 1] Privilege Escalation
        // Replicates missing signature/MMR validation allowing arbitrary admin change.
        gateway.changeAdmin(attacker, "");

        // [EXPLOIT EXECUTION - Step 2] Unbacked Mint
        vm.prank(attacker);
        gateway.mintPhantom(15000 ether);

        // We simulate the Drosera nodes capturing the block window (Oldest vs Newest)
        bytes[] memory data = new bytes[](2);

        // Newest block sample (Post-Exploit)
        data[0] = abi.encode(CollectOutput({
            schemaVersion: 1,
            cumulativeWithdrawals: 0,
            phantomMinted: gateway.phantomMinted(), // 15000 ETH
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
        // The logic evaluates: phantomWindowSpiked = (15000e18 > 0) && (15000e18 > 10000e18) -> true
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);

        // Assert the trap successfully fired
        assertTrue(trigger, "Trap failed to detect Hyperbridge-style phantom mint");

        // Assert the payload exactly matches the snapFreeze(uint256,uint256,bool) signature
        (uint256 vaultV, uint256 phantomV, bool spoof) = abi.decode(payload, (uint256, uint256, bool));
        assertEq(vaultV, 0, "Vault velocity mismatch");
        assertEq(phantomV, 15000 ether, "Phantom velocity mismatch");
        assertEq(spoof, false, "Spoof boolean mismatch");
    }
}
