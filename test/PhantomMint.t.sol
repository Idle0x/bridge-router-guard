// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

contract PhantomMintTest is BridgeTestBase {
    function test_IgnoresNormalVolume() public {
        // Capture baseline
        bytes memory prevData = trap.collect();

        // Admin mints a normal, safe amount under the threshold
        gateway.changeAdmin(address(this), bytes("valid_proof"));
        gateway.mintPhantom(5000 ether);

        // Capture current state
        bytes memory currentData = trap.collect();
        bytes[] memory window = new bytes[](2);
        window[0] = currentData;
        window[1] = prevData;

        (bool trigger,) = trap.shouldRespond(window);

        // Trap should NOT fire
        assertFalse(trigger, "Trap falsely triggered on normal mint volume");
    }

    function test_PhantomMintTriggersTrap() public {
        bytes memory prevData = trap.collect();

        // Attacker hijacks admin and mints a massive amount
        gateway.changeAdmin(address(0xBAD), bytes("fakeMMRproof"));
        vm.prank(address(0xBAD));
        gateway.mintPhantom(15000 ether);

        bytes memory currentData = trap.collect();
        bytes[] memory window = new bytes[](2);
        window[0] = currentData;
        window[1] = prevData;

        // Evaluate Trap
        (bool trigger, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(trigger, "Trap failed to detect massive phantom mint");

        // Execute Containment
        vm.prank(operator);
        (uint256 vDrain, uint256 pMint, bool rSpoof) = abi.decode(payload, (uint256, uint256, bool));
        response.snapFreeze(vDrain, pMint, rSpoof);

        // Verify lockdown
        assertTrue(gateway.paused(), "Gateway was not paused");
    }
}
