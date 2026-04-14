// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

contract RouterSpoofTest is BridgeTestBase {
    function test_SpoofedMessageTriggersTrap() public {
        // Attacker forces a spoofed cross-chain execution
        router.expressExecute(bytes("spoofed_payload"), bytes32(0));

        bytes memory currentData = trap.collect();
        bytes[] memory window = new bytes[](1);
        window[0] = currentData;

        // Evaluate Trap
        (bool trigger, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(trigger, "Trap failed to detect spoofed router message");

        // Execute Containment
        vm.prank(operator);
        (uint256 vDrain, uint256 pMint, bool rSpoof) = abi.decode(payload, (uint256, uint256, bool));
        response.snapFreeze(vDrain, pMint, rSpoof);

        // Verify lockdown
        assertTrue(router.paused(), "Router was not paused");
    }
}
