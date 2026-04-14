// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/BridgeTestBase.t.sol";

contract VaultDrainTest is BridgeTestBase {
    function test_IgnoresNormalWithdrawal() public {
        // User withdraws a normal amount (e.g., 100 ETH)
        vault.removeLiquidity(100 ether);

        bytes memory currentData = trap.collect();
        bytes[] memory window = new bytes[](1);
        window[0] = currentData;

        (bool trigger,) = trap.shouldRespond(window);

        // Trap should NOT fire
        assertFalse(trigger, "Trap falsely triggered on normal volume");
    }

    function test_VelocitySpikeTriggersTrap() public {
        // 1. Capture historical state (Block 1)
        bytes memory prevData = trap.collect();

        // 2. Attacker drains massive amount (Block 2)
        vault.removeLiquidity(1500 ether);

        // 3. Capture current state and build Drosera window array
        bytes memory currentData = trap.collect();
        bytes[] memory window = new bytes[](2);
        window[0] = currentData;
        window[1] = prevData;

        // 4. Evaluate Trap
        (bool trigger, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(trigger, "Trap failed to detect velocity spike");

        // 5. Execute Containment as the Operator
        vm.prank(operator);
        (uint256 vDrain, uint256 pMint, bool rSpoof) = abi.decode(payload, (uint256, uint256, bool));
        response.snapFreeze(vDrain, pMint, rSpoof);

        // 6. Verify absolute lockdown
        assertTrue(vault.paused(), "Vault was not paused");
        assertTrue(gateway.paused(), "Gateway was not paused");
        assertTrue(router.paused(), "Router was not paused");
    }

    function test_ChunkedDrainTriggersTrap() public {
        bytes memory prevData = trap.collect();

        // Attacker tries to bypass the 1000 ETH threshold using 10 smaller transactions
        for (uint256 i = 0; i < 10; i++) {
            vault.removeLiquidity(150 ether); // 1500 ETH total
        }

        bytes memory currentData = trap.collect();
        bytes[] memory window = new bytes[](2);
        window[0] = currentData;
        window[1] = prevData;

        (bool trigger,) = trap.shouldRespond(window);

        // Trap MUST fire because of the cumulative velocity tracking
        assertTrue(trigger, "Trap failed to detect chunked drain");
    }
}
