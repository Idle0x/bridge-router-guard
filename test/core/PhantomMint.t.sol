// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "test/core/utils/BridgeTestBase.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// PhantomMint.t.sol -- Vector 2: cumulativeMinted - validatedMintAuthorizations
//
// Case studies: IoTeX ioTube Feb 2026, Hyperbridge Apr 2026
//
// KEY v3 IMPROVEMENT:
//   Tests the realistic privilege escalation path.
//   Attacker calls changeAdmin() (no proof check) -> seizes admin -> calls mint().
//   cumulativeMinted grows, but validatedMintAuthorizations does not.
//   Payload now includes reserveDrain (Vector 4) for full v3 telemetry alignment.
// ─────────────────────────────────────────────────────────────────────────────
contract PhantomMintTest is BridgeTestBase {

    // ── Normal operation ──────────────────────────────────────────────────────

    function test_authorizedMint_noMismatch_noTrigger() public {
        bytes32 eventHash = _makeHash(1);
        _legitimateMint(eventHash, 500 ether, legitUser);

        assertEq(gateway.getMismatch(), 0, "Authorized mint: no mismatch");
        assertEq(token.balanceOf(legitUser), 500 ether, "User received minted tokens");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Authorized mint must NOT trigger");
    }

    // ── Exploit: IoTeX ioTube pattern ────────────────────────────────────────

    function test_phantomMint_IoTeXPattern_adminSeizure_triggers() public {
        // [EXPLOIT: IoTeX ioTube Feb 2026]
        // Step 1: Attacker seizes gateway admin (no proof validation)
        gateway.changeAdmin(attacker, "");
        assertEq(gateway.admin(), attacker, "Attacker must hold admin");

        // Step 2: Attacker mints unbacked tokens
        uint256 mintAmount = 15_000 ether;
        vm.prank(attacker);
        gateway.mint(attacker, mintAmount);

        assertEq(gateway.getMismatch(), mintAmount, "Mismatch = unbacked mint");
        assertEq(token.balanceOf(attacker), mintAmount, "Attacker holds real minted tokens");
        bytes[] memory data = new bytes[](2);        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger, "IoTeX-style phantom mint MUST trigger");

        (uint256 drainDelta, uint256 mintDelta, uint256 unauthorizedExecs, uint256 reserveDrain) =
            abi.decode(payload, (uint256, uint256, uint256, uint256));
        assertEq(mintDelta,         mintAmount, "Payload: correct mint mismatch delta");
        assertEq(drainDelta,        0,          "Payload: no drain delta");
        assertEq(unauthorizedExecs, 0,          "Payload: no router exec");
        assertEq(reserveDrain,      0,          "Payload: no reserve drain");
    }

    function test_phantomMint_HyperbridgePattern_1BTokens_triggers() public {
        // [EXPLOIT: Hyperbridge Apr 2026] Forged admin change -> 1B DOT phantom mint
        gateway.changeAdmin(attacker, "");
        vm.prank(attacker);
        gateway.mint(attacker, 1_000_000_000 ether); // 1 billion tokens

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger, "Hyperbridge 1B phantom mint MUST trigger");

        (, uint256 mintDelta,,) = abi.decode(payload, (uint256, uint256, uint256, uint256));
        assertGt(mintDelta, 10_000 ether, "Mint delta must exceed PHANTOM_MINT_THRESHOLD");
    }

    function test_exactMintThreshold_noTrigger() public view {
        // Exactly 10000 ETH delta -> does NOT fire
        // Partial auth growth bypasses zero-backing trigger
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 10_100 ether, 100 ether, 0, 0, 0, 0 // delta = 10000
        );
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Exactly 10000 ETH mint must NOT trigger (> not >=)");
    }

    function test_adminChangeAlone_noTrigger() public {
        // Admin change alone does NOT trigger the main trap.
        // The mismatch only grows when mint() is called without authorization.
        // This validates that OwnershipMonitorTrap is needed for that signal.
        gateway.changeAdmin(attacker, "");

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger,            "Admin change alone must NOT trigger main trap -- OwnershipMonitorTrap covers this");
    }

    function test_phantomMint_alertThreshold_firesBeforeResponse() public view {
        // 5000 ETH delta -- above alert, below response
        bytes[] memory data = _buildWindow(
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 5_100 ether, 100 ether, 0, 0, 0, 0 // delta = 5000
        );
        (bool respondFire,) = trap.shouldRespond(data);
        assertFalse(respondFire, "5000 ETH must NOT trigger shouldRespond (< 10000 ETH)");
        (bool alertFire,) = trap.shouldAlert(data);
        assertTrue(alertFire, "5000 ETH MUST trigger shouldAlert (> 2000 ETH alert threshold)");
    }

    function test_snapFreeze_haltsMinting() public {
        gateway.changeAdmin(attacker, "");
        vm.prank(attacker);
        gateway.mint(attacker, 15_000 ether);

        bytes[] memory data = new bytes[](2);
        data[0] = trap.collect();
        data[1] = _enc(0, 0, 0, 0, 0, 0, 0, 0);
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger);

        (uint256 d, uint256 m, uint256 u, uint256 r) = abi.decode(payload, (uint256, uint256, uint256, uint256));
        vm.prank(operator);
        response.snapFreeze(d, m, u, r);

        assertTrue(gateway.paused(), "Gateway must be paused");

        vm.prank(attacker);
        vm.expectRevert("Gateway paused");
        gateway.mint(attacker, 1_000 ether);
    }
}
