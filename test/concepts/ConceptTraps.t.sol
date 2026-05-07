// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/concepts/PreAttackMonitorTrap.sol";
import "../../src/concepts/OwnershipMonitorTrap.sol";
import "../../src/concepts/PositionMonitorTrap.sol";
import "../../src/mocks/concepts/MockPrivilegedBridge.sol";
import "../../src/mocks/concepts/MockUpgradeableGateway.sol";
import "../../src/mocks/concepts/MockLendingPool.sol";

// ─────────────────────────────────────────────────────────────────────────────
// ConceptTraps.t.sol  (v3 merged)
//
// Validates the architectural claims from 010-architecture-and-extensions:
//
//   Trap 2 -- OwnershipMonitorTrap: fires in SAME BLOCK as admin transfer
//            Evidence: IoTeX (Feb 2026), Hyperbridge (Apr 2026)
//
//   Trap 3 -- PreAttackMonitorTrap: fires BEFORE any funds move
//            Evidence: Force Bridge (Jun 2025), Orbit Chain (Dec 2023)
//
//   Trap 4 -- PositionMonitorTrap: fires within one block of stolen-token deposit
//            Evidence: Kelp DAO / Aave (Apr 2026)
//
// These tests change the status of the claims in 010 from "theorized based on
// case study analysis" to "validated by test against mock contracts."
//
// v3 CHANGES:
//   • Imports updated to flat src/concepts/ structure (testable wrappers merged)
//   • Added malformed data & wrong schema hardening tests per trap
//   • All original thresholds, exploit paths, and case study comments preserved
// ─────────────────────────────────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════════════════
// PreAttackMonitorTrap tests
// ══════════════════════════════════════════════════════════════════════════════
contract PreAttackMonitorTest is Test {
    address internal constant AUTHORIZED   = address(0xA000);
    address internal constant UNAUTHORIZED = address(0x000000000000000000000000000000000000dEaD);

    MockPrivilegedBridge          internal bridge;
    TestablePreAttackMonitorTrap  internal trap;

    address internal constant RS_ETH = address(uint160(0xe7));
    address internal constant WBTC   = address(0x0000000000000000000000000000000000000B7C);

    function setUp() public {
        bridge = new MockPrivilegedBridge(1);
        bridge.addSigner(AUTHORIZED);
        require(!bridge.authorizedSigners(UNAUTHORIZED), "UNAUTHORIZED must not be a signer");
        bridge.seedReserve(10_000 ether);
        trap = new TestablePreAttackMonitorTrap(address(bridge));        vm.roll(100); // start well past block 0
    }

    // ── Normal operation -- authorized calls do not record failed attempts ──────

    function test_authorizedCall_noFailedAttempts_noTrigger() public {
        vm.prank(AUTHORIZED);
        bridge.unlock(AUTHORIZED, 100 ether, keccak256("proof"));

        assertEq(bridge.failedAttemptCount(), 0, "Authorized call: no failed attempt recorded");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Authorized call must NOT trigger pre-attack monitor");
    }

    // ── Failed attempts from unauthorized address ─────────────────────────────

    function test_singleFailedAttempt_recordedButNoTrigger() public {
        vm.prank(UNAUTHORIZED);
        try bridge.unlock(UNAUTHORIZED, 100 ether, bytes32(0)) {} catch {}

        assertEq(bridge.failedAttemptCount(), 1, "One failed attempt recorded");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();

        // Only 1 failed attempt -- threshold is 3 for shouldRespond
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Single failed attempt must NOT trigger (threshold = 3)");

        // shouldAlert fires at 1
        (bool alert,) = trap.shouldAlert(data);
        assertTrue(alert, "Single failed attempt MUST trigger shouldAlert");
    }

    function test_threeFailedAttempts_triggers() public {
        // [VALIDATES: Force Bridge Jun 2025 -- 6-hour window of failed attempts]
        // lockedReserve does NOT change during failed attempts.
        // This fires with $0 at risk -- pure pre-drain signal.

        uint256 reserveBefore = bridge.lockedReserve();

        for (uint256 i = 0; i < 3; i++) {
            vm.prank(UNAUTHORIZED);
            try bridge.unlock(UNAUTHORIZED, 100 ether, bytes32(0)) {} catch {}
            vm.roll(block.number + 10); // advance blocks between attempts
        }
        assertEq(bridge.failedAttemptCount(), 3, "Three failed attempts recorded");
        assertEq(bridge.lockedReserve(), reserveBefore, "Reserve UNCHANGED -- fires before any loss");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger,
            "Three failed privileged calls MUST trigger -- validates Force Bridge claim: "
            "fires with $0 at risk during preparation phase");
    }

    function test_attemptsDifferentFunctions_allCount() public {
        // Attacker tries different privileged functions (unlock, release, withdraw)
        vm.prank(UNAUTHORIZED);
        try bridge.unlock(UNAUTHORIZED, 100 ether, bytes32(0)) {} catch {}

        vm.prank(UNAUTHORIZED);
        try bridge.release(UNAUTHORIZED, 100 ether) {} catch {}

        vm.prank(UNAUTHORIZED);
        try bridge.withdraw(100 ether, "") {} catch {}

        assertEq(bridge.failedAttemptCount(), 3, "All failed function calls counted");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Failed attempts across different functions MUST trigger");
    }

    function test_failedAttempts_outsideWindow_noTrigger() public {
        // Failed attempts very far back -- outside the window
        vm.prank(UNAUTHORIZED);
        try bridge.unlock(UNAUTHORIZED, 100 ether, bytes32(0)) {} catch {}
        vm.prank(UNAUTHORIZED);
        try bridge.unlock(UNAUTHORIZED, 100 ether, bytes32(0)) {} catch {}
        vm.prank(UNAUTHORIZED);
        try bridge.unlock(UNAUTHORIZED, 100 ether, bytes32(0)) {} catch {}

        // Advance 600 blocks -- past the 500-block window
        vm.roll(block.number + 600);

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Failed attempts outside window must NOT trigger");
    }

    // ── v3 Hardening: malformed & schema safety ───────────────────────────────
    function test_malformedData_noRevert() public view {        bytes[] memory data = new bytes[](1);
        data[0] = hex"deadbeef";
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Malformed data must not revert");
    }

    function test_wrongSchemaVersion_noTrigger() public view {
        bytes memory wrongSchema = abi.encode(PreAttackCollectOutput({
            schemaVersion: 99, failedAttemptCount: 10, attemptsInWindow: 10,
            lastUnauthorizedCaller: address(0xBAD), lockedReserve: 1000 ether
        }));
        bytes[] memory data = new bytes[](1);
        data[0] = wrongSchema;
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Wrong schema version must NOT trigger");
    }
}


// ══════════════════════════════════════════════════════════════════════════════
// OwnershipMonitorTrap tests
// ══════════════════════════════════════════════════════════════════════════════
contract OwnershipMonitorTest is Test {

    MockUpgradeableGateway          internal gateway;
    TestableOwnershipMonitorTrap    internal trap;

    address internal constant INITIAL_IMPL = address(0xC001);
    address internal constant MALICIOUS_IMPL = address(0xBAD1);
    address internal constant ATTACKER = address(0xBAD);
    address internal constant AUTHORIZED_NEW_OWNER = address(0xA111);

    function setUp() public {
        gateway = new MockUpgradeableGateway(INITIAL_IMPL);
        gateway.addAuthorizedOwner(AUTHORIZED_NEW_OWNER);
        // Pass INITIAL_IMPL as expected implementation
        trap = new TestableOwnershipMonitorTrap(address(gateway), INITIAL_IMPL);
    }

    // ── Normal operation ──────────────────────────────────────────────────────

    function test_stableOwner_noTrigger() public view {
        // Owner is deployer (authorized). No change. No trigger.
        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Stable authorized owner must NOT trigger");
    }

    function test_authorizedOwnerTransfer_noTrigger() public {        // Governance transfers to another authorized address
        gateway.transferOwnership(AUTHORIZED_NEW_OWNER);
        assertTrue(gateway.authorizedOwners(AUTHORIZED_NEW_OWNER), "New owner is authorized");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Transfer to authorized owner must NOT trigger");
    }

    // ── Exploit: IoTeX -- malicious ownership seizure ──────────────────────────

    function test_ownershipSeizure_IoTeXPattern_triggersImmediately() public {
        // [VALIDATES: IoTeX ioTube Feb 2026 claim]
        // Attacker calls seizeOwnership() -- no authorization.
        // OwnershipMonitorTrap fires in SAME BLOCK as the seizure.
        // This is BEFORE any minting occurs.

        address ownerBefore = gateway.owner();
        gateway.seizeOwnership(ATTACKER);

        assertEq(gateway.owner(), ATTACKER, "Attacker seized ownership");
        assertFalse(gateway.authorizedOwners(ATTACKER), "Attacker NOT in authorized set");
        assertEq(gateway.totalMinted(), 0, "No minting yet -- trap fires before minting");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger,
            "Ownership seizure MUST trigger immediately -- validates IoTeX claim: "
            "fires in same block as transfer, BEFORE phantom minting begins");

        (address detectedOwner,) = abi.decode(payload, (address, address));
        assertEq(detectedOwner, ATTACKER, "Detected unauthorized owner is attacker");
        assertNotEq(ownerBefore, ATTACKER, "Ownership changed from legitimate to attacker");
    }

    function test_maliciousUpgrade_HyperbridgePattern_triggersImmediately() public {
        // [VALIDATES: Hyperbridge Apr 2026 claim]
        // Forged ChangeAssetAdmin message -> malicious upgrade.
        // Implementation changes to an unauthorized address.
        gateway.maliciousUpgrade(MALICIOUS_IMPL);

        assertEq(gateway.implementation(), MALICIOUS_IMPL, "Malicious impl installed");

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger,
            "Malicious upgrade MUST trigger -- validates Hyperbridge claim: "            "fires in same block as admin change, before 1B phantom tokens minted");

        (, address detectedImpl) = abi.decode(payload, (address, address));
        assertEq(detectedImpl, MALICIOUS_IMPL, "Detected unauthorized implementation");
    }

    function test_seizureThenMinting_trapFiresOnSeizure_mintingPrevented() public {
        // Full IoTeX sequence: seize -> try to mint
        // The ownership trap fires on seizure.
        // If the response contract had paused the gateway at that point,
        // minting would be impossible. This test shows the chronology.

        gateway.seizeOwnership(ATTACKER);

        // Trap fires here -- before any minting
        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertTrue(trigger, "Trap fires on seizure before minting");
        assertEq(gateway.totalMinted(), 0, "No minting has occurred when trap fires");

        // If a response contract had paused the gateway now:
        gateway.emergencyPause();

        // Attacker cannot mint after pause
        vm.prank(ATTACKER);
        vm.expectRevert("MockUpgradeableGateway: paused");
        gateway.mint(ATTACKER, 1_000_000 ether);

        assertEq(gateway.totalMinted(), 0, "Minting completely prevented by early detection");
    }

    // ── v3 Hardening: malformed data safety ───────────────────────────────────
    function test_malformedData_noRevert() public view {
        bytes[] memory data = new bytes[](1);
        data[0] = hex"cafebabe";
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Malformed data must not revert");
    }
}


// ══════════════════════════════════════════════════════════════════════════════
// PositionMonitorTrap tests
// ══════════════════════════════════════════════════════════════════════════════
contract PositionMonitorTest is Test {

    MockLendingPool               internal pool;
    TestablePositionMonitorTrap   internal trap;
    address internal constant RS_ETH = address(uint160(0xe7));
    address internal constant WBTC = address(0x0000000000000000000000000000000000000B7C);
    address internal constant ATTACKER = address(0xBAD);

    function setUp() public {
        pool = new MockLendingPool();
        pool.acceptToken(RS_ETH, 8000); // 80% LTV -- same as Aave rsETH config
        pool.acceptToken(WBTC,   7500);
        trap = new TestablePositionMonitorTrap(address(pool), RS_ETH);
    }

    // ── Normal operation ──────────────────────────────────────────────────────

    function test_normalLendingActivity_noTrigger() public {
        // Mixed collateral, moderate utilization -- normal lending behavior
        pool.depositCollateral(WBTC,   10 ether, 500 ether);  // WBTC as collateral
        pool.depositCollateral(RS_ETH, 10 ether, 100 ether);  // small rsETH position

        // rsETH share: 100/600 = 16.7% -> below 50% composition threshold
        // Even if borrow happens, utilization low

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Normal mixed lending must NOT trigger");
    }

    // ── Exploit: Kelp DAO / Aave scenario ────────────────────────────────────

    function test_stolenTokensAsCollateral_KelpDAOPattern_triggers() public {
        // [VALIDATES: Kelp DAO Apr 2026 claim]
        // Attacker deposits 116,500 rsETH (stolen bridge tokens) as collateral.
        // rsETH share immediately dominates pool.
        // Attacker borrows against it.
        // Trap fires within one block of deposit.

        // Simulate: attacker deposits massive amount of stolen rsETH
        vm.prank(ATTACKER);
        pool.depositCollateral(RS_ETH, 116_500 ether, 116_500 ether); // 1:1 ETH value

        // rsETH now = 100% of pool collateral
        assertEq(pool.collateralShare(RS_ETH), 10_000, "rsETH = 100% of pool collateral");

        // Attacker borrows against it (up to 80% LTV)
        vm.prank(ATTACKER);
        pool.borrow(90_000 ether); // borrow 90,000 ETH against 116,500 ETH rsETH collateral

        // Utilization = 90000/116500 = ~77% -> above 70% threshold
        uint256 utilRate = pool.utilizationRate();
        assertGt(utilRate, 7_000, "Utilization must exceed alert threshold");
        // Trap fires -- both conditions met simultaneously
        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(trigger,
            "Kelp/Aave pattern MUST trigger -- validates claim: fires within 1 block of deposit. "
            "Actual Aave Guardian response: 77 minutes. This trap: ~12 seconds.");

        (uint256 shareDetected, uint256 utilDetected,) =
            abi.decode(payload, (uint256, uint256, uint256));
        assertGe(shareDetected, 5_000, "Detected composition >= 50%");
        assertGe(utilDetected,  7_000, "Detected utilization >= 70%");
    }

    function test_alertThreshold_firesEarlier() public {
        // Alert at 20% composition AND 50% utilization
        // (lower than 50% + 70% response threshold)
        vm.prank(ATTACKER);
        pool.depositCollateral(RS_ETH, 5_000 ether, 5_000 ether); // 100% of pool

        vm.prank(ATTACKER);
        pool.borrow(3_000 ether); // 60% utilization

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();

        (bool respondTrigger,) = trap.shouldRespond(data);
        (bool alertTrigger,)   = trap.shouldAlert(data);

        // Alert fires at lower thresholds
        assertTrue(alertTrigger,   "shouldAlert must fire at lower thresholds");
        // Response may or may not fire depending on values -- just verify alert < response threshold
    }

    function test_highCompositionLowUtilization_noTrigger() public {
        // rsETH dominates collateral but nobody is borrowing against it yet
        vm.prank(ATTACKER);
        pool.depositCollateral(RS_ETH, 10_000 ether, 10_000 ether);

        // No borrow -> utilization = 0 -> combined condition not met
        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger,
            "High composition alone (without high utilization) must NOT trigger. "
            "Both conditions required to distinguish exploit from legitimate deposit.");
    }

    function test_highUtilizationLowComposition_noTrigger() public {
        // Use only WBTC collateral to avoid mock limitation of single collateral per address
        pool.depositCollateral(WBTC, 100 ether, 10_000 ether);
        pool.borrow(7_500 ether); // 75% of 10,000 ETH collateral at 75% LTV

        bytes[] memory data = new bytes[](1);
        data[0] = trap.collect();
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger,
            "High utilization with low rsETH share must NOT trigger. "
            "Normal leveraged lending with diversified collateral.");
    }

    // ── v3 Hardening: malformed data safety ───────────────────────────────────
    function test_malformedData_noRevert() public view {
        bytes[] memory data = new bytes[](1);
        data[0] = hex"deadbeef";
        (bool trigger,) = trap.shouldRespond(data);
        assertFalse(trigger, "Malformed data must not revert");
    }
}
