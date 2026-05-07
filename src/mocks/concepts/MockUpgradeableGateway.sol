// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// MockUpgradeableGateway  (concept mock -- concepts/ folder)
//
// Validates the claim from 010-architecture-and-extensions.md (Trap 2):
// Monitors owner() and implementation() on upgradeable bridge contracts.
// Fires in the SAME BLOCK as an unauthorized ownership transfer -- before
// any phantom minting begins.
//
// Real-world evidence this concept is grounded in:
//
//   IoTeX ioTube (Feb 2026, ~$4.4M):
//     Root cause: Validator upgrade (UUPS proxy) replaced the implementation.
//     Intermediate step: TokenSafe.owner() and MintPool.owner() changed to
//     attacker-controlled address.
//     Minting began one step later.
//     OwnershipMonitorTrap fires in the SAME block as the ownership transfer --
//     before any phantom minting is submitted.
//
//   Hyperbridge (Apr 2026, ~$2.5M):
//     Root cause: Forged ChangeAssetAdmin message (MMR bounds-check bypass).
//     Intermediate step: bridged DOT token admin() changed to attacker address.
//     Minting began one step later (~1 hour after Phase 1 drain in some variants).
//     OwnershipMonitorTrap fires in the SAME block as the admin change --
//     before the 1B phantom DOT mint is submitted.
//
// The convergence of two independent exploit paths on the same intermediate
// on-chain state change is the argument for this trap. One was a key compromise
// + upgrade. One was a cryptographic library bug enabling message forgery.
// Different root causes. Same observable consequence. Same trap.
//
// INTERFACE CONTRACT (read by OwnershipMonitorTrap.collect()):
//   owner()          -> address
//   implementation() -> address
//   authorizedOwners(address) -> bool
//   totalMinted()    -> uint256 (for test assertions, not read by trap)
//
// PRODUCTION DEPLOYMENT NOTE:
//   This is a concept mock. Real upgradeable bridges must expose the exact
//   view functions above. The trap assumes minimal instrumentation: a public
//   owner(), implementation(), and an authorizedOwners mapping or equivalent
//   allowlist. No state writes occur in the trap; this contract only provides
//   the read surface and exploit simulation paths for testing.
// ─────────────────────────────────────────────────────────────────────────────
contract MockUpgradeableGateway {

    // ─── Proxy state -- what OwnershipMonitorTrap reads ────────────────────────
    // In normal operation: owner and implementation are stable.    // In exploit scenarios: either or both change without authorized governance.
    address public owner;
    address public implementation;
    address public proxyAdmin;    // address authorized to call upgrade()

    // ─── Known-authorized set ────────────────────────────────────────────────
    // OwnershipMonitorTrap compares current owner/impl against expected values.
    // This mapping exposes the authorized set so tests can verify trap logic.
    mapping(address => bool) public authorizedOwners;

    // ─── Bridge state ────────────────────────────────────────────────────────
    // The gateway holds minting authority. After admin change, the new owner
    // can mint tokens freely (the IoTeX / Hyperbridge exploit continuation).
    uint256 public totalMinted;
    bool    public paused;

    // ─── Events ───────────────────────────────────────────────────────────────
    event OwnerChanged(address indexed previousOwner, address indexed newOwner, bool authorized);
    event Upgraded(address indexed previousImpl, address indexed newImpl, bool authorized);
    event UnauthorizedMintAttempt(address indexed caller, uint256 amount);
    event TokensMinted(address indexed by, address indexed to, uint256 amount);
    event EmergencyPaused(address by);

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor(address _initialImpl) {
        require(_initialImpl != address(0), "MockUpgradeableGateway: zero implementation");
        owner          = msg.sender;
        implementation = _initialImpl;
        proxyAdmin     = msg.sender;
        authorizedOwners[msg.sender] = true;
    }

    modifier onlyProxyAdmin() {
        require(msg.sender == proxyAdmin, "MockUpgradeableGateway: not proxy admin");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "MockUpgradeableGateway: not owner");
        _;
    }

    // ─── Governance: authorized ownership transfer ────────────────────────────
    // Normal governance path: owner transfers to another authorized address.
    // OwnershipMonitorTrap sees this change but does NOT fire because the new
    // address is in authorizedOwners.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "MockUpgradeableGateway: zero address");
        bool isAuthorized = authorizedOwners[newOwner];
        address oldOwner  = owner;        owner             = newOwner;
        authorizedOwners[newOwner] = true;  // automatically authorize the new owner
        emit OwnerChanged(oldOwner, newOwner, isAuthorized);
    }

    // ─── EXPLOIT PATH A -- malicious ownership seizure ────────────────────────
    // [EXPLOIT MODEL: IoTeX ioTube Feb 2026]
    //
    // After the malicious Validator upgrade, the attacker transferred ownership
    // of TokenSafe and MintPool to their own address without governance approval.
    // This function replicates that step -- no authorization required.
    //
    // Effect:
    //   owner() changes to attacker address
    //   authorizedOwners[attacker] = false (attacker is NOT in authorized set)
    //   OwnershipMonitorTrap.collect() reads new owner()
    //   OwnershipMonitorTrap.shouldRespond() fires: owner not in authorized set
    //   This fires in the SAME block as the ownership transfer
    //   BEFORE any phantom minting occurs
    //
    // -> [NEUTRALIZED BY] OwnershipMonitorTrap.shouldRespond():
    //   if (!authorizedOwners[newOwner]) -> immediate trigger
    function seizeOwnership(address attacker) external {
        // [VULNERABILITY] No authorization check.
        // IoTeX: malicious upgrade() replaced implementation, then
        //        transferOwnership() was accessible to attacker.
        address oldOwner = owner;
        owner = attacker;
        // authorizedOwners[attacker] is NOT set -> trap fires on this
        emit OwnerChanged(oldOwner, attacker, false);
    }

    // ─── EXPLOIT PATH B -- malicious upgrade ──────────────────────────────────
    // [EXPLOIT MODEL: Hyperbridge Apr 2026 / IoTeX upgrade step]
    //
    // The Validator contract was upgraded to a malicious implementation.
    // This simulates that step: implementation() changes to an unauthorized address.
    //
    // Effect:
    //   implementation() changes to malicious address
    //   OwnershipMonitorTrap reads the change
    //   Fires if new implementation is not in the authorized set
    function maliciousUpgrade(address newImpl) external {
        // [VULNERABILITY] No timelock, no governance vote, no multisig.
        // IoTeX: upgrade() was callable by the compromised Validator owner key alone.
        // Hyperbridge: forged ChangeAssetAdmin bypassed proxy admin checks.
        address oldImpl = implementation;
        implementation  = newImpl;
        // authorizedImplementations check happens in OwnershipMonitorTrap
        emit Upgraded(oldImpl, newImpl, false);    }

    // ─── Authorized upgrade (governance path) ────────────────────────────────
    // Normal upgrade path. Requires proxyAdmin. New implementation is expected
    // to be tracked in the authorized set.
    function upgrade(address newImpl) external onlyProxyAdmin {
        require(newImpl != address(0), "MockUpgradeableGateway: zero implementation");
        address oldImpl = implementation;
        implementation  = newImpl;
        emit Upgraded(oldImpl, newImpl, true);
    }

    // ─── Post-seizure: minting ────────────────────────────────────────────────
    // After seizing ownership, the attacker can call mint() freely.
    // In OwnershipMonitorTrap tests, this step is PREVENTED because the trap
    // fires on the ownership change BEFORE this is called.
    function mint(address to, uint256 amount) external {
        if (msg.sender != owner) {
            emit UnauthorizedMintAttempt(msg.sender, amount);
            revert("MockUpgradeableGateway: not owner");
        }
        require(!paused, "MockUpgradeableGateway: paused");
        totalMinted += amount;
        emit TokensMinted(msg.sender, to, amount);
    }

    // ─── Authorized owner management ─────────────────────────────────────────
    // The OwnershipMonitorTrap stores a known-authorized set.
    // This contract exposes the same set so tests can verify trap logic.
    function addAuthorizedOwner(address addr) external onlyOwner {
        authorizedOwners[addr] = true;
    }

    // ─── Read helpers for OwnershipMonitorTrap.collect() ─────────────────────
    function isOwnerAuthorized() external view returns (bool) {
        return authorizedOwners[owner];
    }

    // ─── Response target ──────────────────────────────────────────────────────
    // Called by BridgeRouterGuardResponse.snapFreeze() or concept response contracts.
    // In production, this function must be restricted to an emergency guardian
    // or the Drosera response contract address.
    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}
