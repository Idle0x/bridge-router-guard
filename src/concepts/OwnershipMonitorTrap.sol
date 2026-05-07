// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

// ─────────────────────────────────────────────────────────────────────────────
// OwnershipMonitorTrap
//
// Validates claim from 010-architecture-and-extensions.md (Trap 2):
// Monitors owner() and implementation() on upgradeable bridge contracts.
// Fires in the SAME BLOCK as an unauthorized ownership transfer -- before
// any phantom minting begins.
//
// Evidence: IoTeX ioTube (Feb 2026)  -- ownership of MintPool transferred to
//                                       attacker before mint.
//           Hyperbridge (Apr 2026)   -- admin of bridged DOT changed via forged
//                                       ChangeAssetAdmin before 1B mint.
//
// These two independent exploits arrived at the same intermediate on-chain
// step. The convergence is the argument for this trap.
//
// PRODUCTION DEPLOYMENT:
//   • Update GATEWAY & EXPECTED_IMPLEMENTATION constants post-deployment.
//   • Target must expose IUpgradeableGateway view functions.
//   • Drosera requires stateless traps: no constructor args, pure/view logic only.
// ─────────────────────────────────────────────────────────────────────────────

interface IUpgradeableGateway {
    function owner()          external view returns (address);
    function implementation() external view returns (address);
    function authorizedOwners(address) external view returns (bool);
}

struct OwnershipCollectOutput {
    uint8   schemaVersion;
    address currentOwner;
    address currentImplementation;
    bool    ownerIsAuthorized;       // false = unauthorized ownership detected
    bool    implIsAuthorized;        // false = unauthorized upgrade detected
}

struct OwnershipAlertData {
    address currentOwner;
    address currentImplementation;
    bool    ownerIsAuthorized;
    bool    implIsAuthorized;
}

contract OwnershipMonitorTrap is ITrap {
    address public constant GATEWAY = address(0); // set after deployment

    // The trap stores the expected authorized implementation hash.
    // If implementation() changes to anything else -> fire.
    // In production: populate from the known-good deployment.
    address public constant EXPECTED_IMPLEMENTATION = address(0);

    uint8 public constant SCHEMA_VERSION = 1;

    function collect() external view virtual override returns (bytes memory) {
        address currentOwner = IUpgradeableGateway(GATEWAY).owner();
        address currentImpl  = IUpgradeableGateway(GATEWAY).implementation();
        bool ownerAuth       = IUpgradeableGateway(GATEWAY).authorizedOwners(currentOwner);
        bool implAuth        = (EXPECTED_IMPLEMENTATION == address(0))
                                   ? true  // not configured -> do not fire on impl
                                   : (currentImpl == EXPECTED_IMPLEMENTATION);

        return abi.encode(OwnershipCollectOutput({
            schemaVersion:          SCHEMA_VERSION,
            currentOwner:           currentOwner,
            currentImplementation:  currentImpl,
            ownerIsAuthorized:      ownerAuth,
            implIsAuthorized:       implAuth
        }));
    }

    function shouldRespond(bytes[] calldata data)
        external
        pure
        virtual
        override
        returns (bool, bytes memory)
    {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));

        OwnershipCollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        // Fire immediately if owner or implementation is unauthorized.
        // No velocity window needed -- ownership change is a hard invariant.
        // One unauthorized owner = one too many.
        if (!newest.ownerIsAuthorized || !newest.implIsAuthorized) {
            return (true, abi.encode(newest.currentOwner, newest.currentImplementation));
        }

        return (false, bytes(""));
    }

    function shouldAlert(bytes[] calldata data)
        external        pure
        virtual
        returns (bool, bytes memory)
    {
        // Same logic -- ownership deviation is always critical
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));
        OwnershipCollectOutput memory newest = _decode(data[0]);
        if (newest.schemaVersion == 0) return (false, bytes(""));

        if (!newest.ownerIsAuthorized || !newest.implIsAuthorized) {
            return (true, abi.encode(OwnershipAlertData({
                currentOwner: newest.currentOwner,
                currentImplementation: newest.currentImplementation,
                ownerIsAuthorized: newest.ownerIsAuthorized,
                implIsAuthorized: newest.implIsAuthorized
            })));
        }
        return (false, bytes(""));
    }

    // Fail-safe decode. Returns zeroed struct (schemaVersion = 0) on malformed input.
    // ABI minimum size: uint8 + 4×32 bytes = 160 bytes.
    function _decode(bytes calldata sample) internal pure returns (OwnershipCollectOutput memory out) {
        if (sample.length < 160) return out;
        out = abi.decode(sample, (OwnershipCollectOutput));
        if (out.schemaVersion != SCHEMA_VERSION) return OwnershipCollectOutput(0, address(0), address(0), false, false);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Testable wrapper for CI/CD. Inherits ALL logic. Only collect() is overridden.
// ─────────────────────────────────────────────────────────────────────────────
contract TestableOwnershipMonitorTrap is OwnershipMonitorTrap {

    address public immutable GATEWAY_TEST;
    address public immutable EXPECTED_IMPL_TEST;

    constructor(address gateway, address expectedImpl) {
        require(gateway != address(0), "TestableOwnership: zero gateway");
        GATEWAY_TEST       = gateway;
        EXPECTED_IMPL_TEST = expectedImpl; // pass address(0) to skip impl check
    }

    function collect() external view override returns (bytes memory) {
        address currentOwner = IUpgradeableGateway(GATEWAY_TEST).owner();
        address currentImpl  = IUpgradeableGateway(GATEWAY_TEST).implementation();
        bool ownerAuth       = IUpgradeableGateway(GATEWAY_TEST).authorizedOwners(currentOwner);
        bool implAuth        = (EXPECTED_IMPL_TEST == address(0))
                                   ? true
                                   : (currentImpl == EXPECTED_IMPL_TEST);
        return abi.encode(OwnershipCollectOutput({
            schemaVersion:         SCHEMA_VERSION,
            currentOwner:          currentOwner,
            currentImplementation: currentImpl,
            ownerIsAuthorized:     ownerAuth,
            implIsAuthorized:      implAuth
        }));
    }
}
