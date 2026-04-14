// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

interface IMockVault {
    function cumulativeWithdrawals() external view returns (uint256);
}

interface IMockGateway {
    function phantomMinted() external view returns (uint256);
}

interface IMockRouter {
    function spoofedMessageExecuted() external view returns (bool);
}

struct AlertData {
    uint256 vaultDrainVelocity;
    uint256 phantomMintVelocity;
    bool routerSpoofed;
}

contract BridgeRouterGuardTrap is ITrap {
    address public constant VAULT = 0x83c9e182b10aC6B62C559F9092C0Cfc12394Ab1E;
    address public constant GATEWAY = 0x544fFbCde66A95b24829EB6a5e803d27E7737Dc1;
    address public constant ROUTER = 0xca324202c796Aa8A5d8Ddcac384852854A253D66;

    function collect() external view virtual override returns (bytes memory) {
        return abi.encode(
            IMockVault(VAULT).cumulativeWithdrawals(),
            IMockGateway(GATEWAY).phantomMinted(),
            IMockRouter(ROUTER).spoofedMessageExecuted()
        );
    }

    function shouldRespond(bytes[] calldata data) external pure virtual override returns (bool, bytes memory) {
        if (data.length == 0 || data[0].length == 0) return (false, bytes(""));
        (uint256 vaultNow, uint256 phantomNow, bool routerNow) = abi.decode(data[0], (uint256, uint256, bool));
        if (data.length < 2 || data[data.length - 1].length == 0) {
            bool trigger = (vaultNow > 1000 ether || phantomNow > 10000 ether || routerNow);
            if (trigger) return (true, abi.encode(vaultNow, phantomNow, routerNow));
            return (false, bytes(""));
        }
        (uint256 vaultPrev, uint256 phantomPrev,) = abi.decode(data[data.length - 1], (uint256, uint256, bool));
        bool vaultDrained = (vaultNow > vaultPrev) && ((vaultNow - vaultPrev) > 1000 ether);
        bool phantomSpiked = (phantomNow > phantomPrev) && ((phantomNow - phantomPrev) > 10000 ether);
        if (vaultDrained || phantomSpiked || routerNow) {
            return (true, abi.encode(vaultNow, phantomNow, routerNow));
        }
        return (false, bytes(""));
    }

    function shouldAlert(bytes[] calldata data) external pure virtual returns (bool, bytes memory) {
        if (data.length < 2 || data[data.length - 1].length == 0) return (false, bytes(""));
        (uint256 vaultNow, uint256 phantomNow, bool routerNow) = abi.decode(data[0], (uint256, uint256, bool));
        (uint256 vaultPrev, uint256 phantomPrev,) = abi.decode(data[data.length - 1], (uint256, uint256, bool));
        uint256 vaultVelocity = vaultNow > vaultPrev ? vaultNow - vaultPrev : 0;
        uint256 phantomVelocity = phantomNow > phantomPrev ? phantomNow - phantomPrev : 0;
        bool isCritical = (vaultVelocity > 1000 ether) || (phantomVelocity > 10000 ether) || routerNow;
        if (isCritical) {
            AlertData memory alertInfo = AlertData({
                vaultDrainVelocity: vaultVelocity, phantomMintVelocity: phantomVelocity, routerSpoofed: routerNow
            });
            return (true, abi.encode(alertInfo));
        }
        return (false, bytes(""));
    }

    function decodeAlertOutput(bytes calldata data) public pure returns (AlertData memory) {
        return abi.decode(data, (AlertData));
    }
}
