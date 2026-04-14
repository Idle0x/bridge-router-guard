// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockERC20 {
    string public name = "Bridged Token";
    string public symbol = "BTKN";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
