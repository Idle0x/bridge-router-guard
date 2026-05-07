// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// MockERC20
//
// A minimal but complete ERC20 token used as the real asset held inside
// MockBridgeVault. This is NOT a simulation counter -- it is an actual token
// contract. When a drain test runs, tokens physically transfer from the vault
// to the attacker address. The attacker's balance is then asserted in tests.
//
// ARCHITECTURAL NOTE:
//   The original codebase tracked `cumulativeWithdrawals` as an abstract counter.
//   An attacker draining a real bridge ends up holding real tokens. This contract
//   makes that concrete. Tests assert `balanceOf(attacker)`, not just counter deltas.
//
// In production, this role is filled by USDC, WETH, WBTC, or any bridged ERC20.
// The mock is generic. Multi-asset drains (Orbit Chain, Force Bridge) can be
// simulated by deploying multiple instances with different symbols.
//
// Authorized minters:
//   The vault is the primary minter (initial liquidity).
//   The gateway is the minter for bridge-wrapped tokens.
//   In exploit scenarios, an attacker who has seized admin can mint freely.
// ─────────────────────────────────────────────────────────────────────────────
contract MockERC20 {
    string  public name;
    string  public symbol;
    uint8   public immutable decimals;
    uint256 public totalSupply;

    mapping(address => uint256)                     public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool)                        public authorizedMinters;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event MinterAdded(address indexed minter);

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name; symbol = _symbol; decimals = _decimals;
        authorizedMinters[msg.sender] = true;
        emit MinterAdded(msg.sender);
    }

    function addMinter(address minter) external {
        require(authorizedMinters[msg.sender], "MockERC20: not minter");
        authorizedMinters[minter] = true;
        emit MinterAdded(minter);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "zero address");
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(to != address(0), "zero address");
        require(balanceOf[from] >= amount, "insufficient balance");
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        require(authorizedMinters[msg.sender], "MockERC20: not minter");
        require(to != address(0), "zero address");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
