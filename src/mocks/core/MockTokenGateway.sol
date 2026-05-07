// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./MockERC20.sol";

// ─────────────────────────────────────────────────────────────────────────────
// MockTokenGateway
//
// The destination-side minting contract for bridge-wrapped tokens.
// In a lock-and-mint bridge, when a user locks ETH on source, the gateway
// mints wrapped ETH to the recipient.
//
// ARCHITECTURAL CHANGE FROM v1/v2:
//   BEFORE: `mintPhantom()` -- self-labeled malicious minting.
//   AFTER:  `mintWithAuthorization()` (legitimate admin path) +
//           `mint()` (admin path abused after seizure) +
//           `changeAdmin()` (no proof check -> IoTeX/Hyperbridge pattern).
//
// Real bridges don't expose phantom mint functions. They expose admin mint
// functions that are supposed to be called only after validated authorization.
// The exploit is that the admin role is seized, and mint() is called without
// a corresponding registerMintAuthorization().
//
// Normal operation:
//   1. Oracle confirms source lock
//   2. Validator calls registerMintAuthorization()
//   3. Admin calls mintWithAuthorization()
//   4. Both counters increment -> mismatch = 0
//
// Exploit operation (IoTeX/Hyperbridge):
//   Attacker calls changeAdmin() (no proof verification).
//   Attacker calls mint() without authorization.
//   cumulativeMinted grows. validatedMintAuthorizations stays put.
//   Mismatch grows. Trap fires.
//
// The gateway is innocent. The validation layer failed upstream.
// ─────────────────────────────────────────────────────────────────────────────
contract MockTokenGateway {
    MockERC20 public immutable bridgedToken;
    uint256 public cumulativeMinted;
    uint256 public validatedMintAuthorizations;

    struct MintAuth { uint256 amount; address recipient; bool consumed; }
    mapping(bytes32 => MintAuth) public mintAuthorizations;

    address public admin;
    address public immutable validator;
    bool    public paused;

    event MintAuthRegistered(bytes32 indexed eventHash, uint256 amount, address recipient);
    event AuthorizedMint(bytes32 indexed eventHash, address indexed recipient, uint256 amount);    event AdminMint(address indexed minter, address indexed recipient, uint256 amount);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event EmergencyPaused(address by);

    constructor(address _bridgedToken, address _validator) {
        require(_bridgedToken != address(0) && _validator != address(0), "zero address");
        bridgedToken = MockERC20(_bridgedToken); validator = _validator; admin = msg.sender;
    }

    modifier notPaused() { require(!paused, "Gateway paused"); _; }
    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }
    modifier onlyValidator() { require(msg.sender == validator, "not validator"); _; }

    function registerMintAuthorization(bytes32 eventHash, uint256 amount, address recipient) external onlyValidator {
        require(mintAuthorizations[eventHash].amount == 0, "auth exists");
        require(amount > 0 && recipient != address(0), "invalid");
        mintAuthorizations[eventHash] = MintAuth(amount, recipient, false);
        validatedMintAuthorizations += amount;
        emit MintAuthRegistered(eventHash, amount, recipient);
    }

    // LEGITIMATE ADMIN MINT: requires prior authorization.
    function mintWithAuthorization(bytes32 eventHash) external notPaused onlyAdmin {
        MintAuth storage auth = mintAuthorizations[eventHash];
        require(auth.amount > 0 && !auth.consumed, "invalid auth");
        auth.consumed = true;
        cumulativeMinted += auth.amount;
        bridgedToken.mint(auth.recipient, auth.amount);
        emit AuthorizedMint(eventHash, auth.recipient, auth.amount);
    }

    // ADMIN MINT: legitimate function, abused after admin seizure.
    // In normal operation, called only after registerMintAuthorization().
    // In exploit operation, called after changeAdmin() without authorization.
    function mint(address recipient, uint256 amount) external notPaused onlyAdmin {
        require(recipient != address(0) && amount > 0, "invalid");
        cumulativeMinted += amount;
        bridgedToken.mint(recipient, amount);
        emit AdminMint(msg.sender, recipient, amount);
    }

    // Missing proof verification. Simulates IoTeX/Hyperbridge admin seizure.
    function changeAdmin(address newAdmin, bytes calldata /*proof*/) external {
        address oldAdmin = admin; admin = newAdmin;
        emit AdminChanged(oldAdmin, newAdmin);
    }

    function gatewayTokenSupply() external view returns (uint256) {
        return bridgedToken.totalSupply();
    }
    function getMismatch() external view returns (uint256) {
        return cumulativeMinted > validatedMintAuthorizations
            ? cumulativeMinted - validatedMintAuthorizations : 0;
    }

    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }
}

