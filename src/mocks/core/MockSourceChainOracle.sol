// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// MockSourceChainOracle  (v3)
//
// Simulates the ground truth that a destination-chain bridge contract is
// supposed to verify before releasing or minting assets.
//
// In every exploit in this case study set, the fundamental failure was that
// the destination chain executed without confirming against the source chain:
//
//   Multichain (Jul 2023)     -- MPC keys compromised; oracle was the MPC
//                               node set; source confirmations never checked
//   Orbit Chain (Dec 2023)    -- multisig signers phished; oracle was the
//                               7/10 multisig quorum
//   Force Bridge (Jun 2025)   -- deployer key compromised; oracle was the
//                               privileged relayer
//   CrossCurve (Feb 2026)     -- Axelar gateway was the oracle;
//                               expressExecute() bypassed it entirely
//   IoTeX ioTube (Feb 2026)   -- Validator upgrade removed the oracle layer
//   Hyperbridge (Apr 2026)    -- MMR proof library was the oracle; bounds
//                               check missing allowed forged proofs
//   Kelp DAO (Apr 2026)       -- LayerZero DVN was the oracle; RPC nodes
//                               poisoned so DVN attested forged messages
//
// This contract represents the on-chain readable portion of that oracle:
// a registry of source-chain events (locks, deposits, burns) that the
// destination chain can query to confirm an inbound event actually happened.
//
// Three states an event can be in:
//   PENDING   -- event reported, not yet finality-confirmed
//   CONFIRMED -- finality passed, safe to release on destination
//   CONSUMED  -- destination contract has already used this credit once
//               (prevents replay attacks)
//
// MockMessageValidator reads this contract before registering credits.
// In normal operation: validator checks CONFIRMED -> registers credit -> marks CONSUMED.
// In compromised operation: validator skips the check entirely.
// In poisoned operation: validator checks, but the oracle reports false confirmations.
//
// INTERFACE CONTRACT (read by MockMessageValidator):
//   isConfirmed(bytes32) -> bool
//   isConsumed(bytes32) -> bool
//   getEvent(bytes32) -> SourceEvent (for test assertions)
//
// PRODUCTION DEPLOYMENT NOTE:
//   This is a concept mock. Real oracles must expose the exact view functions
//   above. The validator assumes minimal instrumentation: public event status
//   tracking and compromise controls for testing. No state writes occur in the//   validator; this contract only provides the read surface and exploit
//   simulation paths for testing.
// ─────────────────────────────────────────────────────────────────────────────
contract MockSourceChainOracle {

    // ─── Event status ─────────────────────────────────────────────────────────
    enum EventStatus { UNKNOWN, PENDING, CONFIRMED, CONSUMED }

    // ─── Source chain event ───────────────────────────────────────────────────
    struct SourceEvent {
        bytes32     eventHash;      // keccak256(sourceChain, sender, token, amount, nonce)
        address     token;          // token locked or burned on source chain
        uint256     amount;         // amount in token's native decimals
        address     recipient;      // intended destination-chain recipient
        uint256     sourceBlock;    // block number on source chain when lock occurred
        EventStatus status;
        bool        poisoned;       // true if oracle was instructed to lie about this event
                                    // (Kelp DVN poisoning model, Hyperbridge MMR bypass model)
    }

    // ─── Storage ──────────────────────────────────────────────────────────────
    mapping(bytes32 => SourceEvent) public events;

    // Cumulative counters for trap monitoring
    uint256 public totalConfirmedValue;   // sum of all CONFIRMED event amounts (ETH-normalized)
    uint256 public totalConsumedValue;    // sum of all CONSUMED event amounts

    // Oracle compromise state -- controls whether the oracle can be poisoned
    // CompromiseType A: SILENT -- oracle stops reporting (simulates MPC gone, keys lost)
    // CompromiseType B: POISONED -- oracle reports false confirmations (DVN poisoning, MMR bypass)
    enum CompromiseType { NONE, SILENT, POISONED }
    CompromiseType public compromiseState;

    // Addresses authorized to submit source-chain events (relayers, validators)
    mapping(address => bool) public authorizedRelayers;

    address public owner;

    // ─── Events ───────────────────────────────────────────────────────────────
    event SourceEventRegistered(bytes32 indexed eventHash, address token, uint256 amount, address recipient);
    event SourceEventConfirmed(bytes32 indexed eventHash);
    event SourceEventConsumed(bytes32 indexed eventHash);
    event OracleCompromised(CompromiseType compromiseType);
    event RelayerAdded(address relayer);

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor() {
        owner = msg.sender;
        authorizedRelayers[msg.sender] = true;
    }
    modifier onlyOwner() {
        require(msg.sender == owner, "MockSourceChainOracle: not owner");
        _;
    }

    modifier onlyRelayer() {
        require(authorizedRelayers[msg.sender], "MockSourceChainOracle: not authorized relayer");
        _;
    }

    // ─── Relayer management ───────────────────────────────────────────────────
    function addRelayer(address relayer) external onlyOwner {
        require(relayer != address(0), "MockSourceChainOracle: zero address");
        authorizedRelayers[relayer] = true;
        emit RelayerAdded(relayer);
    }

    // ─── Normal operation ─────────────────────────────────────────────────────

    // Step 1: Relayer reports that a source-chain lock/burn/deposit occurred.
    // Event starts as PENDING -- not yet safe to release.
    function registerSourceEvent(
        bytes32 eventHash,
        address token,
        uint256 amount,
        address recipient,
        uint256 sourceBlock
    ) external onlyRelayer {
        require(events[eventHash].status == EventStatus.UNKNOWN, "MockSourceChainOracle: event already registered");
        events[eventHash] = SourceEvent({
            eventHash:   eventHash,
            token:       token,
            amount:      amount,
            recipient:   recipient,
            sourceBlock: sourceBlock,
            status:      EventStatus.PENDING,
            poisoned:    false
        });
        emit SourceEventRegistered(eventHash, token, amount, recipient);
    }

    // Step 2: After finality passes on source chain, relayer confirms.
    // CONFIRMED events are safe to consume on the destination side.
    function confirmSourceEvent(bytes32 eventHash) external onlyRelayer {
        SourceEvent storage ev = events[eventHash];
        require(ev.status == EventStatus.PENDING, "MockSourceChainOracle: event not pending");

        // SILENT compromise: oracle stops working -- can't confirm anything.
        // Simulates Multichain MPC gone, keys confiscated.        // In this mode, the oracle never moves events past PENDING.
        if (compromiseState == CompromiseType.SILENT) {
            revert("MockSourceChainOracle: oracle offline (SILENT compromise)");
        }

        ev.status = EventStatus.CONFIRMED;
        totalConfirmedValue += ev.amount;
        emit SourceEventConfirmed(eventHash);
    }

    // Step 3: MockMessageValidator calls this when consuming a credit for
    // a destination-chain release. Marks as CONSUMED to prevent replay.
    function consumeSourceEvent(bytes32 eventHash) external onlyRelayer {
        SourceEvent storage ev = events[eventHash];
        require(
            ev.status == EventStatus.CONFIRMED || ev.poisoned,
            "MockSourceChainOracle: event not confirmed"
        );
        require(ev.status != EventStatus.CONSUMED, "MockSourceChainOracle: already consumed");
        ev.status = EventStatus.CONSUMED;
        totalConsumedValue += ev.amount;
        emit SourceEventConsumed(eventHash);
    }

    // ─── Query interface (used by MockMessageValidator) ───────────────────────

    // Primary query: is this event CONFIRMED and ready to consume?
    // POISONED oracle: returns true for forged events (Kelp DVN / Hyperbridge MMR model).
    function isConfirmed(bytes32 eventHash) external view returns (bool) {
        SourceEvent storage ev = events[eventHash];

        // POISONED compromise: oracle lies. Returns true for events flagged as
        // poisoned -- regardless of their actual on-chain status.
        // Simulates: DVN RPC nodes replaced with versions that attest any message.
        // Simulates: MMR library returning a valid root for an out-of-bounds leaf.
        if (compromiseState == CompromiseType.POISONED && ev.poisoned) {
            return true;
        }

        return ev.status == EventStatus.CONFIRMED;
    }

    function isConsumed(bytes32 eventHash) external view returns (bool) {
        return events[eventHash].status == EventStatus.CONSUMED;
    }

    // Returns the full SourceEvent struct for a given eventHash.
    // Used in tests to assert event state and for debugging.
    function getEvent(bytes32 eventHash) external view returns (SourceEvent memory) {
        return events[eventHash];    }

    // ─── Compromise controls (exploit scenario setup) ─────────────────────────

    // Switch A -- SILENT: oracle goes offline. No new confirmations.
    // Used by: Multichain tests, Orbit Chain tests, Force Bridge tests.
    function compromiseSilent() external onlyOwner {
        compromiseState = CompromiseType.SILENT;
        emit OracleCompromised(CompromiseType.SILENT);
    }

    // Switch B -- POISONED: oracle attests forged events.
    // Then call poisonEvent() on specific event hashes to flag them.
    // Used by: Kelp DAO tests (DVN poisoning), Hyperbridge tests (MMR bypass).
    function compromisePoisoned() external onlyOwner {
        compromiseState = CompromiseType.POISONED;
        emit OracleCompromised(CompromiseType.POISONED);
    }

    // Mark a specific event hash as poisoned.
    // When the oracle is in POISONED mode, isConfirmed() returns true for
    // these even if they were never legitimately registered or confirmed.
    // This allows tests to construct entirely fabricated event hashes
    // (as the Kelp / Hyperbridge attacker did) and have the oracle bless them.
    function poisonEvent(
        bytes32 eventHash,
        address token,
        uint256 amount,
        address recipient
    ) external onlyOwner {
        // Register as a forged event that was never legitimately seen on source chain
        events[eventHash] = SourceEvent({
            eventHash:   eventHash,
            token:       token,
            amount:      amount,
            recipient:   recipient,
            sourceBlock: 0,
            status:      EventStatus.PENDING, // never legitimately confirmed
            poisoned:    true
        });
        emit SourceEventRegistered(eventHash, token, amount, recipient);
    }

    // Restore to normal operation (for multi-phase tests)
    function restoreOracle() external onlyOwner {
        compromiseState = CompromiseType.NONE;
    }
}
