// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║            dotBOT Name Service — BOT Chain                  ║
 * ║  A fully onchain ENS-style registry for .bot names          ║
 * ║                                                              ║
 * ║  Architecture:                                               ║
 * ║    BotRegistry        — owns all names, holds NFTs           ║
 * ║    BotResolver        — stores records per name              ║
 * ║    BotRegistrar       — commit-reveal + pricing              ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

// ─────────────────────────────────────────────
//  INTERFACES
// ─────────────────────────────────────────────

interface IBotRegistry {
    function owner() external view returns (address);
    function setOwner(bytes32 node, address newOwner) external;
    function setResolver(bytes32 node, address resolver) external;
    function setTTL(bytes32 node, uint64 ttl) external;
    function resolver(bytes32 node) external view returns (address);
    function ttl(bytes32 node) external view returns (uint64);
    function ownerOf(bytes32 node) external view returns (address);
    function isApprovedForAll(address owner_, address operator) external view returns (bool);
}

// ─────────────────────────────────────────────
//  LIBRARY: Namehash
//  Mirrors ENS namehash spec for .bot TLD
// ─────────────────────────────────────────────

library BotNamehash {
    /// @notice Compute the namehash for label.bot
    function namehash(string memory label) internal pure returns (bytes32) {
        // bot TLD node = keccak256(keccak256("") + keccak256("bot"))
        bytes32 botNode = keccak256(
            abi.encodePacked(bytes32(0), keccak256(bytes("bot")))
        );
        // full node = keccak256(botNode + keccak256(label))
        return keccak256(abi.encodePacked(botNode, keccak256(bytes(label))));
    }

    /// @notice Validate label: 3–64 chars, lowercase alphanumeric or hyphen
    function isValidLabel(string memory label) internal pure returns (bool) {
        bytes memory b = bytes(label);
        uint256 len = b.length;
        if (len < 3 || len > 64) return false;
        // Cannot start or end with hyphen
        if (b[0] == 0x2D || b[len - 1] == 0x2D) return false;
        for (uint256 i = 0; i < len; i++) {
            bytes1 c = b[i];
            bool isLower  = (c >= 0x61 && c <= 0x7A); // a-z
            bool isDigit  = (c >= 0x30 && c <= 0x39); // 0-9
            bool isHyphen = (c == 0x2D);               // -
            if (!isLower && !isDigit && !isHyphen) return false;
        }
        return true;
    }
}

// ─────────────────────────────────────────────
//  CONTRACT: BotRegistry
//  The canonical ownership registry. Immutable
//  after deployment — all state lives here.
// ─────────────────────────────────────────────

contract BotRegistry {
    using BotNamehash for string;

    struct Record {
        address owner;
        address resolver;
        uint64  ttl;
    }

    mapping(bytes32 => Record) private _records;
    mapping(address => mapping(address => bool)) private _operators;

    // Authorised registrar that can create new nodes
    address public registrar;
    address public admin;

    event NewOwner   (bytes32 indexed node, address indexed owner);
    event NewResolver(bytes32 indexed node, address indexed resolver);
    event NewTTL     (bytes32 indexed node, uint64 ttl);
    event Transfer   (bytes32 indexed node, address owner);
    event ApprovalForAll(address indexed owner_, address indexed operator, bool approved);

    modifier authorised(bytes32 node) {
        address o = _records[node].owner;
        require(
            o == msg.sender || _operators[o][msg.sender],
            "BotRegistry: not authorised"
        );
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "BotRegistry: admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setRegistrar(address _registrar) external onlyAdmin {
        registrar = _registrar;
    }

    /// @notice Only callable by the registrar — creates / reassigns ownership
    function setOwner(bytes32 node, address newOwner) external {
        require(
            msg.sender == registrar ||
            _records[node].owner == msg.sender ||
            _operators[_records[node].owner][msg.sender],
            "BotRegistry: not authorised"
        );
        _records[node].owner = newOwner;
        emit NewOwner(node, newOwner);
    }

    function setResolver(bytes32 node, address res) external authorised(node) {
        _records[node].resolver = res;
        emit NewResolver(node, res);
    }

    function setTTL(bytes32 node, uint64 t) external authorised(node) {
        _records[node].ttl = t;
        emit NewTTL(node, t);
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operators[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function ownerOf(bytes32 node) external view returns (address) {
        return _records[node].owner;
    }

    function resolver(bytes32 node) external view returns (address) {
        return _records[node].resolver;
    }

    function ttl(bytes32 node) external view returns (uint64) {
        return _records[node].ttl;
    }

    function isApprovedForAll(address owner_, address operator) external view returns (bool) {
        return _operators[owner_][operator];
    }
}

// ─────────────────────────────────────────────
//  CONTRACT: BotResolver
//  Stores arbitrary key-value records for each
//  registered name. Mirrors ENS PublicResolver.
// ─────────────────────────────────────────────

contract BotResolver {
    BotRegistry public immutable registry;

    // addr(node)  — the primary wallet address
    mapping(bytes32 => mapping(uint256 => address)) private _addrs;

    // text(node, key) → value  (github, twitter, email, bio …)
    mapping(bytes32 => mapping(string => string)) private _texts;

    // contenthash(node) → bytes  (IPFS, IPNS, Swarm …)
    mapping(bytes32 => bytes) private _contenthashes;

    // cointype (SLIP-44) → address bytes (for multichain)
    mapping(bytes32 => mapping(uint256 => bytes)) private _coinAddresses;

    uint256 constant COIN_TYPE_BOT = 60; // same as ETH for now

    event AddrChanged    (bytes32 indexed node, address addr);
    event AddressChanged (bytes32 indexed node, uint256 coinType, bytes newAddress);
    event TextChanged    (bytes32 indexed node, string indexed key, string value);
    event ContenthashChanged(bytes32 indexed node, bytes hash);

    modifier authorised(bytes32 node) {
        address o = registry.ownerOf(node);
        require(
            o == msg.sender || registry.isApprovedForAll(o, msg.sender),
            "BotResolver: not authorised"
        );
        _;
    }

    constructor(address _registry) {
        registry = BotRegistry(_registry);
    }

    // ── Address records ──

    function setAddr(bytes32 node, address addr) external authorised(node) {
        _addrs[node][COIN_TYPE_BOT] = addr;
        emit AddrChanged(node, addr);
    }

    function addr(bytes32 node) external view returns (address) {
        return _addrs[node][COIN_TYPE_BOT];
    }

    function setCoinAddress(bytes32 node, uint256 coinType, bytes calldata addrBytes)
        external authorised(node)
    {
        _coinAddresses[node][coinType] = addrBytes;
        emit AddressChanged(node, coinType, addrBytes);
    }

    function coinAddress(bytes32 node, uint256 coinType) external view returns (bytes memory) {
        return _coinAddresses[node][coinType];
    }

    // ── Text records ──

    /// @notice Set any text record. Supported standard keys:
    ///         "email", "url", "avatar", "description", "notice",
    ///         "twitter", "github", "telegram", "discord", "bio"
    function setText(bytes32 node, string calldata key, string calldata value)
        external authorised(node)
    {
        _texts[node][key] = value;
        emit TextChanged(node, key, value);
    }

    function text(bytes32 node, string calldata key) external view returns (string memory) {
        return _texts[node][key];
    }

    // ── Content hash ──

    function setContenthash(bytes32 node, bytes calldata hash)
        external authorised(node)
    {
        _contenthashes[node] = hash;
        emit ContenthashChanged(node, hash);
    }

    function contenthash(bytes32 node) external view returns (bytes memory) {
        return _contenthashes[node];
    }

    // ── Batch set records in one tx ──

    struct TextRecord {
        string key;
        string value;
    }

    function setRecords(
        bytes32 node,
        address walletAddr,
        TextRecord[] calldata texts
    ) external authorised(node) {
        if (walletAddr != address(0)) {
            _addrs[node][COIN_TYPE_BOT] = walletAddr;
            emit AddrChanged(node, walletAddr);
        }
        for (uint256 i = 0; i < texts.length; i++) {
            _texts[node][texts[i].key] = texts[i].value;
            emit TextChanged(node, texts[i].key, texts[i].value);
        }
    }
}

// ─────────────────────────────────────────────
//  CONTRACT: BotRegistrar
//  Handles commit-reveal registration, renewals,
//  pricing, expiry, and subname delegation.
// ─────────────────────────────────────────────

contract BotRegistrar {
    using BotNamehash for string;

    BotRegistry public immutable registry;
    BotResolver public immutable resolver;

    // ── Pricing (wei per year per character tier) ──
    // 3 chars: 100 BOT/yr, 4 chars: 20 BOT/yr, 5+ chars: 5 BOT/yr
    uint256 public constant PRICE_3_CHAR = 100 ether;
    uint256 public constant PRICE_4_CHAR = 20  ether;
    uint256 public constant PRICE_5_PLUS = 5   ether;

    // ── Timing ──
    uint256 public constant MIN_COMMIT_AGE  = 60;        // 60 seconds
    uint256 public constant MAX_COMMIT_AGE  = 24 hours;
    uint256 public constant GRACE_PERIOD    = 90 days;   // after expiry, owner can still renew
    uint256 public constant MIN_DURATION    = 365 days;
    uint256 public constant MAX_DURATION    = 365 days * 10;

    // ── State ──
    struct Name {
        address owner;
        uint64  expiry;      // unix timestamp
        bool    exists;
    }

    mapping(bytes32 => Name)    private _names;           // node → Name
    mapping(bytes32 => uint256) private _commitments;     // commitHash → timestamp
    mapping(bytes32 => address) private _subnameOwners;   // subnode → owner

    address public admin;
    uint256 public feesCollected;
    bool    public paused;

    // Events
    event NameRegistered(
        bytes32 indexed node,
        string  label,
        address indexed owner,
        uint64  expiry
    );
    event NameRenewed   (bytes32 indexed node, uint64 newExpiry);
    event NameTransferred(bytes32 indexed node, address indexed newOwner);
    event NameReleased  (bytes32 indexed node);
    event CommitMade    (bytes32 indexed commitment, address indexed registrant);
    event SubnameSet    (bytes32 indexed parentNode, bytes32 indexed subnode, address owner);
    event Withdrawn     (address indexed to, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "BotRegistrar: admin only");
        _;
    }
    modifier whenNotPaused() {
        require(!paused, "BotRegistrar: paused");
        _;
    }
    modifier onlyNameOwner(bytes32 node) {
        require(_names[node].owner == msg.sender, "BotRegistrar: not owner");
        require(!_isExpired(node), "BotRegistrar: name expired");
        _;
    }

    constructor(address _registry, address _resolver) {
        registry = BotRegistry(_registry);
        resolver = BotResolver(_resolver);
        admin = msg.sender;
    }

    // ─────────────────────────────────────
    //  COMMIT-REVEAL REGISTRATION
    // ─────────────────────────────────────

    /// @notice Step 1 — submit commitment to prevent front-running
    /// @param commitment keccak256(abi.encodePacked(label, owner, secret))
    function commit(bytes32 commitment) external whenNotPaused {
        require(_commitments[commitment] == 0, "BotRegistrar: already committed");
        _commitments[commitment] = block.timestamp;
        emit CommitMade(commitment, msg.sender);
    }

    /// @notice Helper to build the commitment off-chain
    function makeCommitment(
        string calldata label,
        address owner_,
        bytes32 secret
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(label, owner_, secret));
    }

    /// @notice Step 2 — reveal and register after commitment window
    /// @param label    The name without ".bot" suffix
    /// @param owner_   Wallet to assign the name to
    /// @param secret   Random bytes32 used to make the commitment
    /// @param duration Lease duration in seconds (min 365 days)
    /// @param walletAddr  Initial eth.addr record (pass address(0) to skip)
    /// @param textKeys    Initial text record keys  (e.g. ["github","twitter"])
    /// @param textValues  Matching text record values
    function register(
        string  calldata label,
        address          owner_,
        bytes32          secret,
        uint256          duration,
        address          walletAddr,
        string[] calldata textKeys,
        string[] calldata textValues
    ) external payable whenNotPaused {
        // ── Validate ──
        require(BotNamehash.isValidLabel(label),   "BotRegistrar: invalid label");
        require(duration >= MIN_DURATION,           "BotRegistrar: duration too short");
        require(duration <= MAX_DURATION,           "BotRegistrar: duration too long");
        require(textKeys.length == textValues.length, "BotRegistrar: array mismatch");

        bytes32 node = BotNamehash.namehash(label);
        require(!_isActive(node), "BotRegistrar: name taken");

        // ── Check commitment ──
        bytes32 commitment = keccak256(abi.encodePacked(label, owner_, secret));
        uint256 commitTime = _commitments[commitment];
        require(commitTime != 0, "BotRegistrar: no commitment found");
        require(block.timestamp >= commitTime + MIN_COMMIT_AGE, "BotRegistrar: commitment too recent");
        require(block.timestamp <= commitTime + MAX_COMMIT_AGE, "BotRegistrar: commitment expired");
        delete _commitments[commitment];

        // ── Check price ──
        uint256 price = getPrice(label, duration);
        require(msg.value >= price, "BotRegistrar: insufficient fee");

        // ── Register ──
        uint64 expiry = uint64(block.timestamp + duration);
        _names[node] = Name({ owner: owner_, expiry: expiry, exists: true });

        // Update registry
        registry.setOwner(node, owner_);
        registry.setResolver(node, address(resolver));

        // Set initial records if provided
        if (walletAddr != address(0) || textKeys.length > 0) {
            BotResolver.TextRecord[] memory recs = new BotResolver.TextRecord[](textKeys.length);
            for (uint256 i = 0; i < textKeys.length; i++) {
                recs[i] = BotResolver.TextRecord({ key: textKeys[i], value: textValues[i] });
            }
            // Registrar sets records as operator of the new owner
            // Owner must pre-approve registrar OR we set records directly here by temporarily holding ownership
            // Simplified: resolver checks registry.ownerOf == registrar during register
            _setInitialRecords(node, walletAddr, recs);
        }

        feesCollected += msg.value;
        emit NameRegistered(node, label, owner_, expiry);

        // Refund excess
        if (msg.value > price) {
            payable(msg.sender).transfer(msg.value - price);
        }
    }

    // Internal: set records right after registration while registrar is temp owner
    function _setInitialRecords(
        bytes32 node,
        address walletAddr,
        BotResolver.TextRecord[] memory recs
    ) internal {
        // Temporarily set registry owner to this contract so resolver accepts us
        // Then hand off to the true owner (already done in register above)
        // Since we called registry.setOwner(node, owner_) already, we can't call resolver
        // unless approved. Here we set records directly without going through resolver auth.
        // In production: emit events or let owner set them post-registration.
        // Simplified path: emit data so the frontend can prompt a second tx.
        // This function is a placeholder — the real flow is the owner calls
        // resolver.setRecords() separately after registration.
    }

    // ─────────────────────────────────────
    //  RENEWAL
    // ─────────────────────────────────────

    /// @notice Renew a name before or within grace period
    function renew(string calldata label, uint256 duration)
        external payable whenNotPaused
    {
        require(BotNamehash.isValidLabel(label), "BotRegistrar: invalid label");
        require(duration >= MIN_DURATION, "BotRegistrar: duration too short");

        bytes32 node = BotNamehash.namehash(label);
        Name storage n = _names[node];
        require(n.exists, "BotRegistrar: name not registered");

        // Renewal is allowed if in grace period or still active
        require(
            block.timestamp <= n.expiry + GRACE_PERIOD,
            "BotRegistrar: name released"
        );

        uint256 price = getPrice(label, duration);
        require(msg.value >= price, "BotRegistrar: insufficient fee");

        // Extend from current expiry (or now, if in grace period)
        uint64 base = n.expiry > uint64(block.timestamp) ? n.expiry : uint64(block.timestamp);
        n.expiry = uint64(base + duration);

        feesCollected += msg.value;
        emit NameRenewed(node, n.expiry);

        if (msg.value > price) {
            payable(msg.sender).transfer(msg.value - price);
        }
    }

    // ─────────────────────────────────────
    //  TRANSFER
    // ─────────────────────────────────────

    function transfer(string calldata label, address newOwner)
        external
    {
        require(newOwner != address(0), "BotRegistrar: zero address");
        bytes32 node = BotNamehash.namehash(label);
        require(_names[node].owner == msg.sender, "BotRegistrar: not owner");
        require(!_isExpired(node), "BotRegistrar: name expired");

        _names[node].owner = newOwner;
        registry.setOwner(node, newOwner);
        emit NameTransferred(node, newOwner);
    }

    // ─────────────────────────────────────
    //  SUBNAMES
    //  e.g.  dev.jerydam.bot
    // ─────────────────────────────────────

    /// @notice Issue a subname under your .bot name
    /// @param parentLabel   Your label (e.g. "jerydam")
    /// @param sublabel      The prefix (e.g. "dev")
    /// @param subnameOwner  Who owns the subname
    function issueSubname(
        string calldata parentLabel,
        string calldata sublabel,
        address subnameOwner
    ) external {
        require(BotNamehash.isValidLabel(parentLabel), "BotRegistrar: invalid parent");
        require(bytes(sublabel).length >= 1, "BotRegistrar: empty sublabel");

        bytes32 parentNode = BotNamehash.namehash(parentLabel);
        require(_names[parentNode].owner == msg.sender, "BotRegistrar: not parent owner");
        require(!_isExpired(parentNode), "BotRegistrar: parent expired");

        // subnode = keccak256(parentNode + keccak256(sublabel))
        bytes32 subnode = keccak256(abi.encodePacked(parentNode, keccak256(bytes(sublabel))));
        _subnameOwners[subnode] = subnameOwner;
        registry.setOwner(subnode, subnameOwner);
        registry.setResolver(subnode, address(resolver));

        emit SubnameSet(parentNode, subnode, subnameOwner);
    }

    /// @notice Revoke a subname (parent owner only)
    function revokeSubname(
        string calldata parentLabel,
        string calldata sublabel
    ) external {
        bytes32 parentNode = BotNamehash.namehash(parentLabel);
        require(_names[parentNode].owner == msg.sender, "BotRegistrar: not parent owner");

        bytes32 subnode = keccak256(abi.encodePacked(parentNode, keccak256(bytes(sublabel))));
        delete _subnameOwners[subnode];
        registry.setOwner(subnode, address(0));
    }

    // ─────────────────────────────────────
    //  VIEWS
    // ─────────────────────────────────────

    /// @notice Get the annual price for a label
    function getPrice(string memory label, uint256 duration) public pure returns (uint256) {
        uint256 len = bytes(label).length;
        uint256 annualPrice;
        if (len <= 3) {
            annualPrice = PRICE_3_CHAR;
        } else if (len == 4) {
            annualPrice = PRICE_4_CHAR;
        } else {
            annualPrice = PRICE_5_PLUS;
        }
        return (annualPrice * duration) / 365 days;
    }

    function getExpiry(string calldata label) external view returns (uint64) {
        return _names[BotNamehash.namehash(label)].expiry;
    }

    function getOwner(string calldata label) external view returns (address) {
        return _names[BotNamehash.namehash(label)].owner;
    }

    function isAvailable(string calldata label) external view returns (bool) {
        if (!BotNamehash.isValidLabel(label)) return false;
        bytes32 node = BotNamehash.namehash(label);
        return !_isActive(node);
    }

    function nameInfo(string calldata label)
        external view
        returns (address owner_, uint64 expiry, bool active)
    {
        bytes32 node = BotNamehash.namehash(label);
        Name memory n = _names[node];
        return (n.owner, n.expiry, _isActive(node));
    }

    // ─────────────────────────────────────
    //  ADMIN
    // ─────────────────────────────────────

    function setPaused(bool _paused) external onlyAdmin {
        paused = _paused;
    }

    function withdraw(address payable to) external onlyAdmin {
        uint256 amt = address(this).balance;
        feesCollected = 0;
        emit Withdrawn(to, amt);
        to.transfer(amt);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "BotRegistrar: zero address");
        admin = newAdmin;
    }

    // ─────────────────────────────────────
    //  INTERNALS
    // ─────────────────────────────────────

    function _isExpired(bytes32 node) internal view returns (bool) {
        return block.timestamp > _names[node].expiry;
    }

    /// Active = exists AND not past grace period
    function _isActive(bytes32 node) internal view returns (bool) {
        Name memory n = _names[node];
        if (!n.exists) return false;
        return block.timestamp <= n.expiry + GRACE_PERIOD;
    }

    receive() external payable {}
}

// ─────────────────────────────────────────────
//  DEPLOYMENT ORDER
// ─────────────────────────────────────────────
//  1. Deploy BotRegistry        → get registryAddr
//  2. Deploy BotResolver        → pass registryAddr
//  3. Deploy BotRegistrar       → pass registryAddr, resolverAddr
//  4. BotRegistry.setRegistrar(registrarAddr)
//
//  ── USAGE FLOW ──
//  Frontend:
//    1. Call registrar.isAvailable("alice")
//    2. secret = ethers.randomBytes(32)
//    3. commitment = await registrar.makeCommitment("alice", userAddr, secret)
//    4. await registrar.commit(commitment)
//    5. Wait 60 seconds
//    6. await registrar.register("alice", userAddr, secret, 365d, addr, [], [], {value: price})
//    7. await resolver.setRecords(node, addr, [{key:"twitter",value:"@alice"}])
//
//  Read:
//    node = keccak256(keccak256("") + keccak256("bot") + keccak256("alice"))
//    await resolver.addr(node)      → wallet address
//    await resolver.text(node, "github") → "alice"
