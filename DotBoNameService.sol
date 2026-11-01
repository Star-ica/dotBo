// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DotBoNameService — single contract .bot name registry
 * Handles: registration, renewal, transfer, resolver records,
 *          commit-reveal anti-frontrun, subnames, pricing
 *
 * Fixes applied:
 *   - register() locals packed into RegisterParams struct (stack-too-deep)
 *   - All .transfer() replaced with .call{value:}("") (deprecated transfer)
 */
contract DotBoNameService {

    // ─────────────────────────────────────────
    //  STRUCTS
    // ─────────────────────────────────────────

    struct Name {
        address owner;
        uint64  expiry;
    }

    struct TextRecord {
        string key;
        string value;
    }

    /// @dev Packs register() intermediates to stay under 16-slot EVM stack limit
    struct RegisterParams {
        bytes32 node;
        bytes32 commitment;
        uint256 commitTime;
        uint256 price;
        uint64  expiry;
    }

    // ─────────────────────────────────────────
    //  STORAGE
    // ─────────────────────────────────────────

    mapping(bytes32 => Name)                        private _names;
    mapping(address => mapping(address => bool))    private _operators;
    mapping(bytes32 => uint256)                     private _commitments;
    mapping(bytes32 => address)                     private _addrs;
    mapping(bytes32 => mapping(string => string))   private _texts;
    mapping(bytes32 => bytes)                       private _contentHashes;
    mapping(bytes32 => bytes32)                     private _subnameParent;

    address public owner;
    bool    public paused;

    // ─────────────────────────────────────────
    //  CONSTANTS
    // ─────────────────────────────────────────

    uint256 public constant PRICE_3_CHAR  = 100 ether;
    uint256 public constant PRICE_4_CHAR  = 20  ether;
    uint256 public constant PRICE_5_PLUS  = 5   ether;

    uint256 public constant MIN_COMMIT_AGE = 60;
    uint256 public constant MAX_COMMIT_AGE = 24 hours;
    uint256 public constant GRACE_PERIOD   = 90 days;
    uint256 public constant MIN_DURATION   = 365 days;
    uint256 public constant MAX_DURATION   = 365 days * 10;

    // ─────────────────────────────────────────
    //  EVENTS
    // ─────────────────────────────────────────

    event NameRegistered    (bytes32 indexed node, string label, address indexed nameOwner, uint64 expiry);
    event NameRenewed       (bytes32 indexed node, string label, uint64 newExpiry);
    event NameTransferred   (bytes32 indexed node, address indexed newOwner);
    event SubnameIssued     (bytes32 indexed parentNode, bytes32 indexed subnode, string sublabel, address subnameOwner);
    event SubnameRevoked    (bytes32 indexed parentNode, bytes32 indexed subnode);
    event CommitMade        (bytes32 indexed commitment, address indexed registrant);
    event AddrChanged       (bytes32 indexed node, address addr);
    event TextChanged       (bytes32 indexed node, string indexed key, string value);
    event ContentHashChanged(bytes32 indexed node, bytes hash);
    event ApprovalForAll    (address indexed owner_, address indexed operator, bool approved);
    event Withdrawn         (address indexed to, uint256 amount);

    // ─────────────────────────────────────────
    //  MODIFIERS
    // ─────────────────────────────────────────

    modifier onlyContractOwner() {
        require(msg.sender == owner, "DotBo: not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "DotBo: paused");
        _;
    }

    modifier authorisedName(bytes32 node) {
        require(_isAuthorised(node, msg.sender), "DotBo: not authorised");
        _;
    }

    // ─────────────────────────────────────────
    //  CONSTRUCTOR
    // ─────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ─────────────────────────────────────────
    //  INTERNAL ETH SEND — replaces deprecated .transfer()
    // ─────────────────────────────────────────

    function _sendEth(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "DotBo: ETH send failed");
    }

    // ─────────────────────────────────────────
    //  NAMEHASH
    // ─────────────────────────────────────────

    function namehash(string memory label) public pure returns (bytes32) {
        bytes32 botNode = keccak256(
            abi.encodePacked(bytes32(0), keccak256(bytes("bot")))
        );
        return keccak256(abi.encodePacked(botNode, keccak256(bytes(label))));
    }

    function subnamehash(bytes32 parentNode, string memory sublabel) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(parentNode, keccak256(bytes(sublabel))));
    }

    // ─────────────────────────────────────────
    //  LABEL VALIDATION
    // ─────────────────────────────────────────

    function isValidLabel(string memory label) public pure returns (bool) {
        bytes memory b = bytes(label);
        uint256 len = b.length;
        if (len < 3 || len > 64) return false;
        if (b[0] == 0x2D || b[len - 1] == 0x2D) return false;
        for (uint256 i = 0; i < len; i++) {
            bytes1 c = b[i];
            bool ok = (c >= 0x61 && c <= 0x7A) ||
                      (c >= 0x30 && c <= 0x39) ||
                      (c == 0x2D);
            if (!ok) return false;
        }
        return true;
    }

    // ─────────────────────────────────────────
    //  PRICING
    // ─────────────────────────────────────────

    function getPrice(string memory label, uint256 duration) public pure returns (uint256) {
        uint256 len    = bytes(label).length;
        uint256 annual = len <= 3 ? PRICE_3_CHAR
                       : len == 4 ? PRICE_4_CHAR
                       : PRICE_5_PLUS;
        return (annual * duration) / 365 days;
    }

    // ─────────────────────────────────────────
    //  COMMIT-REVEAL
    // ─────────────────────────────────────────

    function makeCommitment(
        string  calldata label,
        address          registrant,
        bytes32          secret
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(label, registrant, secret));
    }

    function commit(bytes32 commitment) external whenNotPaused {
        require(_commitments[commitment] == 0, "DotBo: already committed");
        _commitments[commitment] = block.timestamp;
        emit CommitMade(commitment, msg.sender);
    }

    // ─────────────────────────────────────────
    //  REGISTER
    // ─────────────────────────────────────────

    function register(
        string   calldata label,
        address           registrant,
        bytes32           secret,
        uint256           duration,
        address           walletAddr,
        string[] calldata textKeys,
        string[] calldata textValues
    ) external payable whenNotPaused {
        require(isValidLabel(label),                  "DotBo: invalid label");
        require(duration >= MIN_DURATION,             "DotBo: too short");
        require(duration <= MAX_DURATION,             "DotBo: too long");
        require(textKeys.length == textValues.length, "DotBo: array mismatch");

        RegisterParams memory p;
        p.node       = namehash(label);
        p.commitment = keccak256(abi.encodePacked(label, registrant, secret));
        p.commitTime = _commitments[p.commitment];

        require(_isAvailableNode(p.node),                          "DotBo: name taken");
        require(p.commitTime != 0,                                 "DotBo: no commitment");
        require(block.timestamp >= p.commitTime + MIN_COMMIT_AGE,  "DotBo: too soon");
        require(block.timestamp <= p.commitTime + MAX_COMMIT_AGE,  "DotBo: commitment expired");

        delete _commitments[p.commitment];

        p.price  = getPrice(label, duration);
        require(msg.value >= p.price, "DotBo: insufficient fee");

        p.expiry = uint64(block.timestamp + duration);
        _names[p.node] = Name({owner: registrant, expiry: p.expiry});

        _setInitialRecords(p.node, walletAddr, textKeys, textValues);

        emit NameRegistered(p.node, label, registrant, p.expiry);

        if (msg.value > p.price) {
            _sendEth(msg.sender, msg.value - p.price);
        }
    }

    function _setInitialRecords(
        bytes32           node,
        address           walletAddr,
        string[] calldata textKeys,
        string[] calldata textValues
    ) internal {
        if (walletAddr != address(0)) {
            _addrs[node] = walletAddr;
            emit AddrChanged(node, walletAddr);
        }
        for (uint256 i = 0; i < textKeys.length; i++) {
            _texts[node][textKeys[i]] = textValues[i];
            emit TextChanged(node, textKeys[i], textValues[i]);
        }
    }

    // ─────────────────────────────────────────
    //  RENEW
    // ─────────────────────────────────────────

    function renew(string calldata label, uint256 duration)
        external payable whenNotPaused
    {
        require(duration >= MIN_DURATION, "DotBo: too short");

        bytes32 node = namehash(label);
        Name storage n = _names[node];

        require(n.owner != address(0),                               "DotBo: not registered");
        require(block.timestamp <= uint256(n.expiry) + GRACE_PERIOD, "DotBo: name released");

        uint256 price = getPrice(label, duration);
        require(msg.value >= price, "DotBo: insufficient fee");

        uint64 base = n.expiry > uint64(block.timestamp)
            ? n.expiry
            : uint64(block.timestamp);
        n.expiry = uint64(uint256(base) + duration);

        emit NameRenewed(node, label, n.expiry);

        if (msg.value > price) {
            _sendEth(msg.sender, msg.value - price);
        }
    }

    // ─────────────────────────────────────────
    //  TRANSFER
    // ─────────────────────────────────────────

    function transfer(string calldata label, address newOwner_) external {
        require(newOwner_ != address(0), "DotBo: zero address");
        bytes32 node = namehash(label);
        require(_names[node].owner == msg.sender, "DotBo: not owner");
        require(!_isExpired(node),                "DotBo: expired");
        _names[node].owner = newOwner_;
        emit NameTransferred(node, newOwner_);
    }

    // ─────────────────────────────────────────
    //  SUBNAMES
    // ─────────────────────────────────────────

    function issueSubname(
        string calldata parentLabel,
        string calldata sublabel,
        address         subnameOwner
    ) external {
        bytes32 parentNode = namehash(parentLabel);
        require(_names[parentNode].owner == msg.sender, "DotBo: not parent owner");
        require(!_isExpired(parentNode),                "DotBo: parent expired");
        require(bytes(sublabel).length > 0,             "DotBo: empty sublabel");

        bytes32 subnode = subnamehash(parentNode, sublabel);
        _names[subnode]         = Name({owner: subnameOwner, expiry: _names[parentNode].expiry});
        _subnameParent[subnode] = parentNode;

        emit SubnameIssued(parentNode, subnode, sublabel, subnameOwner);
    }

    function revokeSubname(
        string calldata parentLabel,
        string calldata sublabel
    ) external {
        bytes32 parentNode = namehash(parentLabel);
        require(_names[parentNode].owner == msg.sender, "DotBo: not parent owner");
        bytes32 subnode = subnamehash(parentNode, sublabel);
        delete _names[subnode];
        emit SubnameRevoked(parentNode, subnode);
    }

    // ─────────────────────────────────────────
    //  RESOLVER — ADDRESS
    // ─────────────────────────────────────────

    function setAddr(bytes32 node, address addr_) external authorisedName(node) {
        _addrs[node] = addr_;
        emit AddrChanged(node, addr_);
    }

    function addr(bytes32 node) external view returns (address) {
        return _addrs[node];
    }

    // ─────────────────────────────────────────
    //  RESOLVER — TEXT
    // ─────────────────────────────────────────

    function setText(bytes32 node, string calldata key, string calldata value)
        external authorisedName(node)
    {
        _texts[node][key] = value;
        emit TextChanged(node, key, value);
    }

    function text(bytes32 node, string calldata key) external view returns (string memory) {
        return _texts[node][key];
    }

    // ─────────────────────────────────────────
    //  RESOLVER — CONTENT HASH
    // ─────────────────────────────────────────

    function setContentHash(bytes32 node, bytes calldata hash) external authorisedName(node) {
        _contentHashes[node] = hash;
        emit ContentHashChanged(node, hash);
    }

    function contentHash(bytes32 node) external view returns (bytes memory) {
        return _contentHashes[node];
    }

    // ─────────────────────────────────────────
    //  RESOLVER — BATCH
    // ─────────────────────────────────────────

    function setRecords(
        bytes32              node,
        address              walletAddr,
        TextRecord[] calldata records
    ) external authorisedName(node) {
        if (walletAddr != address(0)) {
            _addrs[node] = walletAddr;
            emit AddrChanged(node, walletAddr);
        }
        for (uint256 i = 0; i < records.length; i++) {
            _texts[node][records[i].key] = records[i].value;
            emit TextChanged(node, records[i].key, records[i].value);
        }
    }

    // ─────────────────────────────────────────
    //  OPERATOR APPROVAL
    // ─────────────────────────────────────────

    function setApprovalForAll(address operator, bool approved) external {
        _operators[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner_, address operator) external view returns (bool) {
        return _operators[owner_][operator];
    }

    // ─────────────────────────────────────────
    //  VIEWS
    // ─────────────────────────────────────────

    function isAvailable(string calldata label) external view returns (bool) {
        if (!isValidLabel(label)) return false;
        return _isAvailableNode(namehash(label));
    }

    function nameInfo(string calldata label)
        external view
        returns (address nameOwner, uint64 expiry, bool active)
    {
        bytes32 node = namehash(label);
        Name memory n = _names[node];
        return (n.owner, n.expiry, _isActive(node));
    }

    function nameInfoByNode(bytes32 node)
        external view
        returns (address nameOwner, uint64 expiry, bool active)
    {
        Name memory n = _names[node];
        return (n.owner, n.expiry, _isActive(node));
    }

    function getExpiry(string calldata label) external view returns (uint64) {
        return _names[namehash(label)].expiry;
    }

    function getOwner(string calldata label) external view returns (address) {
        return _names[namehash(label)].owner;
    }

    // ─────────────────────────────────────────
    //  ADMIN
    // ─────────────────────────────────────────

    function setPaused(bool _paused) external onlyContractOwner {
        paused = _paused;
    }

    function withdraw(address payable to) external onlyContractOwner {
        uint256 bal = address(this).balance;
        emit Withdrawn(to, bal);
        _sendEth(to, bal);
    }

    function transferOwnership(address newOwner_) external onlyContractOwner {
        require(newOwner_ != address(0), "DotBo: zero address");
        owner = newOwner_;
    }

    // ─────────────────────────────────────────
    //  INTERNALS
    // ─────────────────────────────────────────

    function _isExpired(bytes32 node) internal view returns (bool) {
        return block.timestamp > uint256(_names[node].expiry);
    }

    function _isActive(bytes32 node) internal view returns (bool) {
        Name memory n = _names[node];
        if (n.owner == address(0)) return false;
        return block.timestamp <= uint256(n.expiry) + GRACE_PERIOD;
    }

    function _isAvailableNode(bytes32 node) internal view returns (bool) {
        Name memory n = _names[node];
        if (n.owner == address(0)) return true;
        return block.timestamp > uint256(n.expiry) + GRACE_PERIOD;
    }

    function _isAuthorised(bytes32 node, address caller) internal view returns (bool) {
        address nameOwner = _names[node].owner;
        return nameOwner == caller || _operators[nameOwner][caller];
    }

    receive() external payable {}
}
