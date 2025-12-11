pragma solidity ^0.6.10;

contract DataRegistry {
    // 存储数据元信息
    struct DataRecord {
        address owner;      // 数据所有者
        uint256 timestamp;  // 注册时间戳
        uint256 cost;       // Token价格
        uint256 dataId;     // 本地DB ID
    }

    // bytes32 (数据哈希) => DataRecord
    mapping(bytes32 => DataRecord) public dataHashes;
    
    // 数据哈希 => (用户地址 => 是否拥有权限)
    mapping(bytes32 => mapping(address => bool)) public accessMapping;

    event DataRegistered(bytes32 indexed dataHash, address indexed owner, uint256 price, uint256 dataId);
    event AccessGranted(bytes32 indexed dataHash, address indexed user);
    event AccessRevoked(bytes32 indexed dataHash, address indexed user);

    // 存证确权：接收后端计算的哈希、价格和本地ID，记录数据所有者 (msg.sender)
    function registerData(bytes32 dataHash, uint256 price, uint256 dataId) public {
        require(dataHashes[dataHash].owner == address(0), "Data already registered");

        DataRecord memory newRecord = DataRecord({
            owner: msg.sender,
            timestamp: now,
            cost: price,
            dataId: dataId
        });

        dataHashes[dataHash] = newRecord;
        
        // 数据所有者默认拥有权限
        accessMapping[dataHash][msg.sender] = true;

        emit DataRegistered(dataHash, msg.sender, price, dataId);
    }

    // 赋予权限：由数据所有者调用
    function grantAccess(bytes32 dataHash, address userAddress) public {
        require(dataHashes[dataHash].owner == msg.sender, "Only data owner can grant access");
        accessMapping[dataHash][userAddress] = true;
        emit AccessGranted(dataHash, userAddress);
    }

    // 收回权限：由数据所有者调用
    function revokeAccess(bytes32 dataHash, address userAddress) public {
        require(dataHashes[dataHash].owner == msg.sender, "Only data owner can revoke access");
        accessMapping[dataHash][userAddress] = false;
        emit AccessRevoked(dataHash, userAddress);
    }

    // 溯源查询：查询并返回数据所有者地址
    function getDataOwner(bytes32 dataHash) public view returns (address) {
        return dataHashes[dataHash].owner;
    }

    // 权限验证：查询用户是否对该数据有访问权限
    function hasAccess(bytes32 dataHash, address user) public view returns (bool) {
        return accessMapping[dataHash][user];
    }
    // 购买与授权：原子操作，支付成功即获得权限
    function buyAndGrantAccess(bytes32 dataHash, address tokenContractAddress) public {
        DataRecord memory record = dataHashes[dataHash];
        require(record.owner != address(0), "Data not registered");
        require(record.owner != msg.sender, "Owner already has access");
        // 简单防止重复购买（可选，视业务逻辑而定，这里不做强制限制，因为也许是续费? 但根据 describe 'grant access' 这是一个布尔值）
        // require(!accessMapping[dataHash][msg.sender], "Access already granted");

        // 实例化 Token 合约接口
        ISimpleToken token = ISimpleToken(tokenContractAddress);

        // 调用 transferFrom 进行扣款：从买家 (msg.sender) 转给 数据所有者 (record.owner)
        // 注意：买家必须先在 SimpleToken 合约中 approve DataRegistry 合约地址
        token.transferFrom(msg.sender, record.owner, record.cost);

        // 支付成功后，自动赋予权限
        accessMapping[dataHash][msg.sender] = true;
        emit AccessGranted(dataHash, msg.sender);
    }
}

interface ISimpleToken {
    function transferFrom(address sender, address recipient, uint256 amount) external;
}
