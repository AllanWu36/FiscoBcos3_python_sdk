pragma solidity ^0.6.10;

contract SimpleToken {
    // 存储用户 Token 余额
    mapping(address => uint256) public balances;
    // 合约部署者地址
    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() public {
        owner = msg.sender;
    }

    // 支付功能：模拟买家向卖家（数据所有者）转账 Token
    function transfer(address recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[recipient] += amount;
        emit Transfer(msg.sender, recipient, amount);
    }

    // 水龙头：供用户在 Demo 中初始化或领取 Token
    function faucet(uint256 amount) public {
        balances[msg.sender] += amount;
        emit Transfer(address(0), msg.sender, amount);
    }
    // 授权额度：owner => spender => amount
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    // 授权花费：允许指定地址（spender）花费调用者账户一定数量的 Token
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // 代理转账：DataRegistry 调用此函数将买家的 Token 转给卖家
    function transferFrom(address sender, address recipient, uint256 amount) public returns (bool) {
        require(allowance[sender][msg.sender] >= amount, "Allowance exceeded");
        require(balances[sender] >= amount, "Insufficient balance");

        allowance[sender][msg.sender] -= amount;
        balances[sender] -= amount;
        balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
        return true;
    }
}
