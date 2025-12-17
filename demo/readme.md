### 目前在192.168.1.103上安装了一个简单环境

```
cd fisco/
bash nodes/127.0.0.1/start_all.sh

source .venv/bin/activate
cd python-sdk/
python console3.py getBlockNumber


python ./console3.py sendtx HelloWorld 0x6546c3571f17858ea45575e7c6457dad03e53dbb set "Hello, wyh"


python console3.py call HelloWorld 0x6546c3571f17858ea45575e7c6457dad03e53dbb get


```

Client 执行合约部署和调用：

### 命令段调用

```
 python console3.py deploy SimpleToken
 
 python console3.py sendtx SimpleToken last faucet '1000'

python console3.py call SimpleToken last balances 0xef356b157f59bbc258c885a36cf180798e87c86b

python console3.py call SimpleToken last balances 0x2De5C210370Daef452Eb610AF76C3A293AE1661f 
```

### 代码调用

```
#注意编译器 solc 的版本，目前好像合约都是写 0.6.10
npm install solc@0.6.10 fs-extra yargs@16.2.0

手动编译合约（绕过 SDK 自带 solcjs）
npx solcjs --bin --abi ./contracts/HelloWorld6.sol -o contracts/
npx solcjs --bin --abi ./contracts/SimpleInfo.sol -o contracts/

重命名成 demo 脚本期待的文件名
cd contracts
cp __contracts_HelloWorld6_sol_HelloWorld6.abi HelloWorld6.abi
cp __contracts_HelloWorld6_sol_HelloWorld6.bin HelloWorld6.bin
cp __contracts_SimpleInfo_sol_SimpleInfo.abi SimpleInfo.abi
cp __contracts_SimpleInfo_sol_SimpleInfo.bin SimpleInfo.bin

关闭 SDK 内部编译调用
编辑 demo/demo_transaction3.py
把Compiler.compile_file("./contracts/HelloWorld6.sol")注释掉：


在执行 python demo/demo_transaction3.py
```

### 跨链操作的测试

```
## 基于两个合约
python console3.py sendtx SimpleToken last faucet '1000'


python console3.py call SimpleToken last balances 0xef356b157f59bbc258c885a36cf180798e87c86b

python console3.py call SimpleToken last balances 0x2De5C210370Daef452Eb610AF76C3A293AE1661f 

//授权 data合约 1000 额度
python console3.py sendtx SimpleToken last  approve 0x247d2809cd54267a00af94bb0528317845e5a4fe 1000

//修改 config，切换一个用户，注册数据
python console3.py sendtx DataRegistry last registerData '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925' 20 1001

//查询数据权限
python console3.py call DataRegistry last getDataOwner '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925'

//切换回原来用户，然后执行
python console3.py sendtx DataRegistry last buyAndGrantAccess '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925' '0x412d17a4b6a79953bc891106b420bcd4493cd1cd'

//查询用户余额，发生变化
python console3.py call SimpleToken last balances 0xef356b157f59bbc258c885a36cf180798e87c86b

python console3.py call SimpleToken last balances 0x2De5C210370Daef452Eb610AF76C3A293AE1661f

//查询用户权限
python console3.py call DataRegistry last hasAccess '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925' '0xef356b157f59bbc258c885a36cf180798e87c86b'

python console3.py call DataRegistry last hasAccess '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925' '0x2De5C210370Daef452Eb610AF76C3A293AE1661f'
```

### 三个端点的demo

我实现了三个端点利用区块链做数据可信交易的 demo ，一个代表用户端，一个代表平台，一个代表（iot）设备端：

设备端：接受参数，进行不同的动作 （主要参考python-sdk/demo/demo_get_pubkey.py）
1、直接发送给区块链注册数据
2、启动监听 mq ，如果收到一个平台的数据购买请求，则从数据库（可先用模拟数据）打包加密数据，并send 给 mq

平台：是一个 fastapi 的 server 服务
1、订阅区块链的 event，收到数据注册请求后，插入数据库（data 表）
2、提供/show_data 接口，展示所有已经注册的数据
3、提供/req_task 接口，用户端调用后，发送数据购买请求给 mq，让设备端处理
4、启动和 mq 的对接，如果收到设备传回的 mq 的消息，则保存到本地数据（payed_data）
5、提供/download_data,

用户端：接受参数，进行不同的动作 （区块链的操作参考python-sdk/demo/demo_data_market.py；合约方法参考python-sdk/contracts/DataRegistry.sol）
1、接水龙头，获取一定的 token，并调用approve 授权额度
2、调用平台/show_data 接口，展示所有已经注册的数据
3、直接调用区块链DataRegistry合约，buyAndGrantAccess
4、提取自己的公钥信息，并向平台发生请求/req_task，请求数据，得到返回 taskid，表示处理中，打印出 taskid
5、调用/download_data接口，提交taskid，下载文件，并解析打印内容

```

# 启动平台 (注意这里的是注册数据合约的合约地址)
python demo/platform_server.py --registry-address 0x247d2809cd54267a00af94bb0528317845e5a4fe

# 设备注册数据
python demo/device_endpoint.py  register --data-id '10036' --payload 'nih' --price 24

# 设备启动监听mq
python demo/device_endpoint.py  listen

# （记得切换用户）用户领水，授权
python demo/user_endpoint.py token_setup

# 查看数据
python demo/user_endpoint.py show_data

#链上购买数据
python demo/user_endpoint.py buy_onchain  --data-hash 'data_hash'

#向平台请求数据
python demo/user_endpoint.py req_task --data-id 10038

#向平台获取数据
python demo/user_endpoint.py download_data --task-id task-696e925a
```
