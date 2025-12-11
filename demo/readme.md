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
