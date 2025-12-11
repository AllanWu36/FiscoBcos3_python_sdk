#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
  FISCO BCOS/Python-SDK Demo: Data Market
  Demonstrates usage of SimpleToken and DataRegistry contracts.
'''
import sys
import os
import time
import secrets
import ctypes

sys.path.append("./")
from eth_utils import to_checksum_address

from client.stattool import StatTool
from bcos3sdk.bcos3client import Bcos3Client
from client.contractnote import ContractNote
from client.datatype_parser import DatatypeParser
from client.common.compiler import Compiler
from client.bcoserror import BcosException, BcosError
from client_config import client_config
#!/usr/bin/env python
# - * - coding: utf - 8 -
import os
from eth_utils.crypto import set_crypto_type, CRYPTO_TYPE_GM, CRYPTO_TYPE_ECDSA


class client_config_A:
    """
    类成员变量，便于用.调用和区分命名空间
    """
    # 整个客户端的全局配置，影响console相关的账户目录、日志目录、合约目录等
    # crypto_type : 大小写不敏感："GM" for 国密, "ECDSA" 或其他是椭圆曲线默认实现。
    crypto_type = "ECDSA"
    # crypto_type = "GM"
    ssl_type = crypto_type  # 和节点tls通信方式，如设为gm，则使用国密证书认证和加密
    # ssl_type = "GM"
    set_crypto_type(crypto_type)  # 使其全局生效
    # 默认日志输出目录，该目录不会自动建，必须先建立
    logdir = "bin/logs"
    # 合约相关路径
    contract_dir = "./contracts"
    contract_info_file = "bin/contract.ini"  # 保存已部署合约信息的文件
    # 账号文件相关路径
    account_keyfile_path = "bin/accounts"  # 保存keystore文件的路径，在此路径下,keystore文件以 [name].keystore命名
    # account_keyfile = "allanwu36.keystore"
    # account_password = "7758258w77"
    # account_keyfile = "pemtest.pem"
    # account_password = "123456"  # 实际使用时建议改为复杂密码
    # gm_account_keyfile = "gm_account.json"  # 国密账号的存储文件，可以加密存储,如果留空则不加载
    # gm_account_password = "123456"  # 如果不设密码，置为None或""则不加密
    
    # ---------编译器 compiler related--------------
    # path of solc compiler
    solc_path = "bin/solc/v0.6.11/solc"
    # solc_path = "bin/solc/solc6.exe"
    solcjs_path = "./solcjs"
    gm_solc_path = "./bin/solc/v0.6.11/solc-gm"
    # ---------console mode, support user input--------------
    background = True

    # ------------------FISCO BCOS3.0 Begin----------------------------------------
    # FISCO BCOS3.0的配置段，如连接FISCO BCOS2.0版本，无需关心此段
    # FISCO BCOS3.0 c底层sdk的配置，都在bcos3_config_file里，无需配置在此文件
    bcos3_lib_path = "./bcos3sdklib"
    bcos3_config_file = "./bcos3sdklib/bcos3_sdk_config.ini"
    bcos3_group = "group0"
    bcos3_check_node_version = True #是否在初始化后验证一次node版本
    bcos3_when_version_mismatch = "WARN" # WARN 或 "ERROR" ,如果版本不匹配，WARN只是打个警告，ERROR就抛异常了，建议WARN
    bcos3_major_version = 3
    bcos3_max_miner_version = 6 #最大子版本号验证
    # -------------------FISCO BCOS3.0 End-----------------------------------------
    
    # --------------------------------------
    # FISCO BCOS2.0的配置段，如连接FISCO BCOS3.0版本，无需关心此段
    # keyword used to represent the RPC Protocol
    PROTOCOL_RPC = "rpc"
    # keyword used to represent the Channel Protocol
    PROTOCOL_CHANNEL = "channel"
    fiscoChainId = 1  # 链ID，和要通信的节点*必须*一致
    groupid = 1  # 群组ID，和要通信的节点*必须*一致，如和其他群组通信，修改这一项，或者设置bcosclient.py里对应的成员变量
    client_protocol = "channel"  # or PROTOCOL_CHANNEL to use channel prototol
    # client_protocol = PROTOCOL_CHANNEL
    remote_rpcurl = "http://127.0.0.1:8545"  # 采用rpc通信时，节点的rpc端口,和要通信的节点*必须*一致,如采用channel协议通信，这里可以留空
    channel_host = "127.0.0.1"  # 采用channel通信时，节点的channel ip地址,如采用rpc协议通信，这里可以留空
    channel_port = 20200  # 节点的channel 端口,如采用rpc协议通信，这里可以留空
    channel_ca = "bin/ca.crt"  # 采用channel协议时，需要设置链证书,如采用rpc协议通信，这里可以留空
    channel_node_cert = "bin/sdk.crt"  # 采用channel协议时，需要设置sdk证书,如采用rpc协议通信，这里可以留空
    channel_node_key = "bin/sdk.key"  # 采用channel协议时，需要设置sdk私钥,如采用rpc协议通信，这里可以留空
    channel_en_crt = "bin/gmensdk.crt"  # 仅国密双证书使用，加密证书
    channel_en_key = "bin/gmensdk.key"  # 仅国密双证书使用，加密key




def demo_data_market():
    try:
        stat = StatTool.begin()
        client = Bcos3Client()
        print(client.getinfo())
        
        # Get Sender Address
        # Fix for: type object 'client_config' has no attribute 'account_key'
        # 从底层 C SDK 获取当前账户的公钥对应的地址指针
        address_p = client.bcossdk.bcos_sdk_get_keypair_address(client.keypair)
        # 将 C 字符串指针转换为 Python 字符串（UTF-8 解码）
        sender_address = ctypes.string_at(address_p).decode("utf-8")
        # 释放底层 C SDK 分配的内存，防止内存泄漏
        client.bcossdk.bcos_sdk_c_free(address_p)
        # 将地址转换为 Checksum 地址格式 (EIP-55)，以兼容 Web3.py 的校验要求
        sender_address = to_checksum_address(sender_address)
        print("Sender Address:", sender_address)

        # 1. Compile Contracts (Skipped as per request)
        # print("\n>>Compiling Contracts:------------------------------------------------")
        # if os.path.isfile(client_config.solc_path) or os.path.isfile(client_config.solcjs_path):
        #     Compiler.compile_file("contracts/SimpleToken.sol")
        #     Compiler.compile_file("contracts/DataRegistry.sol")
        #     print("Compilation finished.")

        # =========================================================================
        # 2. Deploy and Test SimpleToken
        # =========================================================================
        print("\n>>Deploy/Load SimpleToken:------------------------------------------------")
        abi_file_token = "contracts/SimpleToken.abi"
        parser_token = DatatypeParser()
        parser_token.load_abi_file(abi_file_token)
        
        # Try to load existing address
        token_address = ContractNote.get_last("demo", "SimpleToken")
        
        if token_address:
            print(f"Found SimpleToken at {token_address}, skipping deployment.")
        else:
            print("Deploying SimpleToken...")
            bin_file_token = "contracts/SimpleToken.bin"
            with open(bin_file_token, 'r') as f:
                contract_bin_token = f.read()
            result_token = client.deploy(contract_bin_token)
            print("SimpleToken deployed at:", result_token["contractAddress"])
            token_address = result_token["contractAddress"]
            ContractNote.save_address_to_contract_note("demo", "SimpleToken", token_address)

        print("\n>>Test SimpleToken Functions:----------------------------------------")
        # 2.1 Call faucet
        print("-> Calling faucet(1000)...")
        receipt = client.sendRawTransaction(token_address, parser_token.contract_abi, "faucet", [1000])
        if receipt['status'] == 0:
            print("Faucet success. TxHash:", receipt['transactionHash'])
        else:
            print("Faucet failed:", receipt)
            
        # 2.2 Check balance
        res = client.call(token_address, parser_token.contract_abi, "balances", [sender_address])
        print("Current Balance:", res)

        # 2.3 Transfer
        recipient = to_checksum_address("0x7029c502b4F824d19Bd7921E9cb74Ef92392FB1c")
        print(f"-> Transferring 100 to {recipient}...")
        receipt = client.sendRawTransaction(token_address, parser_token.contract_abi, "transfer", [recipient, 100])
        if receipt['status'] == 0:
             print("Transfer success. TxHash:", receipt['transactionHash'])
        else:
             print("Transfer failed:", receipt)

        # Check balance again
        res = client.call(token_address, parser_token.contract_abi, "balances", [sender_address])
        print("Balance after transfer:", res)


        # =========================================================================
        # 3. Deploy and Test DataRegistry
        # =========================================================================
        print("\n>>Deploy/Load DataRegistry:-----------------------------------------------")
        abi_file_registry = "contracts/DataRegistry.abi"
        parser_registry = DatatypeParser()
        parser_registry.load_abi_file(abi_file_registry)
        
        # Try to load existing address
        registry_address = ContractNote.get_last("demo", "DataRegistry")
        
        if registry_address:
             print(f"Found DataRegistry at {registry_address}, skipping deployment.")
        else:
            print("Deploying DataRegistry...")
            bin_file_registry = "contracts/DataRegistry.bin"
            with open(bin_file_registry, 'r') as f:
                contract_bin_registry = f.read()
            result_registry = client.deploy(contract_bin_registry)
            print("DataRegistry deployed at:", result_registry["contractAddress"])
            registry_address = result_registry["contractAddress"]
            ContractNote.save_address_to_contract_note("demo", "DataRegistry", registry_address)

        print("\n>>Test DataRegistry Functions:---------------------------------------")
        # 3.1 Register Data
        # Generate a random bytes32 hash (using hex string format for compatibility)
        data_hash_bytes = secrets.token_bytes(32)
        # BCOS SDK usually expects bytes to be passed as bytes or hex string depending on config/implementation. 
        # Typically hex string with 0x prefix works well for bytes32 in JSON-RPC.
        data_hash = "0x" + data_hash_bytes.hex()
        
        price = 50
        data_id = 1001
        
        print(f"-> Registering data: Hash={data_hash}, Price={price}, ID={data_id}")
        receipt = client.sendRawTransaction(registry_address, parser_registry.contract_abi, "registerData", [data_hash, price, data_id])
        if receipt['status'] == 0:
            print("Register Data success. TxHash:", receipt['transactionHash'])
        else:
            print("Register Data failed:", receipt)
            
        # 3.2 Check Owner
        res = client.call(registry_address, parser_registry.contract_abi, "getDataOwner", [data_hash])
        print("Data Owner:", res)
        
        # 3.3 Grant Access
        user_to_grant = recipient
        print(f"-> Granting access to {user_to_grant}...")
        receipt = client.sendRawTransaction(registry_address, parser_registry.contract_abi, "grantAccess", [data_hash, user_to_grant])
        if receipt['status'] == 0:
             print("Grant Access success.")
        else:
             print("Grant Access failed:", receipt)
             
        # 3.4 Check Access
        res = client.call(registry_address, parser_registry.contract_abi, "hasAccess", [data_hash, user_to_grant])
        print(f"Has Access ({user_to_grant}): {res}")
        
        # 3.5 Revoke Access
        print(f"-> Revoking access from {user_to_grant}...")
        receipt = client.sendRawTransaction(registry_address, parser_registry.contract_abi, "revokeAccess", [data_hash, user_to_grant])
        if receipt['status'] == 0:
             print("Revoke Access success.")
        
        # Check Access again
        res = client.call(registry_address, parser_registry.contract_abi, "hasAccess", [data_hash, user_to_grant])
        print(f"Has Access ({user_to_grant}) after revoke: {res}")

        stat.done()
        print("\nDemo completed.")
    except BcosException as e:
        print("execute demo failed ,BcosException for: {}".format(e))
        import traceback
        traceback.print_exc()
    except Exception as e:
        print("execute demo failed ,Exception for: {}".format(e))
        import traceback
        traceback.print_exc()
    finally:
        if 'client' in locals():
            client.finish()

if __name__ == "__main__":
    demo_data_market()
