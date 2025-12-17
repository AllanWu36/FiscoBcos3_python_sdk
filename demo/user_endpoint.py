#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户侧 demo：
1. faucet + approve，初始化 token 余额与授权额度；
2. 调用平台 REST 接口：/show_data、/req_task、/download_data；
3. 直接对 DataRegistry 执行 buyAndGrantAccess；
4. 提取当前账户公钥，向平台发起任务并解密回包。
"""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import requests
sys.path.append("./")
from eth_utils import to_checksum_address
from eth_utils.crypto import set_crypto_type, CRYPTO_TYPE_GM, CRYPTO_TYPE_ECDSA

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
sys.path.append(str(ROOT_DIR))
sys.path.append(str(CURRENT_DIR))

from bcos3sdk.bcos3client import Bcos3Client  # type: ignore  # pylint: disable=import-error
from client.bcoserror import BcosException  # type: ignore  # pylint: disable=import-error
from client.contractnote import ContractNote  # type: ignore  # pylint: disable=import-error
from client.datatype_parser import DatatypeParser  # type: ignore  # pylint: disable=import-error

from data_market.crypto_utils import EncryptedPackage, decrypt_with_private_key


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
    account_keyfile = "pemtest.pem"
    account_password = "123456"  # 实际使用时建议改为复杂密码
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




@dataclass
class AccountMaterial:
    """封装当前账户的地址、公钥与私钥 Byte."""

    address: str
    public_key: str
    private_key_bytes: bytes


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def _normalize_hex(value: str) -> str:
    return value if value.startswith("0x") else f"0x{value}"


def _normalize_address(address: str) -> str:
    if not address:
        raise ValueError("需要提供有效的合约地址")
    normalized = address if address.startswith("0x") else f"0x{address}"
    return to_checksum_address(normalized)


def _resolve_contract_address(
    explicit: Optional[str], tag: str, name: str, info_file: str
) -> str:
    if explicit:
        return _normalize_address(explicit)
    address = ContractNote.get_last(tag, name, contract_info_file=info_file)
    if not address:
        raise RuntimeError(
            f"未能在 {info_file} 的 [{tag}] 段找到 {name} 合约地址，请先部署或通过参数指定"
        )
    return _normalize_address(address)


def _load_abi(abi_path: Optional[str], default_name: str) -> DatatypeParser:
    parser = DatatypeParser()
    target = abi_path or str(ROOT_DIR / "contracts" / default_name)
    parser.load_abi_file(target)
    return parser


def _get_account_material(client: Bcos3Client) -> AccountMaterial:
    addr_ptr = client.bcossdk.bcos_sdk_get_keypair_address(client.keypair)
    address = _normalize_address(ctypes.string_at(addr_ptr).decode("utf-8"))
    client.bcossdk.bcos_sdk_c_free(addr_ptr)

    pub_ptr = client.bcossdk.bcos_sdk_get_keypair_public_key(client.keypair)
    public_key = ctypes.string_at(pub_ptr).decode("utf-8")
    client.bcossdk.bcos_sdk_c_free(pub_ptr)

    keypair = client.default_from_account_signer.get_keypair()
    priv_hex = keypair.private_key or ""
    clean_hex = priv_hex[2:] if priv_hex.startswith("0x") else priv_hex
    private_key_bytes = bytes.fromhex(clean_hex)
    return AccountMaterial(address=address, public_key=public_key, private_key_bytes=private_key_bytes)


def _normalize_base_url(url: str) -> str:
    return url[:-1] if url.endswith("/") else url


def _request_json(method: str, url: str, **kwargs) -> Dict:
    try:
        resp = requests.request(method, url, **kwargs)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"调用 {url} 失败：{exc}") from exc
    try:
        return resp.json()
    except ValueError as exc:
        raise RuntimeError(f"解析 {url} 返回值失败：{exc}") from exc


def _log_receipt(action: str, receipt: Dict) -> None:
    if receipt.get("status") == 0:
        logging.info("%s 成功，tx=%s", action, receipt.get("transactionHash"))
    else:
        logging.error("%s 失败：%s", action, json.dumps(receipt, ensure_ascii=False, indent=2))


def faucet_and_approve(args: argparse.Namespace) -> None:
    token_address = _resolve_contract_address(
        args.token_address, args.contract_tag, args.token_name, args.contract_info
    )
    registry_address = _resolve_contract_address(
        args.registry_address, args.contract_tag, args.registry_name, args.contract_info
    )
    parser_token = _load_abi(args.token_abi, "SimpleToken.abi")

    client = Bcos3Client(client_config_A)
    try:
        material = _get_account_material(client)
        logging.info("当前账户地址：%s", material.address)
        if args.faucet_amount > 0:
            receipt = client.sendRawTransaction(
                token_address,
                parser_token.contract_abi,
                "faucet",
                [args.faucet_amount],
            )
            _log_receipt("faucet", receipt)
        receipt = client.sendRawTransaction(
            token_address,
            parser_token.contract_abi,
            "approve",
            [registry_address, args.approve_amount],
        )
        _log_receipt("approve", receipt)
        balance = client.call(
            token_address, parser_token.contract_abi, "balances", [material.address]
        )
        logging.info("当前余额：%s", balance)
    except BcosException as exc:
        logging.exception("链上调用失败：%s", exc)
        raise
    finally:
        client.finish()


def show_registered_data(args: argparse.Namespace) -> None:
    base = _normalize_base_url(args.platform_url)
    payload = _request_json("GET", f"{base}/show_data", timeout=args.http_timeout)
    logging.info("共返回 %s 条记录：", payload.get("count"))
    for item in payload.get("data", []):
        logging.info(
            "data_id=%s hash=%s price=%s owner=%s",
            item.get("data_id"),
            item.get("data_hash"),
            item.get("price"),
            item.get("owner"),
        )


def buy_on_chain(args: argparse.Namespace) -> None:
    if not args.data_hash:
        raise ValueError("请通过 --data-hash 指定数据哈希")
    token_address = _resolve_contract_address(
        args.token_address, args.contract_tag, args.token_name, args.contract_info
    )
    registry_address = _resolve_contract_address(
        args.registry_address, args.contract_tag, args.registry_name, args.contract_info
    )
    parser_registry = _load_abi(args.registry_abi, "DataRegistry.abi")
    client = Bcos3Client(client_config_A)
    try:
        data_hash = _normalize_hex(args.data_hash)
        receipt = client.sendRawTransaction(
            registry_address,
            parser_registry.contract_abi,
            "buyAndGrantAccess",
            [data_hash, token_address],
        )
        _log_receipt("buyAndGrantAccess", receipt)
    except BcosException as exc:
        logging.exception("链上调用失败：%s", exc)
        raise
    finally:
        client.finish()


def request_task(args: argparse.Namespace) -> None:
    client = Bcos3Client(client_config_A)
    try:
        material = _get_account_material(client)
    finally:
        client.finish()

    base = _normalize_base_url(args.platform_url)
    payload: Dict[str, object] = {
        "data_id": args.data_id,
        "buyer_pubkey": material.public_key,
    }
    if args.note:
        payload["note"] = args.note
    if args.reply_topic:
        payload["reply_topic"] = args.reply_topic
    if args.extra_json:
        try:
            payload["extra"] = json.loads(args.extra_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"extra-json 解析失败：{exc}") from exc

    logging.info("买家公钥：%s", material.public_key)
    data = _request_json(
        "POST",
        f"{base}/req_task",
        json=payload,
        timeout=args.http_timeout,
    )
    logging.info("平台返回：%s", data)


def download_data(args: argparse.Namespace) -> None:
    base = _normalize_base_url(args.platform_url)
    result = _request_json(
        "GET",
        f"{base}/download_data",
        params={"task_id": args.task_id},
        timeout=args.http_timeout,
    )
    logging.info("任务状态：%s", result.get("status"))
    payload = result.get("data")
    if not payload:
        logging.info("尚未收到设备回包：%s", result)
        return
    encrypted = payload.get("encrypted_package")
    if not encrypted:
        logging.info("回包中没有密文，原始数据：%s", payload)
        return

    client = Bcos3Client(client_config_A)
    try:
        material = _get_account_material(client)
    finally:
        client.finish()

    package = EncryptedPackage.from_message(encrypted)
    decrypted = decrypt_with_private_key(material.private_key_bytes, package)
    try:
        decoded = decrypted.decode("utf-8")
    except UnicodeDecodeError:
        decoded = decrypted.hex()
        logging.warning("密文非 UTF-8 文本，已按 hex 输出")
    logging.info("解密内容：%s", decoded)


def _add_contract_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--contract-tag", default="bcos3-chain0-group0", help="contract.ini 段名，默认 demo")
    parser.add_argument(
        "--contract-info",
        default="bin/contract.ini",
        help="合约地址存储文件，默认 bin/contract.ini",
    )
    parser.add_argument("--token-name", default="SimpleToken", help="token 合约别名")
    parser.add_argument("--registry-name", default="DataRegistry", help="DataRegistry 合约别名")
    parser.add_argument("--token-address", help="覆盖 SimpleToken 地址")
    parser.add_argument("--registry-address", help="覆盖 DataRegistry 地址")
    parser.add_argument("--token-abi", help="SimpleToken ABI 路径，默认 contracts/SimpleToken.abi")
    parser.add_argument("--registry-abi", help="DataRegistry ABI 路径，默认 contracts/DataRegistry.abi")


def _add_platform_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--platform-url",
        default="http://127.0.0.1:8000",
        help="平台 FastAPI 根地址，默认 http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=5.0,
        help="HTTP 请求超时时间，默认 5 秒",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="数据市场 demo - 用户端")
    parser.add_argument("--log-level", default="INFO", help="日志级别，默认 INFO")
    subparsers = parser.add_subparsers(dest="command", required=True)

    token_parser = subparsers.add_parser("token_setup", help="调用 faucet 并授权 DataRegistry")
    _add_contract_options(token_parser)
    token_parser.add_argument(
        "--faucet-amount", type=int, default=1000, help="faucet 领取数量，默认 1000"
    )
    token_parser.add_argument(
        "--approve-amount", type=int, default=1000, help="approve 授权额度，默认 1000"
    )
    token_parser.set_defaults(func=faucet_and_approve)

    show_parser = subparsers.add_parser("show_data", help="调用平台 /show_data")
    _add_platform_options(show_parser)
    show_parser.set_defaults(func=show_registered_data)

    buy_parser = subparsers.add_parser(
        "buy_onchain", help="直接调用 DataRegistry.buyAndGrantAccess"
    )
    _add_contract_options(buy_parser)
    buy_parser.add_argument("--data-hash", required=True, help="目标数据哈希 (0x...)")
    buy_parser.set_defaults(func=buy_on_chain)

    req_parser = subparsers.add_parser("req_task", help="向平台请求设备数据")
    _add_platform_options(req_parser)
    req_parser.add_argument("--data-id", type=int, required=True, help="目标 data_id")
    req_parser.add_argument("--note", help="请求备注，将写入平台 task")
    req_parser.add_argument("--reply-topic", help="覆盖平台默认回传 topic")
    req_parser.add_argument("--extra-json", help="额外 JSON 字符串，透传至设备")
    req_parser.set_defaults(func=request_task)

    download_parser = subparsers.add_parser("download_data", help="下载并解密任务结果")
    _add_platform_options(download_parser)
    download_parser.add_argument("--task-id", required=True, help="平台返回的 taskId")
    download_parser.set_defaults(func=download_data)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)
    args.func(args)


if __name__ == "__main__":
    main()
