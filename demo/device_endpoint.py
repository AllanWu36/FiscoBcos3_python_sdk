#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备端 demo：
1. 将本地数据注册到区块链 DataRegistry 合约；
2. 监听 MQ，响应平台发起的数据购买请求，打包并加密数据后回传。
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
sys.path.append(str(ROOT_DIR))  # 访问 SDK 顶层模块
sys.path.append(str(CURRENT_DIR))  # 访问 demo.data_market.*

from bcos3sdk.bcos3client import Bcos3Client  # type: ignore  # pylint: disable=import-error
from client.contractnote import ContractNote  # type: ignore  # pylint: disable=import-error
from client.datatype_parser import DatatypeParser  # type: ignore  # pylint: disable=import-error
from client.bcoserror import BcosException  # type: ignore  # pylint: disable=import-error

from data_market.crypto_utils import encrypt_for_user
from data_market.mq import SQLiteMessageQueue
from data_market.storage import DataRecord, LocalDataStore


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def _load_payload_from_args(args: argparse.Namespace) -> Optional[str]:
    if args.payload:
        return args.payload
    if args.payload_file:
        payload_path = Path(args.payload_file)
        return payload_path.read_text(encoding="utf-8")
    return None


def _ensure_record(store: LocalDataStore, args: argparse.Namespace) -> DataRecord:
    store.seed_demo_records()
    payload = _load_payload_from_args(args)
    record = store.get_record(args.data_id)
    if payload:
        name = args.name or (record.name if record else f"Data-{args.data_id}")
        description = args.description or (record.description if record else "")
        price = args.price if args.price is not None else (record.price if record else 0)
        if price <= 0:
            raise ValueError("请通过 --price 指定注册价格")
        record = store.upsert_record(
            data_id=args.data_id,
            name=name,
            description=description,
            payload=payload,
            price=price,
            extra={"source": "device_cli"},
        )
        return record

    if record is None:
        raise ValueError(
            f"未找到 data_id={args.data_id} 的本地数据，请使用 --payload/--payload-file 先创建"
        )

    if args.price is not None and args.price != record.price:
        record = store.upsert_record(
            data_id=record.data_id,
            name=record.name,
            description=record.description,
            payload=record.payload,
            price=args.price,
            extra={"updated_by": "device_cli"},
        )
    return record


def _load_registry_address(args: argparse.Namespace) -> str:
    if args.registry_address:
        return args.registry_address
    address = ContractNote.get_last(
        args.contract_tag, args.contract_name, contract_info_file=args.contract_info
    )
    if not address:
        raise RuntimeError(
            f"未在 {args.contract_info} 中找到 {args.contract_tag}.{args.contract_name}，"
            "请先部署并记录 DataRegistry 合约地址"
        )
    return address


def register_data(args: argparse.Namespace) -> None:
    store = LocalDataStore(db_name=args.data_db)
    record = _ensure_record(store, args)
    registry_address = _load_registry_address(args)
    parser = DatatypeParser()
    abi_path = Path(args.registry_abi or ROOT_DIR / "contracts" / "DataRegistry.abi")
    parser.load_abi_file(str(abi_path))
    client = Bcos3Client()
    logging.info(
        "准备注册数据：id=%s hash=%s price=%s registry=%s",
        record.data_id,
        record.data_hash,
        record.price,
        registry_address,
    )
    try:
        receipt = client.sendRawTransaction(
            registry_address,
            parser.contract_abi,
            "registerData",
            [record.data_hash, record.price, record.data_id],
        )
        if receipt.get("status") == 0:
            logging.info("注册成功，tx=%s", receipt.get("transactionHash"))
        else:
            logging.error("注册失败：%s", json.dumps(receipt, indent=2, ensure_ascii=False))
    except BcosException as exc:
        logging.exception("发送交易失败：%s", exc)
        raise
    finally:
        client.finish()


def _build_success_payload(record: DataRecord, request: dict, encrypted_hex: dict) -> dict:
    return {
        "type": "purchase_response",
        "task_id": request["task_id"],
        "data_id": record.data_id,
        "data_hash": record.data_hash,
        "price": record.price,
        "encrypted_package": encrypted_hex,
        "metadata": {"name": record.name, "description": record.description},
        "status": "ready",
    }


def listen_purchase_requests(args: argparse.Namespace) -> None:
    queue = SQLiteMessageQueue(db_name=args.mq_db)
    store = LocalDataStore(db_name=args.data_db)
    store.seed_demo_records()

    def handle_message(message: dict, message_id: int) -> None:
        logging.info("收到消息 #%s：%s", message_id, json.dumps(message, ensure_ascii=False))
        if message.get("type") != "purchase_request":
            logging.info("忽略 type=%s 的消息", message.get("type"))
            return
        try:
            data_id = int(message["data_id"])
            buyer_pubkey = message["buyer_pubkey"]
        except KeyError as exc:
            logging.error("消息缺少字段：%s", exc)
            return

        record = store.get_record(data_id)
        if not record:
            logging.error("本地不存在 data_id=%s 的数据", data_id)
            error_payload = {
                "type": "purchase_response",
                "task_id": message.get("task_id"),
                "status": "not_found",
                "data_id": data_id,
                "error": f"data_id={data_id} not found",
            }
            queue.publish(message.get("reply_topic", args.reply_topic), error_payload)
            return

        payload_bytes = record.payload.encode("utf-8")
        encrypted = encrypt_for_user(buyer_pubkey, payload_bytes)
        response = _build_success_payload(record, message, encrypted.to_message())
        reply_topic = message.get("reply_topic", args.reply_topic)
        queue.publish(reply_topic, response)
        logging.info(
            "已加密并回传 task_id=%s -> topic=%s", message.get("task_id"), reply_topic
        )

    queue.consume_forever(
        topic=args.topic,
        handler=handle_message,
        poll_interval=args.poll_interval,
    )


def send_test_message(args: argparse.Namespace) -> None:
    queue = SQLiteMessageQueue(db_name=args.mq_db)
    task_id = args.task_id or f"task-{int(time.time())}"
    payload = {
        "type": "purchase_request",
        "task_id": task_id,
        "data_id": args.data_id,
        "buyer_pubkey": args.buyer_pubkey,
        "reply_topic": args.reply_topic,
    }
    if args.note:
        payload["note"] = args.note
    if args.extra_json:
        try:
            payload["extra"] = json.loads(args.extra_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"extra-json 解析失败：{exc}") from exc
    message_id = queue.publish(args.topic, payload)
    logging.info(
        "测试消息已写入 MQ：topic=%s task_id=%s message_id=%s",
        args.topic,
        task_id,
        message_id,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="数据市场 demo - 设备端")
    parser.add_argument("--log-level", default="INFO", help="日志级别，默认 INFO")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="将数据注册到 DataRegistry")
    register_parser.add_argument("--data-id", type=int, required=True, help="数据本地 ID")
    register_parser.add_argument("--price", type=int, help="Token 价格")
    register_parser.add_argument("--name", help="可选，创建数据时使用")
    register_parser.add_argument("--description", help="可选，创建数据时使用")
    payload_group = register_parser.add_mutually_exclusive_group()
    payload_group.add_argument("--payload", help="直接提供数据内容（建议 JSON）")
    payload_group.add_argument("--payload-file", help="从文件读取数据内容")
    register_parser.add_argument(
        "--registry-address", help="显式指定 DataRegistry 合约地址"
    )
    register_parser.add_argument(
        "--registry-abi",
        help="DataRegistry ABI 路径，默认 contracts/DataRegistry.abi",
    )
    register_parser.add_argument(
        "--contract-tag",
        default="demo",
        help="contract.ini 中的段名，默认 demo",
    )
    register_parser.add_argument(
        "--contract-name",
        default="DataRegistry",
        help="contract.ini 中存放地址的键名，默认 DataRegistry",
    )
    register_parser.add_argument(
        "--contract-info",
        default="bin/contract.ini",
        help="合约地址记录文件，默认 bin/contract.ini",
    )
    register_parser.add_argument(
        "--data-db",
        default="device_data.db",
        help="设备侧 sqlite 文件名，默认 device_data.db",
    )
    register_parser.set_defaults(func=register_data)

    mq_parser = subparsers.add_parser(
        "listen", help="监听 MQ，处理平台发起的数据购买请求"
    )
    mq_parser.add_argument("--topic", default="platform.purchase", help="订阅的 MQ topic")
    mq_parser.add_argument(
        "--reply-topic",
        default="device.payloads",
        help="默认回传 topic（平台可在请求中覆盖）",
    )
    mq_parser.add_argument(
        "--mq-db",
        default="demo_mq.db",
        help="MQ sqlite 文件名，默认 demo_mq.db",
    )
    mq_parser.add_argument(
        "--data-db",
        default="device_data.db",
        help="设备侧 sqlite 文件名，默认 device_data.db",
    )
    mq_parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="轮询间隔秒数，默认 2 秒",
    )
    mq_parser.set_defaults(func=listen_purchase_requests)

    test_parser = subparsers.add_parser(
        "test_sendmq", help="向 MQ 写入一条 purchase_request 测试消息"
    )
    test_parser.add_argument("--topic", default="platform.purchase", help="发送目标 topic")
    test_parser.add_argument("--mq-db", default="demo_mq.db", help="MQ sqlite 文件名")
    test_parser.add_argument("--data-id", type=int, required=True, help="目标数据 ID")
    test_parser.add_argument("--buyer-pubkey", required=True, help="买家公钥 (0x04+X+Y)")
    test_parser.add_argument(
        "--reply-topic",
        default="device.payloads",
        help="期望设备回传的 topic（消息体中携带）",
    )
    test_parser.add_argument(
        "--task-id",
        help="自定义 taskId，默认为 task-<timestamp>",
    )
    test_parser.add_argument("--note", help="附加说明，写入消息 note 字段")
    test_parser.add_argument(
        "--extra-json",
        help="附加 JSON，会写入消息 extra 字段，示例: '{\"foo\":123}'",
    )
    test_parser.set_defaults(func=send_test_message)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)
    args.func(args)


if __name__ == "__main__":
    main()
