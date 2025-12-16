#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
平台侧 FastAPI 服务：
1. 监听链上 DataRegistered 事件，写入本地 registered_data；
2. 提供 /show_data、/req_task、/download_data REST 接口；
3. 通过 MQ 与设备端通讯，管理任务状态和回包（payed_data）。
"""
from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
sys.path.append(str(ROOT_DIR))
sys.path.append(str(CURRENT_DIR))

from bcos3sdk.bcos3client import Bcos3Client  # type: ignore  # pylint: disable=import-error
from client.datatype_parser import DatatypeParser  # type: ignore  # pylint: disable=import-error
from client.bcoserror import BcosException  # type: ignore  # pylint: disable=import-error
from eth_utils import to_checksum_address

from data_market.mq import SQLiteMessageQueue
from data_market.platform_storage import PlatformDataStore


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@dataclass
class PlatformConfig:
    registry_address: str
    registry_abi: str
    db_name: str = "platform_data.db"
    mq_db: str = "demo_mq.db"
    purchase_topic: str = "platform.purchase"
    response_topic: str = "device.payloads"
    mq_poll_interval: float = 2.0


class PlatformRuntime:
    """封装平台侧的后台线程与共享状态。"""

    def __init__(self, config: PlatformConfig) -> None:
        self.config = config
        self.store = PlatformDataStore(db_name=config.db_name)
        self.queue = SQLiteMessageQueue(db_name=config.mq_db)
        self.stop_event = threading.Event()
        self.event_thread: Optional[threading.Thread] = None
        self.mq_thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger("PlatformRuntime")
        self.parser = DatatypeParser()
        self.parser.load_abi_file(self.config.registry_abi)

    def start(self) -> None:
        self.stop_event.clear()
        self.event_thread = threading.Thread(
            target=self._event_listener_loop, name="EventListener", daemon=True
        )
        self.event_thread.start()
        self.mq_thread = threading.Thread(
            target=self._mq_listener_loop, name="MQListener", daemon=True
        )
        self.mq_thread.start()
        self.logger.info(
            "平台后台线程已启动，监听合约 %s / topic=%s",
            self.config.registry_address,
            self.config.response_topic,
        )

    def shutdown(self) -> None:
        self.stop_event.set()
        self.logger.info("等待后台线程退出...")
        for thread in [self.event_thread, self.mq_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=2)
        self.logger.info("后台线程停止")

    def _event_listener_loop(self) -> None:
        """订阅 DataRegistered 事件，并写入数据库。"""
        while not self.stop_event.is_set():
            client = Bcos3Client()
            sub_id = None
            try:
                sub_id, future = client.event_subscribe(
                    self.config.registry_address,
                    "DataRegistered",
                    self.parser.contract_abi,
                    fromBlock=-1,
                    toBlock=-1,
                )
                self.logger.info("事件订阅成功，sub_id=%s", sub_id)
                while not self.stop_event.is_set():
                    is_timeout, resp = future.wait(timeout=2)
                    if is_timeout:
                        continue
                    result = client.get_result(resp.data)
                    logs = self._extract_logs_from_result(result)
                    if not logs:
                        continue
                    parsed_logs = self.parser.parse_event_logs(logs)
                    for log in parsed_logs:
                        if log.get("eventname") != "DataRegistered":
                            continue
                        self._handle_data_registered(log)
            except BcosException as exc:
                self.logger.error("事件监听异常：%s", exc)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.exception("事件监听线程异常：%s", exc)
            finally:
                if sub_id is not None:
                    try:
                        client.bcossdk.bcos_event_sub_unsubscribe_event(client.bcossdk.sdk, sub_id)
                    except Exception:  # pylint: disable=broad-except
                        pass
                client.finish()
            if not self.stop_event.is_set():
                self.logger.info("事件监听 5 秒后重试...")
                time.sleep(5)

    def _mq_listener_loop(self) -> None:
        """监听设备端回包，写入 payed_data。"""
        self.queue.consume_forever(
            topic=self.config.response_topic,
            handler=self._handle_device_response,
            poll_interval=self.config.mq_poll_interval,
            stop_event=self.stop_event,
        )

    def _extract_logs_from_result(self, result):
        if isinstance(result, dict):
            if "logs" in result:
                return result["logs"]
            if "result" in result and isinstance(result["result"], dict):
                return result["result"].get("logs", [])
        if isinstance(result, list):
            return result
        return []

    def _handle_data_registered(self, log: Dict) -> None:
        topics = log.get("topics") or []
        data_hash = topics[1] if len(topics) > 1 else log.get("dataHash")
        owner_topic = topics[2] if len(topics) > 2 else None
        price = 0
        data_id = 0
        event_data = log.get("eventdata") or ()
        if len(event_data) >= 2:
            price = int(event_data[0])
            data_id = int(event_data[1])
        block_number = self._parse_hex_field(log.get("blockNumber"))
        block_ts = self._parse_hex_field(log.get("blockTimestamp"))
        tx_hash = log.get("transactionHash", "")
        owner = self._topic_to_address(owner_topic)
        normalized_hash = self._normalize_hex(data_hash)
        metadata = {
            "transactionIndex": log.get("transactionIndex"),
            "logIndex": log.get("logIndex"),
        }
        if not normalized_hash:
            self.logger.warning("跳过无效的 DataRegistered 日志：%s", log)
            return
        self.store.upsert_registered_data(
            data_hash=normalized_hash,
            data_id=data_id,
            owner=owner,
            price=price,
            block_number=block_number,
            tx_hash=tx_hash,
            block_timestamp=block_ts,
            metadata=metadata,
        )
        self.logger.info(
            "链上注册记录 data_id=%s hash=%s owner=%s price=%s block=%s tx=%s",
            data_id,
            normalized_hash,
            owner,
            price,
            block_number,
            tx_hash,
        )

    def _topic_to_address(self, topic: Optional[str]) -> Optional[str]:
        if not topic:
            return None
        clean = topic[-40:]
        try:
            return to_checksum_address("0x" + clean)
        except ValueError:
            return "0x" + clean

    def _normalize_hex(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        return value if value.startswith("0x") else f"0x{value}"

    def _parse_hex_field(self, value) -> int:
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        try:
            return int(str(value), 16)
        except ValueError:
            return 0

    def _handle_device_response(self, message: Dict, message_id: int) -> None:
        msg_type = message.get("type")
        if msg_type != "purchase_response":
            self.logger.debug("忽略 MQ 消息 #%s type=%s", message_id, msg_type)
            return
        task_id = message.get("task_id")
        if not task_id:
            self.logger.warning("MQ 消息缺少 task_id：%s", message)
            return
        status = message.get("status", "ready")
        data_id = message.get("data_id")
        data_hash = message.get("data_hash")
        self.store.save_task_response(
            task_id=task_id,
            data_id=data_id,
            data_hash=data_hash,
            response_payload=message,
            status=status,
        )
        self.logger.info("已保存设备回传：task_id=%s status=%s", task_id, status)


class ReqTaskBody(BaseModel):
    data_id: int = Field(..., description="数据 ID")
    buyer_pubkey: str = Field(..., description="买家未压缩公钥 (0x04+X+Y)")
    note: Optional[str] = Field(None, description="附加说明")
    reply_topic: Optional[str] = Field(None, description="覆盖默认回传 topic")
    extra: Optional[Dict] = Field(None, description="额外字段，将透传到 MQ")


def create_app(config: PlatformConfig) -> FastAPI:
    runtime = PlatformRuntime(config)
    app = FastAPI(title="Data Market Platform", version="0.1.0")

    @app.on_event("startup")
    async def _startup():
        runtime.start()

    @app.on_event("shutdown")
    async def _shutdown():
        runtime.shutdown()

    @app.get("/healthz")
    def health_check():
        return {"status": "ok"}

    @app.get("/show_data")
    def show_data():
        records = [r.to_dict() for r in runtime.store.list_registered_data()]
        return {"count": len(records), "data": records}

    @app.post("/req_task")
    def request_task(body: ReqTaskBody):
        record = runtime.store.get_data_by_id(body.data_id)
        if not record:
            raise HTTPException(status_code=404, detail="data_id 未在平台登记")
        reply_topic = body.reply_topic or runtime.config.response_topic
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        message = {
            "type": "purchase_request",
            "task_id": task_id,
            "data_id": body.data_id,
            "buyer_pubkey": body.buyer_pubkey,
            "reply_topic": reply_topic,
            "platform_note": body.note,
            "price": record.price,
            "data_hash": record.data_hash,
        }
        if body.extra:
            message["extra"] = body.extra
        message_id = runtime.queue.publish(runtime.config.purchase_topic, message)
        runtime.store.save_task_request(
            task_id=task_id,
            data_id=body.data_id,
            data_hash=record.data_hash,
            buyer_pubkey=body.buyer_pubkey,
            price=record.price,
            request_payload=message,
        )
        return {
            "task_id": task_id,
            "status": "pending",
            "message_id": message_id,
            "reply_topic": reply_topic,
        }

    @app.get("/download_data")
    def download_data(task_id: str):
        task = runtime.store.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="task_id 不存在")
        if not task.response_payload:
            return {
                "task_id": task_id,
                "status": task.status,
                "message": "数据尚未返回，请稍后重试",
            }
        return {
            "task_id": task_id,
            "status": task.status,
            "data": task.response_payload,
        }

    app.state.runtime = runtime
    return app


def parse_args():
    parser = argparse.ArgumentParser(description="数据市场平台 FastAPI 服务")
    parser.add_argument("--registry-address", required=True, help="DataRegistry 合约地址")
    parser.add_argument(
        "--registry-abi",
        default=str(ROOT_DIR / "contracts" / "DataRegistry.abi"),
        help="DataRegistry ABI 路径",
    )
    parser.add_argument("--db-name", default="platform_data.db", help="平台 sqlite 文件名")
    parser.add_argument("--mq-db", default="demo_mq.db", help="MQ sqlite 文件名")
    parser.add_argument(
        "--purchase-topic",
        default="platform.purchase",
        help="发送给设备的 MQ topic",
    )
    parser.add_argument(
        "--response-topic",
        default="device.payloads",
        help="设备回传的 MQ topic",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--reload", action="store_true", help="开发模式下开启 uvicorn reload")
    return parser


def main():
    parser = parse_args()
    args = parser.parse_args()
    configure_logging(args.log_level)
    config = PlatformConfig(
        registry_address=args.registry_address,
        registry_abi=args.registry_abi,
        db_name=args.db_name,
        mq_db=args.mq_db,
        purchase_topic=args.purchase_topic,
        response_topic=args.response_topic,
    )
    app = create_app(config)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
