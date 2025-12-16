"""极简 SQLite 消息队列，方便 demo 进程间通讯。"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Callable, Dict, Optional

from . import default_data_dir


class SQLiteMessageQueue:
    """以 sqlite 文件模拟 MQ，支持跨进程轮询消费。"""

    def __init__(self, db_name: str = "demo_mq.db") -> None:
        self.db_path = default_data_dir() / db_name
        self._ensure_schema()
        self.logger = logging.getLogger("SQLiteMQ")

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mq_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.commit()

    def publish(self, topic: str, payload: Dict) -> int:
        """写入消息，返回 message id。"""
        serialized = json.dumps(payload, ensure_ascii=False)
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO mq_messages(topic, payload, status) VALUES(?,?, 'pending')",
                (topic, serialized),
            )
            conn.commit()
            return cur.lastrowid

    def _fetch_pending(self, topic: str, limit: int = 10):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, payload FROM mq_messages
                WHERE topic=? AND status='pending'
                ORDER BY id ASC
                LIMIT ?
                """,
                (topic, limit),
            ).fetchall()
        return rows

    def _mark_done(self, message_id: int, status: str = "done") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE mq_messages SET status=? WHERE id=?", (status, message_id)
            )
            conn.commit()

    def consume_forever(
        self,
        topic: str,
        handler: Callable[[Dict, int], None],
        poll_interval: float = 2.0,
        stop_event: Optional["Event"] = None,
    ) -> None:
        """阻塞式消费函数，收到 Ctrl+C 会退出。"""
        self.logger.info("开始监听 MQ，topic=%s db=%s", topic, self.db_path)
        try:
            while True:
                if stop_event and stop_event.is_set():
                    self.logger.info("收到停止信号，退出消费循环")
                    return
                rows = self._fetch_pending(topic)
                if not rows:
                    time.sleep(poll_interval)
                    continue
                for message_id, payload in rows:
                    try:
                        handler(json.loads(payload), message_id)
                        self._mark_done(message_id)
                    except Exception as exc:  # pylint: disable=broad-except
                        self.logger.exception(
                            "处理消息 %s 失败：%s，消息将保留为 pending", message_id, exc
                        )
                        self._mark_done(message_id, status="error")
        except KeyboardInterrupt:
            self.logger.info("收到 Ctrl+C，停止消费")
