"""简单的 sqlite 数据库存储，用于模拟设备端/平台端的数据表。"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Dict, List, Optional

from . import default_data_dir


@dataclass
class DataRecord:
    data_id: int
    name: str
    description: str
    payload: str
    price: int
    data_hash: str


class LocalDataStore:
    """针对 demo 的 sqlite 封装。"""

    def __init__(self, db_name: str = "device_data.db") -> None:
        self.db_path = default_data_dir() / db_name
        self._ensure_schema()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS data_records (
                    data_id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    payload TEXT NOT NULL,
                    price INTEGER NOT NULL,
                    data_hash TEXT NOT NULL,
                    extra JSON
                );
                """
            )
            conn.commit()

    def _compute_hash(self, payload: str) -> str:
        return "0x" + sha256(payload.encode("utf-8")).hexdigest()

    def seed_demo_records(self) -> None:
        """初始化几条示例数据，方便快速体验。"""
        if self.list_records():
            return
        samples = [
            {
                "data_id": 1,
                "name": "EnvMonitor-01",
                "description": "温湿度传感器 24h 数据片段",
                "payload": json.dumps({"temp": [25.3, 24.8, 23.9], "hum": [60, 58, 57]}),
                "price": 30,
            },
            {
                "data_id": 2,
                "name": "Vibration-Edge",
                "description": "振动传感器频域特征",
                "payload": json.dumps({"fft": [0.12, 0.44, 0.11]}),
                "price": 50,
            },
        ]
        for record in samples:
            self.upsert_record(**record)

    def upsert_record(
        self,
        data_id: int,
        name: str,
        description: str,
        payload: str,
        price: int,
        extra: Optional[Dict] = None,
    ) -> DataRecord:
        desc = description or ""
        data_hash = self._compute_hash(payload)
        with self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM data_records WHERE data_id=?", (data_id,)
            ).fetchone()
            if exists:
                conn.execute(
                    """
                    UPDATE data_records
                    SET name=?, description=?, payload=?, price=?, data_hash=?, extra=?
                    WHERE data_id=?
                    """,
                    (name, desc, payload, price, data_hash, json.dumps(extra) if extra else None, data_id),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO data_records(
                        data_id, name, description, payload, price, data_hash, extra
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (data_id, name, desc, payload, price, data_hash, json.dumps(extra) if extra else None),
                )
            conn.commit()
        return DataRecord(
            data_id=data_id,
            name=name,
            description=desc,
            payload=payload,
            price=price,
            data_hash=data_hash,
        )

    def get_record(self, data_id: int) -> Optional[DataRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data_id, name, description, payload, price, data_hash FROM data_records WHERE data_id=?",
                (data_id,),
            ).fetchone()
        if not row:
            return None
        return DataRecord(*row)

    def list_records(self) -> List[DataRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data_id, name, description, payload, price, data_hash FROM data_records ORDER BY data_id"
            ).fetchall()
        return [DataRecord(*row) for row in rows]
