"""平台侧 sqlite 数据库封装。"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from . import default_data_dir


@dataclass
class RegisteredData:
    data_hash: str
    data_id: int
    owner: str
    price: int
    block_number: int
    tx_hash: str
    block_timestamp: Optional[int] = None
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict:
        payload = asdict(self)
        return payload


@dataclass
class TaskRecord:
    task_id: str
    data_id: int
    data_hash: Optional[str]
    status: str
    buyer_pubkey: str
    price: Optional[int] = None
    request_payload: Optional[Dict] = None
    response_payload: Optional[Dict] = None

    def to_dict(self) -> Dict:
        payload = asdict(self)
        return payload


class PlatformDataStore:
    """平台服务使用的 sqlite 数据库。"""

    def __init__(self, db_name: str = "platform_data.db") -> None:
        self.db_path = default_data_dir() / db_name
        self._ensure_schema()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS registered_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data_hash TEXT UNIQUE,
                    data_id INTEGER,
                    owner TEXT,
                    price INTEGER,
                    block_number INTEGER,
                    tx_hash TEXT,
                    block_timestamp INTEGER,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS payed_data (
                    task_id TEXT PRIMARY KEY,
                    data_id INTEGER,
                    data_hash TEXT,
                    buyer_pubkey TEXT,
                    price INTEGER,
                    status TEXT,
                    request_payload TEXT,
                    response_payload TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.commit()

    def upsert_registered_data(
        self,
        data_hash: str,
        data_id: int,
        owner: str,
        price: int,
        block_number: int,
        tx_hash: str,
        block_timestamp: Optional[int] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        """插入或更新链上注册信息。"""
        meta = json.dumps(metadata) if metadata else None
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO registered_data(
                    data_hash, data_id, owner, price, block_number, tx_hash, block_timestamp, metadata
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(data_hash) DO UPDATE SET
                    data_id=excluded.data_id,
                    owner=excluded.owner,
                    price=excluded.price,
                    block_number=excluded.block_number,
                    tx_hash=excluded.tx_hash,
                    block_timestamp=excluded.block_timestamp,
                    metadata=excluded.metadata
                ;
                """,
                (
                    data_hash,
                    data_id,
                    owner,
                    price,
                    block_number,
                    tx_hash,
                    block_timestamp,
                    meta,
                ),
            )
            conn.commit()

    def list_registered_data(self) -> List[RegisteredData]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT data_hash, data_id, owner, price, block_number, tx_hash, block_timestamp, metadata
                FROM registered_data
                ORDER BY id DESC
                """
            ).fetchall()
        result: List[RegisteredData] = []
        for row in rows:
            metadata = json.loads(row[7]) if row[7] else None
            result.append(
                RegisteredData(
                    data_hash=row[0],
                    data_id=row[1],
                    owner=row[2],
                    price=row[3],
                    block_number=row[4],
                    tx_hash=row[5],
                    block_timestamp=row[6],
                    metadata=metadata,
                )
            )
        return result

    def get_data_by_id(self, data_id: int) -> Optional[RegisteredData]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT data_hash, data_id, owner, price, block_number, tx_hash, block_timestamp, metadata
                FROM registered_data
                WHERE data_id=?
                """,
                (data_id,),
            ).fetchone()
        if not row:
            return None
        metadata = json.loads(row[7]) if row[7] else None
        return RegisteredData(
            data_hash=row[0],
            data_id=row[1],
            owner=row[2],
            price=row[3],
            block_number=row[4],
            tx_hash=row[5],
            block_timestamp=row[6],
            metadata=metadata,
        )

    def save_task_request(
        self,
        task_id: str,
        data_id: int,
        data_hash: Optional[str],
        buyer_pubkey: str,
        price: Optional[int],
        request_payload: Dict,
    ) -> None:
        payload = json.dumps(request_payload, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO payed_data(
                    task_id, data_id, data_hash, buyer_pubkey, price, status, request_payload, updated_at
                ) VALUES(?,?,?,?,?, 'pending', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(task_id) DO UPDATE SET
                    data_id=excluded.data_id,
                    data_hash=excluded.data_hash,
                    buyer_pubkey=excluded.buyer_pubkey,
                    price=excluded.price,
                    status='pending',
                    request_payload=excluded.request_payload,
                    updated_at=CURRENT_TIMESTAMP
                ;
                """,
                (
                    task_id,
                    data_id,
                    data_hash,
                    buyer_pubkey,
                    price,
                    payload,
                ),
            )
            conn.commit()

    def save_task_response(
        self,
        task_id: str,
        data_id: Optional[int],
        data_hash: Optional[str],
        response_payload: Dict,
        status: str = "ready",
    ) -> None:
        payload = json.dumps(response_payload, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO payed_data(
                    task_id, data_id, data_hash, status, response_payload, updated_at
                ) VALUES(?,?,?,?,?, CURRENT_TIMESTAMP)
                ON CONFLICT(task_id) DO UPDATE SET
                    data_id=COALESCE(excluded.data_id, payed_data.data_id),
                    data_hash=COALESCE(excluded.data_hash, payed_data.data_hash),
                    status=excluded.status,
                    response_payload=excluded.response_payload,
                    updated_at=CURRENT_TIMESTAMP
                ;
                """,
                (task_id, data_id, data_hash, status, payload),
            )
            conn.commit()

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT task_id, data_id, data_hash, buyer_pubkey, price, status, request_payload, response_payload
                FROM payed_data
                WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
        if not row:
            return None
        request_payload = json.loads(row[6]) if row[6] else None
        response_payload = json.loads(row[7]) if row[7] else None
        return TaskRecord(
            task_id=row[0],
            data_id=row[1] or 0,
            data_hash=row[2],
            buyer_pubkey=row[3] or "",
            price=row[4],
            status=row[5],
            request_payload=request_payload,
            response_payload=response_payload,
        )
