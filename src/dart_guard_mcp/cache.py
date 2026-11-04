"""SQLite 기반 TTL 캐시. 캐시 키에는 API 키가 절대 들어가지 않는다."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any


def open_db(path) -> tuple[sqlite3.Connection, threading.Lock]:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn, threading.Lock()


class TTLCache:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn, self._lock = conn, lock
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS http_cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL NOT NULL)"
            )
            self._conn.commit()

    @staticmethod
    def make_key(endpoint: str, params: dict[str, str]) -> str:
        return endpoint + "?" + "&".join(f"{k}={params[k]}" for k in sorted(params))

    def get(self, key: str) -> Any | None:
        with self._lock:
            row = self._conn.execute("SELECT value, expires FROM http_cache WHERE key=?", (key,)).fetchone()
        if not row or row[1] < time.time():
            return None
        return json.loads(row[0])

    def set(self, key: str, value: Any, ttl_sec: int) -> None:
        if ttl_sec <= 0:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO http_cache(key, value, expires) VALUES(?, ?, ?)",
                (key, json.dumps(value, ensure_ascii=False), time.time() + ttl_sec),
            )
            self._conn.commit()
