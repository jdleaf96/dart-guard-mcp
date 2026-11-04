"""요청 횟수 제한.

- RateLimiter: 도구 호출에 거는 토큰 버킷 (프로세스 메모리, 분 단위)
- DailyBudget: DART 실제 호출 수 일일 한도 (SQLite에 저장해 재시작해도 유지)
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


@dataclass
class _Bucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    updated: float = field(default_factory=time.monotonic)


class RateLimiter:
    def __init__(self, per_minute: int, overrides: dict[str, int] | None = None) -> None:
        self._default = per_minute
        self._overrides = overrides or {}
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _bucket(self, key: str) -> _Bucket:
        b = self._buckets.get(key)
        if b is None:
            per_min = self._overrides.get(key, self._default)
            b = self._buckets[key] = _Bucket(per_min, per_min / 60.0, float(per_min))
        return b

    def acquire(self, *keys: str) -> tuple[bool, float]:
        """모든 키의 버킷에서 토큰 1개씩. 하나라도 부족하면 소모하지 않고 대기 시간을 돌려준다."""
        now = time.monotonic()
        with self._lock:
            buckets = [self._bucket(k) for k in keys]
            for b in buckets:
                b.tokens = min(b.capacity, b.tokens + (now - b.updated) * b.refill_per_sec)
                b.updated = now
            short = [b for b in buckets if b.tokens < 1]
            if short:
                wait = max((1 - b.tokens) / b.refill_per_sec for b in short)
                return False, round(wait, 1)
            for b in buckets:
                b.tokens -= 1
            return True, 0.0


class DailyBudgetExceeded(RuntimeError):
    pass


class DailyBudget:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock, limit: int) -> None:
        self._conn, self._lock, self.limit = conn, lock, limit
        with self._lock:
            self._conn.execute("CREATE TABLE IF NOT EXISTS daily_budget (day TEXT PRIMARY KEY, used INTEGER NOT NULL)")
            self._conn.commit()

    @staticmethod
    def _today() -> str:
        return datetime.now(KST).strftime("%Y-%m-%d")

    def consume(self) -> int:
        day = self._today()
        with self._lock:
            row = self._conn.execute("SELECT used FROM daily_budget WHERE day=?", (day,)).fetchone()
            used = row[0] if row else 0
            if used >= self.limit:
                raise DailyBudgetExceeded(f"오늘 DART 호출 한도({self.limit}회)를 모두 사용했습니다.")
            self._conn.execute(
                "INSERT INTO daily_budget(day, used) VALUES(?, 1) "
                "ON CONFLICT(day) DO UPDATE SET used = used + 1",
                (day,),
            )
            self._conn.commit()
            return used + 1

    def used_today(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT used FROM daily_budget WHERE day=?", (self._today(),)).fetchone()
        return row[0] if row else 0
