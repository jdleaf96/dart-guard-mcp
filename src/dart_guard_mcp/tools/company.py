"""resolve_company: 회사 이름 → DART 고유번호(corp_code) 후보.

DART 고유번호 목록(corpCode.xml, zip)을 하루 1번 받아 SQLite에 저장하고,
검색은 로컬에서만 한다 (질의마다 DART를 부르지 않음).
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from typing import Any

from ..dart_client import DartClient
from ..envelope import ToolFailure, ok
from ..security.safe_archive import ArchiveLimits, UnsafeArchive, parse_xml, read_zip

REFRESH_SEC = 24 * 3600
# 전체 회사 목록 XML은 수십 MB라서 별도 상한을 둔다.
CORP_LIST_LIMITS = ArchiveLimits(max_files=1, max_total_bytes=150 * 1024 * 1024, max_ratio=100)
_STRIP = re.compile(r"\(주\)|㈜|주식회사|\(유\)|유한회사|\s+")


def normalize(name: str) -> str:
    return _STRIP.sub("", name).lower()


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class CorpIndex:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock, client: DartClient) -> None:
        self._conn, self._lock, self._client = conn, lock, client
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS corps (
                    corp_code TEXT PRIMARY KEY, corp_name TEXT NOT NULL, norm TEXT NOT NULL,
                    stock_code TEXT NOT NULL, modify_date TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS corps_norm ON corps(norm);
                CREATE TABLE IF NOT EXISTS corps_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
                """
            )
            self._conn.commit()

    def _loaded_at(self) -> float:
        with self._lock:
            row = self._conn.execute("SELECT v FROM corps_meta WHERE k='loaded_at'").fetchone()
        return float(row[0]) if row else 0.0

    async def ensure_fresh(self) -> float:
        loaded_at = self._loaded_at()
        if time.time() - loaded_at < REFRESH_SEC:
            return loaded_at
        raw = await self._client.get_binary("corp_code", {})
        try:
            files = read_zip(raw, CORP_LIST_LIMITS)
            root = parse_xml(next(iter(files.values())))
        except (UnsafeArchive, StopIteration) as exc:
            raise ToolFailure("upstream_error", "UNSAFE_ARCHIVE", f"회사 목록 파일을 처리할 수 없습니다: {exc}") from exc

        rows = []
        for item in root.iter("list"):
            code = (item.findtext("corp_code") or "").strip()
            name = (item.findtext("corp_name") or "").strip()
            if not re.fullmatch(r"\d{8}", code) or not name:
                continue
            rows.append(
                (code, name, normalize(name), (item.findtext("stock_code") or "").strip(),
                 (item.findtext("modify_date") or "").strip())
            )
        if not rows:
            raise ToolFailure("upstream_error", "UPSTREAM_BAD_RESPONSE", "회사 목록이 비어 있습니다.")
        now = time.time()
        with self._lock:
            self._conn.execute("DELETE FROM corps")
            self._conn.executemany("INSERT OR REPLACE INTO corps VALUES (?,?,?,?,?)", rows)
            self._conn.execute("INSERT OR REPLACE INTO corps_meta VALUES ('loaded_at', ?)", (str(now),))
            self._conn.commit()
        return now

    def search(self, query: str, listed_only: bool, limit: int = 10) -> list[dict[str, Any]]:
        norm = normalize(query)
        if not norm:
            return []
        listed = "AND stock_code != ''" if listed_only else ""
        like = _escape_like(norm)
        sql = f"""
            SELECT corp_code, corp_name, stock_code,
                   CASE WHEN norm = ? THEN 0 WHEN norm LIKE ? ESCAPE '\\' THEN 1 ELSE 2 END AS rank
            FROM corps
            WHERE norm LIKE ? ESCAPE '\\' {listed}
            ORDER BY rank, (stock_code = ''), length(norm), corp_name
            LIMIT ?
        """
        with self._lock:
            rows = self._conn.execute(sql, (norm, like + "%", "%" + like + "%", limit)).fetchall()
        kinds = {0: "exact", 1: "prefix", 2: "partial"}
        return [
            {"corp_code": c, "corp_name": n, "stock_code": s or None, "listed": bool(s), "match": kinds[r]}
            for c, n, s, r in rows
        ]


async def resolve_company(index: CorpIndex, query: str, listed_only: bool) -> dict[str, Any]:
    loaded_at = await index.ensure_fresh()
    candidates = index.search(query, listed_only)
    exact = [c for c in candidates if c["match"] == "exact"]
    data = {
        "query": query,
        "candidates": candidates,
        "resolved": exact[0] if len(exact) == 1 else None,
        "guidance": (
            "정확히 일치하는 회사가 1개라 resolved에 넣었습니다."
            if len(exact) == 1
            else "정확히 일치하는 회사가 없거나 여러 개입니다. 사용자에게 어느 회사인지 확인하세요."
        ),
    }
    source = {
        "kind": "dataset",
        "name": "DART 고유번호 목록 (corpCode.xml)",
        "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(loaded_at)),
    }
    return ok(data, sources=[source], status="ok" if candidates else "not_found")
