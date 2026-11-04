"""감사 로그 (JSONL, 한 줄에 도구 호출 1건).

MCP 미들웨어로 걸어서, 인자 검증 단계에서 거절된 호출까지 포함해
모든 tools/call 요청을 기록한다. 비밀값은 남기지 않는다.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from .ratelimit import KST
from .secrets import mask

_MAX_ARG_CHARS = 200


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        return mask(value[:_MAX_ARG_CHARS])
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _clip(json.dumps(value, ensure_ascii=False))


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.session = uuid.uuid4().hex[:8]
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        record = {"ts": datetime.now(KST).isoformat(timespec="seconds"), "session": self.session, **record}
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def middleware(self):
        audit = self

        async def audit_middleware(ctx, call_next):
            if getattr(ctx, "method", None) != "tools/call":
                return await call_next(ctx)
            params = ctx.params if isinstance(ctx.params, dict) else {}
            tool = str(params.get("name", "?"))
            args = params.get("arguments") or {}
            started = time.perf_counter()
            record: dict[str, Any] = {
                "tool": tool,
                "args": {str(k): _clip(v) for k, v in args.items()} if isinstance(args, dict) else {},
            }
            try:
                result = await call_next(ctx)
            except Exception as exc:
                record.update(
                    status="protocol_error",
                    error=type(exc).__name__,
                    latency_ms=round((time.perf_counter() - started) * 1000),
                )
                audit.write(record)
                raise
            record["latency_ms"] = round((time.perf_counter() - started) * 1000)
            record.update(_summarize(result))
            audit.write(record)
            return result

        return audit_middleware


def _summarize(result: Any) -> dict[str, Any]:
    """도구 결과(dict)에서 봉투 필드를 뽑는다. 봉투가 아니면 SDK 단계 거절로 본다."""
    out: dict[str, Any] = {}
    if not isinstance(result, dict):
        return {"status": "unknown"}
    content = result.get("content") or []
    text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
    output_chars = sum(len(c.get("text", "")) for c in content if isinstance(c, dict))
    try:
        env = json.loads(text)
    except (TypeError, ValueError):
        env = None
    if isinstance(env, dict) and "status" in env:
        out["status"] = env["status"]
        if env.get("error"):
            out["error"] = env["error"].get("code")
        sec = env.get("security") or {}
        out["injection_flags"] = sec.get("injection_flags", [])
        out["redactions"] = sec.get("redactions", 0)
        meta = env.get("meta") or {}
        out["upstream_calls"] = meta.get("upstream_calls", 0)
        out["cache_hits"] = meta.get("cache_hits", 0)
    else:
        # MCP SDK가 스키마 검증 단계에서 거절한 경우 (예: 글자 수 초과)
        out["status"] = "rejected" if result.get("isError") else "unknown"
        out["error"] = "SCHEMA_VALIDATION" if result.get("isError") else None
    out["output_chars"] = output_chars
    return out
