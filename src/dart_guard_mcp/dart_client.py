"""DART OpenAPI 클라이언트.

- 허용 목록(allowlist)에 있는 API·파라미터만 호출
- 호스트 고정, 리다이렉트 따라가지 않음
- 일일 호출 한도 확인 후 호출, 응답은 TTL 캐시
- DART 상태 코드를 표준 실패(ToolFailure)로 변환하고, 에러 메시지에 키가 들어가지 않게 함
"""

from __future__ import annotations

import contextvars
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from .cache import TTLCache
from .envelope import ToolFailure
from .security import allowlist
from .security.ratelimit import DailyBudget, DailyBudgetExceeded
from .security.secrets import install_log_masking, mask

log = logging.getLogger(__name__)

# DART 응답 status → (봉투 status, 에러 코드, 메시지)
_DART_STATUS: dict[str, tuple[str, str, str]] = {
    "013": ("not_found", "NO_DATA", "조회된 데이터가 없습니다."),
    "014": ("not_found", "NO_DATA", "원문 파일이 존재하지 않습니다."),
    "020": ("rate_limited", "UPSTREAM_RATE_LIMIT", "DART 요청 제한을 초과했습니다."),
    "021": ("rejected", "TOO_MANY_COMPANIES", "조회 가능한 회사 수를 초과했습니다."),
    "010": ("upstream_error", "UPSTREAM_AUTH", "DART 인증키가 등록되지 않았습니다."),
    "011": ("upstream_error", "UPSTREAM_AUTH", "사용할 수 없는 DART 인증키입니다."),
    "012": ("upstream_error", "UPSTREAM_AUTH", "접근할 수 없는 IP입니다."),
    "901": ("upstream_error", "UPSTREAM_AUTH", "인증키 보유 기간이 만료되었습니다."),
    "100": ("rejected", "INVALID_ARGUMENT", "DART가 파라미터를 거부했습니다."),
    "101": ("rejected", "INVALID_ARGUMENT", "DART가 파라미터를 거부했습니다."),
    "800": ("upstream_error", "UPSTREAM_MAINTENANCE", "DART 시스템 점검 중입니다."),
}


@dataclass
class CallStats:
    upstream_calls: int = 0
    cache_hits: int = 0


# 도구 호출 1건 동안의 통계 (guard가 시작할 때 새로 만든다)
current_stats: contextvars.ContextVar[CallStats | None] = contextvars.ContextVar("current_stats", default=None)


def _stats() -> CallStats:
    s = current_stats.get()
    return s if s is not None else CallStats()


class DartClient:
    def __init__(
        self,
        api_key: str,
        cache: TTLCache,
        budget: DailyBudget,
        *,
        timeout_sec: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._key = api_key
        # 클라이언트를 만드는 순간 마스킹을 건다 (main()을 거치지 않는 테스트·스크립트에서도 안전).
        install_log_masking(api_key)
        self._cache = cache
        self._budget = budget
        self._http = httpx.AsyncClient(
            base_url=allowlist.DART_BASE_URL,
            timeout=timeout_sec,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": "dart-guard-mcp/0.1"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get_json(self, endpoint: str, params: dict[str, str]) -> dict[str, Any]:
        ep = allowlist.check(endpoint, params)
        if ep.binary:
            raise allowlist.NotAllowed(f"{endpoint}는 JSON API가 아닙니다.")
        key = TTLCache.make_key(endpoint, params)
        cached = self._cache.get(key)
        if cached is not None:
            _stats().cache_hits += 1
            return cached

        resp = await self._request(ep.path, params)
        try:
            body = resp.json()
        except ValueError as exc:
            raise ToolFailure("upstream_error", "UPSTREAM_BAD_RESPONSE", "DART 응답을 해석할 수 없습니다.") from exc
        self._raise_for_dart_status(body)
        self._cache.set(key, body, ep.cache_ttl_sec)
        return body

    async def get_binary(self, endpoint: str, params: dict[str, str]) -> bytes:
        ep = allowlist.check(endpoint, params)
        if not ep.binary:
            raise allowlist.NotAllowed(f"{endpoint}는 파일 API가 아닙니다.")
        resp = await self._request(ep.path, params)
        if not resp.content.startswith(b"PK"):
            # 오류일 때 DART는 zip 대신 상태 메시지(JSON/XML)를 준다.
            body = self._parse_status_body(resp)
            self._raise_for_dart_status(body)
            raise ToolFailure("upstream_error", "UPSTREAM_BAD_RESPONSE", "DART가 zip이 아닌 응답을 보냈습니다.")
        return resp.content

    async def _request(self, path: str, params: dict[str, str]) -> httpx.Response:
        try:
            self._budget.consume()
        except DailyBudgetExceeded as exc:
            raise ToolFailure("rate_limited", "DAILY_BUDGET_EXCEEDED", str(exc)) from exc

        _stats().upstream_calls += 1
        try:
            resp = await self._http.get(path, params={**params, "crtfc_key": self._key})
        except httpx.TimeoutException as exc:
            raise ToolFailure("upstream_error", "UPSTREAM_TIMEOUT", "DART 응답 시간이 초과되었습니다.") from exc
        except httpx.HTTPError as exc:
            log.warning("DART 요청 실패: %s", mask(str(exc), self._key))
            raise ToolFailure("upstream_error", "UPSTREAM_NETWORK", "DART에 연결할 수 없습니다.") from exc

        if resp.is_redirect or resp.url.host != allowlist.DART_HOST:
            raise ToolFailure("upstream_error", "UPSTREAM_REDIRECT", "예상하지 못한 리다이렉트 응답입니다.")
        if resp.status_code != 200:
            raise ToolFailure("upstream_error", "UPSTREAM_HTTP", f"DART HTTP 오류 ({resp.status_code})")
        return resp

    @staticmethod
    def _parse_status_body(resp: httpx.Response) -> dict[str, Any]:
        try:
            return resp.json()
        except ValueError:
            text = resp.text
            status = text.split("<status>", 1)[-1].split("</status>", 1)[0] if "<status>" in text else "900"
            return {"status": status}

    @staticmethod
    def _raise_for_dart_status(body: dict[str, Any]) -> None:
        status = str(body.get("status", "900"))
        if status == "000":
            return
        env_status, code, message = _DART_STATUS.get(
            status, ("upstream_error", "UPSTREAM_ERROR", f"DART 오류 (status={status})")
        )
        raise ToolFailure(env_status, code, message)  # type: ignore[arg-type]
