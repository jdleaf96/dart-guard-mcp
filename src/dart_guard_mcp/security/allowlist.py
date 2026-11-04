"""호출 가능한 DART API와 파라미터 허용 목록.

여기에 없는 API·파라미터는 호출할 수 없다. 호스트도 고정이다.
"""

from __future__ import annotations

from dataclasses import dataclass

DART_HOST = "opendart.fss.or.kr"
DART_BASE_URL = f"https://{DART_HOST}/api/"
VIEWER_URL = "https://dart.fss.or.kr/dsaf001/main.do?rcpNo={rcept_no}"


@dataclass(frozen=True)
class Endpoint:
    path: str
    params: frozenset[str]
    binary: bool  # zip 응답 여부
    cache_ttl_sec: int


ENDPOINTS: dict[str, Endpoint] = {
    "corp_code": Endpoint("corpCode.xml", frozenset(), binary=True, cache_ttl_sec=0),  # 별도 테이블에 저장
    "list": Endpoint(
        "list.json",
        frozenset({"corp_code", "bgn_de", "end_de", "pblntf_ty", "page_no", "page_count", "last_reprt_at"}),
        binary=False,
        cache_ttl_sec=600,
    ),
    "document": Endpoint("document.xml", frozenset({"rcept_no"}), binary=True, cache_ttl_sec=0),  # Day 2
    "financials": Endpoint(
        "fnlttSinglAcnt.json",
        frozenset({"corp_code", "bsns_year", "reprt_code"}),
        binary=False,
        cache_ttl_sec=86400,
    ),
}


class NotAllowed(ValueError):
    pass


def check(endpoint: str, params: dict[str, str]) -> Endpoint:
    ep = ENDPOINTS.get(endpoint)
    if ep is None:
        raise NotAllowed(f"허용되지 않은 API: {endpoint}")
    extra = set(params) - ep.params
    if extra:
        raise NotAllowed(f"허용되지 않은 파라미터: {sorted(extra)}")
    for name, value in params.items():
        if not isinstance(value, str) or len(value) > 64:
            raise NotAllowed(f"파라미터 값이 올바르지 않음: {name}")
    return ep
