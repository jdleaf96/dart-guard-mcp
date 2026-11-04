"""MCP 도구 통합 테스트 (가짜 DART + in-memory MCP 클라이언트)."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from mcp.client import Client

from dart_guard_mcp.server import build_server

from .conftest import FAKE_KEY, envelope

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_resolve_company_exact_and_ambiguous(settings, transport):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool("resolve_company", {"query": "카카오"}))
        assert env["status"] == "ok"
        assert env["data"]["resolved"]["corp_code"] == "00258801"
        assert [x["corp_name"] for x in env["data"]["candidates"]] == ["카카오", "카카오뱅크"]  # 비상장 제외

        env = envelope(await c.call_tool("resolve_company", {"query": "카카"}))
        assert env["data"]["resolved"] is None  # 정확히 일치하는 회사 없음 → 사용자 확인 필요


async def test_resolve_company_like_wildcards_are_escaped(settings, transport):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool("resolve_company", {"query": "%", "listed_only": False}))
        assert env["status"] == "not_found"  # '%'가 와일드카드로 동작하면 전체가 나옴


async def test_corp_list_downloaded_once(settings, transport, fake_dart):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        for q in ("카카오", "삼성전자", "카카오뱅크"):
            await c.call_tool("resolve_company", {"query": q})
    assert sum(r.url.path.endswith("corpCode.xml") for r in fake_dart.requests) == 1


async def test_search_disclosures_has_sources_and_caches(settings, transport, fake_dart):
    args = {"corp_code": "00258801", "start_date": "2026-08-01", "end_date": "2026-11-01"}
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool("search_disclosures", args))
        env2 = envelope(await c.call_tool("search_disclosures", args))
    item = env["data"]["items"][0]
    assert item["url"].endswith("rcpNo=20261103800250")
    assert env["sources"][0]["rcept_no"] == "20261103800250"
    assert env["security"]["untrusted_content"] is True
    assert env["meta"]["upstream_calls"] == 1
    assert env2["meta"] == {"upstream_calls": 0, "cache_hits": 1}


async def test_requests_go_only_to_dart_host_with_allowed_params(settings, transport, fake_dart):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        await c.call_tool("search_disclosures", {"corp_code": "00258801", "start_date": "2026-08-01", "end_date": "2026-11-01"})
    req = fake_dart.requests[-1]
    assert req.url.host == "opendart.fss.or.kr"
    assert set(req.url.params) <= {"corp_code", "bgn_de", "end_de", "page_no", "page_count", "crtfc_key"}


async def test_range_too_wide_rejected_without_upstream_call(settings, transport, fake_dart):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool(
            "search_disclosures", {"corp_code": "00258801", "start_date": "2024-01-01", "end_date": "2025-12-31"}))
    assert env["status"] == "rejected" and env["error"]["code"] == "RANGE_TOO_WIDE"
    assert fake_dart.requests == []


async def test_schema_rejects_bad_corp_code(settings, transport, fake_dart):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        result = await c.call_tool("search_disclosures", {"corp_code": "../x", "start_date": "2026-01-01", "end_date": "2026-02-01"})
    assert result.is_error and fake_dart.requests == []
    audit = [json.loads(l) for l in settings.audit_path.read_text(encoding="utf-8").splitlines()]
    assert audit[-1]["status"] == "rejected" and audit[-1]["error"] == "SCHEMA_VALIDATION"


async def test_dart_status_mapped_to_envelope(settings, transport, fake_dart):
    fake_dart.list_status = "020"
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool(
            "search_disclosures", {"corp_code": "00258801", "start_date": "2026-08-01", "end_date": "2026-11-01"}))
    assert env["status"] == "rate_limited" and env["error"]["code"] == "UPSTREAM_RATE_LIMIT"
    fake_dart.list_status = "013"
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool(
            "search_disclosures", {"corp_code": "00258801", "start_date": "2026-07-01", "end_date": "2026-11-01"}))
    assert env["status"] == "not_found"


async def test_rate_limit_returns_retry_after(settings, transport):
    tight = replace(settings, calls_per_minute=2)
    async with Client(build_server(tight, FAKE_KEY, transport)) as c:
        statuses = [envelope(await c.call_tool("resolve_company", {"query": "카카오"}))["status"] for _ in range(3)]
        env = envelope(await c.call_tool("resolve_company", {"query": "카카오"}))
    assert statuses == ["ok", "ok", "rate_limited"]
    assert env["error"]["retry_after_sec"] > 0


async def test_daily_budget_blocks_upstream(settings, transport):
    tiny = replace(settings, daily_budget=1)
    async with Client(build_server(tiny, FAKE_KEY, transport)) as c:
        await c.call_tool("resolve_company", {"query": "카카오"})  # corpCode.xml로 1회 사용
        env = envelope(await c.call_tool(
            "search_disclosures", {"corp_code": "00258801", "start_date": "2026-08-01", "end_date": "2026-11-01"}))
    assert env["status"] == "rate_limited" and env["error"]["code"] == "DAILY_BUDGET_EXCEEDED"


async def test_financials_computed_by_server(settings, transport):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        env = envelope(await c.call_tool("get_financials", {"corp_code": "00126380", "year": 2025}))
    basis, accounts = env["data"]["basis"], {a["account_nm"]: a for a in env["data"]["accounts"]}
    assert basis["fs_div"] == "CFS" and basis["computed_by"] == "server"
    assert accounts["매출액"]["current"] == 1100 and accounts["매출액"]["change_pct"] == 10.0  # OFS 900이 섞이지 않음
    assert accounts["영업이익"]["change"] == 70 and accounts["영업이익"]["change_pct"] is None  # 전기 적자
    assert env["sources"][0]["rcept_no"] == "20260310002820"


async def test_no_key_in_audit_or_responses(settings, transport):
    async with Client(build_server(settings, FAKE_KEY, transport)) as c:
        r = await c.call_tool("get_financials", {"corp_code": "00126380", "year": 2025})
    assert FAKE_KEY not in r.content[0].text
    assert FAKE_KEY not in settings.audit_path.read_text(encoding="utf-8")
