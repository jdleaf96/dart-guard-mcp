"""실제 DART에 붙여 시나리오 S1·S2를 확인하는 스모크 테스트 (in-memory MCP 클라이언트)."""
import json
import sys
from datetime import date, timedelta

import anyio
from mcp.client import Client

from dart_guard_mcp.server import build_server


def show(label, result, n=900):
    text = result.content[0].text
    print(f"\n=== {label} (is_error={result.is_error}) ===")
    print(text[:n])
    return json.loads(text) if not result.is_error else None


async def main():
    async with Client(build_server()) as c:
        env = show("resolve_company 카카오", await c.call_tool("resolve_company", {"query": "카카오"}))
        kakao = env["data"]["resolved"]["corp_code"]
        today = date.today()
        show("search_disclosures 카카오 90일", await c.call_tool("search_disclosures", {
            "corp_code": kakao, "start_date": str(today - timedelta(days=90)), "end_date": str(today), "limit": 5}))
        env = show("resolve_company 삼성전자", await c.call_tool("resolve_company", {"query": "삼성전자"}), 400)
        sam = env["data"]["resolved"]["corp_code"]
        show("get_financials 삼성전자 2025", await c.call_tool("get_financials", {"corp_code": sam, "year": 2025}), 1800)
        show("rejected: 2년 범위", await c.call_tool("search_disclosures", {
            "corp_code": sam, "start_date": "2024-01-01", "end_date": "2025-12-31"}), 500)
        show("rejected: schema", await c.call_tool("search_disclosures", {
            "corp_code": "abc", "start_date": "2025-01-01", "end_date": "2025-02-01"}), 300)

anyio.run(main)
