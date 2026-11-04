"""실제 DART 공시에서 정제기 오탐(정상 문장을 차단하는 경우)을 측정한다.

사용: uv run python scripts/fp_scan.py [회사당 공시 수]
결과: eval/false_positive_scan.md
DART 호출 수 ≈ 회사 수 × (1 + 공시 수). 서버의 일일 한도 안에서 동작한다.
"""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import anyio

from dart_guard_mcp.cache import TTLCache, open_db
from dart_guard_mcp.config import load_settings
from dart_guard_mcp.dart_client import DartClient
from dart_guard_mcp.envelope import ToolFailure
from dart_guard_mcp.rag.parser import parse_document
from dart_guard_mcp.security.ratelimit import DailyBudget
from dart_guard_mcp.security.safe_archive import UnsafeArchive, read_zip
from dart_guard_mcp.security.sanitizer import sanitize
from dart_guard_mcp.security.secrets import load_api_key
from dart_guard_mcp.tools.documents import DOCUMENT_LIMITS

COMPANIES = {"삼성전자": "00126380", "카카오": "00258801", "SK하이닉스": "00164779", "현대자동차": "00164742", "NAVER": "00266961"}


async def main(per_company: int) -> None:
    s = load_settings()
    conn, lock = open_db(s.db_path)
    client = DartClient(load_api_key(), TTLCache(conn, lock), DailyBudget(conn, lock, s.daily_budget))
    end = date.today()
    start = end - timedelta(days=180)
    docs = chars = 0
    flagged: list[str] = []
    skipped = 0
    for name, code in COMPANIES.items():
        body = await client.get_json("list", {"corp_code": code, "bgn_de": start.strftime("%Y%m%d"),
                                              "end_de": end.strftime("%Y%m%d"), "page_no": "1",
                                              "page_count": str(per_company)})
        for item in body.get("list", []):
            rno = item["rcept_no"]
            try:
                files = read_zip(await client.get_binary("document", {"rcept_no": rno}), DOCUMENT_LIMITS)
            except (ToolFailure, UnsafeArchive):
                skipped += 1
                continue
            docs += 1
            for fname, data in files.items():
                for sec in parse_document(data).sections:
                    chars += len(sec.text)
                    r = sanitize(sec.text)
                    hits = r.flags - {"invisible_unicode"}  # 보이지 않는 문자 제거는 차단이 아님
                    if hits:
                        for line in sec.text.split("\n"):
                            if sanitize(line).flags - {"invisible_unicode"}:
                                flagged.append(f"| {name} | {item['report_nm'].strip()} | {rno} | {sorted(hits)} | {line[:80]} |")
    await client.aclose()

    out = Path(s.home) / "eval" / "false_positive_scan.md"
    out.parent.mkdir(exist_ok=True)
    lines = [
        "# 정제기 오탐 측정 (실제 DART 공시)",
        "",
        f"- 측정일: {date.today()} / 대상: {', '.join(COMPANIES)} 최근 180일 공시, 회사당 최대 {per_company}건",
        f"- 공시 {docs}건 (원문 없음 등으로 건너뜀 {skipped}건), 본문 {chars:,}자",
        f"- **차단된 줄: {len(flagged)}개** (실제 공시에는 인젝션이 없다고 보고, 차단된 줄은 모두 오탐으로 계산)",
        "",
    ]
    if flagged:
        lines += ["| 회사 | 보고서 | rcept_no | 분류 | 차단된 줄 |", "|---|---|---|---|---|", *flagged]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:6]))


if __name__ == "__main__":
    anyio.run(main, int(sys.argv[1]) if len(sys.argv) > 1 else 10)
