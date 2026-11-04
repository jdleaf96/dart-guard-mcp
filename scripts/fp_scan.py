"""실제 DART 공시에서 정제기 오탐(정상 문장을 차단하는 경우)을 측정한다.

측정 대상
1. 최근 공시: COMPANIES 각 회사의 최근 180일 공시, 회사당 최대 N건 (대부분 짧은 거래소·지분 공시)
2. 고정 대상: FIXED_DOCS (본문이 긴 사업보고서. 첨부 감사보고서 포함)

사용: uv run python scripts/fp_scan.py [회사당 공시 수, 기본 10]
결과: eval/false_positive_scan.md (공시별 rcept_no·글자 수 표 포함, 같은 명령으로 재현 가능)
DART 호출 수 ≈ 회사 수 × (1 + 공시 수) + 고정 대상 수. 서버의 일일 한도 안에서 동작한다.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
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
FIXED_DOCS = {"20260310002820": ("삼성전자", "사업보고서 (2025.12)")}
IGNORED_FLAGS = {"invisible_unicode"}  # 보이지 않는 문자 제거는 줄 차단이 아니므로 오탐으로 세지 않음


@dataclass
class DocResult:
    group: str
    corp: str
    report: str
    rcept_no: str
    files: int
    chars: int
    blocked: int


async def scan_doc(client: DartClient, group: str, corp: str, report: str, rno: str,
                   flagged: list[str]) -> DocResult | None:
    try:
        files = read_zip(await client.get_binary("document", {"rcept_no": rno}), DOCUMENT_LIMITS)
    except (ToolFailure, UnsafeArchive):
        return None
    chars = blocked = 0
    for data in files.values():
        for sec in parse_document(data).sections:
            chars += len(sec.text)
            if not (sanitize(sec.text).flags - IGNORED_FLAGS):
                continue
            for line in sec.text.split("\n"):
                hits = sanitize(line).flags - IGNORED_FLAGS
                if hits:
                    blocked += 1
                    flagged.append(f"| {corp} | {report} | {rno} | {sorted(hits)} | {line[:80]} |")
    return DocResult(group, corp, report, rno, len(files), chars, blocked)


async def main(per_company: int) -> None:
    s = load_settings()
    conn, lock = open_db(s.db_path)
    client = DartClient(load_api_key(), TTLCache(conn, lock), DailyBudget(conn, lock, s.daily_budget))
    end = date.today()
    start = end - timedelta(days=180)
    results: list[DocResult] = []
    flagged: list[str] = []
    skipped = 0

    for name, code in COMPANIES.items():
        body = await client.get_json("list", {"corp_code": code, "bgn_de": start.strftime("%Y%m%d"),
                                              "end_de": end.strftime("%Y%m%d"), "page_no": "1",
                                              "page_count": str(per_company)})
        for item in body.get("list", []):
            if item["rcept_no"] in FIXED_DOCS:
                continue  # 고정 대상과 겹치면 한 번만 센다
            r = await scan_doc(client, "최근 공시", name, item["report_nm"].strip(), item["rcept_no"], flagged)
            if r is None:
                skipped += 1
            else:
                results.append(r)

    for rno, (corp, report) in FIXED_DOCS.items():
        r = await scan_doc(client, "고정 대상", corp, report, rno, flagged)
        if r is None:
            skipped += 1
        else:
            results.append(r)
    await client.aclose()

    def total(group: str | None = None) -> tuple[int, int, int]:
        rs = [r for r in results if group is None or r.group == group]
        return len(rs), sum(r.chars for r in rs), sum(r.blocked for r in rs)

    n_recent, c_recent, b_recent = total("최근 공시")
    n_fixed, c_fixed, b_fixed = total("고정 대상")
    n_all, c_all, b_all = total()

    out = Path(s.home) / "eval" / "false_positive_scan.md"
    out.parent.mkdir(exist_ok=True)
    lines = [
        "# 정제기 오탐 측정 (실제 DART 공시)",
        "",
        f"- 측정일: {date.today()} / 명령: `uv run python scripts/fp_scan.py {per_company}`",
        "- 실제 공시에는 인젝션이 없다고 보고, 차단된 줄은 모두 오탐으로 계산 (보이지 않는 문자 제거는 제외)",
        "",
        "| 구분 | 대상 | 공시 수 | 본문 글자 수 | 차단된 줄 |",
        "|---|---|---:|---:|---:|",
        f"| 최근 공시 | {', '.join(COMPANIES)} 최근 180일, 회사당 최대 {per_company}건 | {n_recent} | {c_recent:,} | {b_recent} |",
        f"| 고정 대상 | " + ", ".join(f"{c} {r}" for c, r in FIXED_DOCS.values()) + f" (첨부 포함) | {n_fixed} | {c_fixed:,} | {b_fixed} |",
        f"| **합계** | | **{n_all}** | **{c_all:,}** | **{b_all}** |",
        "",
        f"원문 없음 등으로 건너뛴 공시: {skipped}건",
        "",
    ]
    if flagged:
        lines += ["## 차단된 줄", "", "| 회사 | 보고서 | rcept_no | 분류 | 차단된 줄 |", "|---|---|---|---|---|", *flagged, ""]
    lines += ["## 측정한 공시 목록", "", "| 구분 | 회사 | 보고서 | rcept_no | 파일 수 | 글자 수 | 차단 |", "|---|---|---|---|---:|---:|---:|"]
    lines += [f"| {r.group} | {r.corp} | {r.report} | {r.rcept_no} | {r.files} | {r.chars:,} | {r.blocked} |" for r in results]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:12]))


if __name__ == "__main__":
    anyio.run(main, int(sys.argv[1]) if len(sys.argv) > 1 else 10)
