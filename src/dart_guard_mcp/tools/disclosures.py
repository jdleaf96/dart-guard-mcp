"""search_disclosures: 회사 1곳의 기간 내 공시 목록."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from ..dart_client import DartClient
from ..envelope import ToolFailure, disclosure_source, ok

KST = timezone(timedelta(hours=9))
MAX_RANGE_DAYS = 366

DISCLOSURE_TYPES = {
    "A": "정기공시", "B": "주요사항보고", "C": "발행공시", "D": "지분공시", "E": "기타공시",
    "F": "외부감사관련", "G": "펀드공시", "H": "자산유동화", "I": "거래소공시", "J": "공정위공시",
}


def _parse_date(value: str, name: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ToolFailure("rejected", "INVALID_ARGUMENT", f"{name}는 YYYY-MM-DD 형식이어야 합니다.") from exc


def _fmt_dt(yyyymmdd: str) -> str:
    return f"{yyyymmdd[:4]}-{yyyymmdd[4:6]}-{yyyymmdd[6:]}" if len(yyyymmdd) == 8 else yyyymmdd


async def search_disclosures(
    client: DartClient,
    corp_code: str,
    start_date: str,
    end_date: str,
    disclosure_type: str | None,
    limit: int,
) -> dict[str, Any]:
    start, end = _parse_date(start_date, "start_date"), _parse_date(end_date, "end_date")
    today = datetime.now(KST).date()
    if end > today:
        end = today
    if start > end:
        raise ToolFailure("rejected", "INVALID_ARGUMENT", "start_date가 end_date보다 늦습니다.")
    if (end - start).days > MAX_RANGE_DAYS:
        raise ToolFailure("rejected", "RANGE_TOO_WIDE", f"조회 기간은 최대 {MAX_RANGE_DAYS}일입니다. 기간을 나눠서 조회하세요.")

    params = {
        "corp_code": corp_code,
        "bgn_de": start.strftime("%Y%m%d"),
        "end_de": end.strftime("%Y%m%d"),
        "page_no": "1",
        "page_count": str(limit),
    }
    if disclosure_type:
        params["pblntf_ty"] = disclosure_type

    try:
        body = await client.get_json("list", params)
    except ToolFailure as exc:
        if exc.code == "NO_DATA":
            return ok(
                {"items": [], "total": 0, "period": {"start": str(start), "end": str(end)}},
                status="not_found",
            )
        raise

    items = []
    for row in body.get("list", []):
        rcept_no = str(row.get("rcept_no", ""))
        if not rcept_no.isdigit() or len(rcept_no) != 14:
            continue
        src = disclosure_source(
            rcept_no,
            corp_name=str(row.get("corp_name", "")),
            report_nm=str(row.get("report_nm", "")).strip(),
            rcept_dt=_fmt_dt(str(row.get("rcept_dt", ""))),
        )
        src["filer_nm"] = str(row.get("flr_nm", ""))
        src["remark"] = str(row.get("rm", ""))
        items.append(src)

    data = {
        "period": {"start": str(start), "end": str(end)},
        "disclosure_type": DISCLOSURE_TYPES.get(disclosure_type or "", "전체"),
        "total": int(body.get("total_count", len(items)) or 0),
        "returned": len(items),
        "items": items,
    }
    return ok(data, sources=items)
