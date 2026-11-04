"""get_financials: 주요 재무 계정과 전기 대비 증감 (계산은 서버에서)."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from ..dart_client import DartClient
from ..envelope import ToolFailure, disclosure_source, ok

REPORT_CODES = {"annual": "11011", "half": "11012", "q1": "11013", "q3": "11014"}
REPORT_NAMES = {"annual": "사업보고서", "half": "반기보고서", "q1": "1분기보고서", "q3": "3분기보고서"}
FS_NAMES = {"CFS": "연결재무제표", "OFS": "별도(개별)재무제표"}


def _amount(value: Any) -> Decimal | None:
    text = str(value or "").replace(",", "").strip()
    if text in {"", "-"}:
        return None
    try:
        return Decimal(text)
    except InvalidOperation:
        return None


def _num(d: Decimal | None) -> int | None:
    return int(d) if d is not None else None


def _change(current: Decimal | None, prior: Decimal | None) -> tuple[int | None, float | None, str | None]:
    if current is None or prior is None:
        return None, None, "비교할 값이 없습니다."
    diff = current - prior
    if prior <= 0:
        # 전기가 0 이하(적자 등)이면 증감률이 의미가 없다.
        return int(diff), None, "전기 값이 0 이하라 증감률을 계산하지 않았습니다."
    return int(diff), float(round(diff / prior * 100, 2)), None


async def get_financials(client: DartClient, corp_code: str, year: int, report: str, fs_div: str) -> dict[str, Any]:
    params = {"corp_code": corp_code, "bsns_year": str(year), "reprt_code": REPORT_CODES[report]}
    try:
        body = await client.get_json("financials", params)
    except ToolFailure as exc:
        if exc.code == "NO_DATA":
            return ok(
                {"note": f"{year}년 {REPORT_NAMES[report]} 재무 데이터가 DART에 없습니다. 아직 제출 전이거나 비상장사일 수 있습니다."},
                status="not_found",
            )
        raise

    rows = [r for r in body.get("list", []) if r.get("fs_div") == fs_div]
    available = sorted({str(r.get("fs_div")) for r in body.get("list", [])})
    if not rows:
        return ok(
            {"note": f"{FS_NAMES[fs_div]} 데이터가 없습니다.", "available_fs_div": available},
            status="not_found",
        )

    accounts = []
    seen: set[tuple[str, str, str]] = set()
    for r in rows:
        # DART가 같은 계정(예: 당기순이익)을 같은 값으로 두 번 주는 경우가 있어 중복을 제거한다.
        dedupe_key = (str(r.get("sj_div")), str(r.get("account_nm")), str(r.get("thstrm_amount")))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        cur, prior = _amount(r.get("thstrm_amount")), _amount(r.get("frmtrm_amount"))
        diff, pct, note = _change(cur, prior)
        entry = {
            "account_nm": str(r.get("account_nm", "")),
            "statement": str(r.get("sj_nm", "")),
            "current": _num(cur),
            "prior": _num(prior),
            "change": diff,
            "change_pct": pct,
            "current_period": str(r.get("thstrm_dt", "")),
            "prior_period": str(r.get("frmtrm_dt", "")),
        }
        cum = _amount(r.get("thstrm_add_amount"))
        if cum is not None:
            entry["current_cumulative"] = _num(cum)
        if note:
            entry["note"] = note
        accounts.append(entry)

    first = rows[0]
    rcept_no = str(first.get("rcept_no", ""))
    basis = {
        "fs_div": fs_div,
        "fs_name": FS_NAMES[fs_div],
        "report": REPORT_NAMES[report],
        "business_year": year,
        "current_term": str(first.get("thstrm_nm", "")),
        "prior_term": str(first.get("frmtrm_nm", "")),
        "unit": str(first.get("currency") or "KRW"),
        "computed_by": "server",  # 증감·증감률은 LLM이 아니라 서버가 계산
    }
    if report != "annual":
        basis["caution"] = (
            "분기·반기 보고서의 손익 항목 current는 해당 분기 값이고 current_cumulative는 누적 값입니다. "
            "재무상태표 항목의 prior는 직전 사업연도 말 기준입니다."
        )
    data = {"basis": basis, "accounts": accounts}
    source = disclosure_source(rcept_no, report_nm=f"{REPORT_NAMES[report]} ({year})")
    return ok(data, sources=[source] if rcept_no else [])
