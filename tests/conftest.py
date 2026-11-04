from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest

from dart_guard_mcp.config import Settings

FAKE_KEY = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(
        home=tmp_path, data_dir=tmp_path / "data", log_dir=tmp_path / "logs",
        daily_budget=100, calls_per_minute=30, http_timeout_sec=5,
    )
    s.data_dir.mkdir()
    s.log_dir.mkdir()
    return s


def corp_zip() -> bytes:
    xml = (
        "<?xml version='1.0' encoding='UTF-8'?><result>"
        "<list><corp_code>00126380</corp_code><corp_name>삼성전자</corp_name><stock_code>005930</stock_code><modify_date>20260101</modify_date></list>"
        "<list><corp_code>00258801</corp_code><corp_name>카카오</corp_name><stock_code>035720</stock_code><modify_date>20260101</modify_date></list>"
        "<list><corp_code>01133217</corp_code><corp_name>카카오뱅크</corp_name><stock_code>323410</stock_code><modify_date>20260101</modify_date></list>"
        "<list><corp_code>99999999</corp_code><corp_name>카카오_비상장</corp_name><stock_code> </stock_code><modify_date>20260101</modify_date></list>"
        "</result>"
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("CORPCODE.xml", xml)
    return buf.getvalue()


FIN_ROWS = [
    {"rcept_no": "20260310002820", "fs_div": "CFS", "sj_div": "IS", "sj_nm": "손익계산서", "account_nm": "매출액",
     "thstrm_nm": "제 57 기", "frmtrm_nm": "제 56 기", "thstrm_dt": "2025.01.01 ~ 2025.12.31",
     "frmtrm_dt": "2024.01.01 ~ 2024.12.31", "thstrm_amount": "1,100", "frmtrm_amount": "1,000", "currency": "KRW"},
    {"rcept_no": "20260310002820", "fs_div": "CFS", "sj_div": "IS", "sj_nm": "손익계산서", "account_nm": "영업이익",
     "thstrm_amount": "50", "frmtrm_amount": "-20"},
    {"rcept_no": "20260310002820", "fs_div": "OFS", "sj_div": "IS", "sj_nm": "손익계산서", "account_nm": "매출액",
     "thstrm_amount": "900", "frmtrm_amount": "800"},
]


class FakeDart:
    """httpx.MockTransport 핸들러. 받은 요청을 기록한다."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.list_status = "000"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("corpCode.xml"):
            return httpx.Response(200, content=corp_zip(), headers={"content-type": "application/x-msdownload"})
        if path.endswith("list.json"):
            if self.list_status != "000":
                return httpx.Response(200, json={"status": self.list_status, "message": "x"})
            return httpx.Response(200, json={
                "status": "000", "total_count": 1,
                "list": [{"corp_name": "카카오", "report_nm": "기업설명회(IR)개최", "rcept_no": "20261103800250",
                          "flr_nm": "카카오", "rcept_dt": "20261103", "rm": "유"}]})
        if path.endswith("fnlttSinglAcnt.json"):
            return httpx.Response(200, json={"status": "000", "list": FIN_ROWS})
        return httpx.Response(404)


@pytest.fixture
def fake_dart() -> FakeDart:
    return FakeDart()


@pytest.fixture
def transport(fake_dart: FakeDart) -> httpx.MockTransport:
    return httpx.MockTransport(fake_dart)


def envelope(result) -> dict:
    return json.loads(result.content[0].text)
