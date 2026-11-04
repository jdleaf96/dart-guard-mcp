"""보안 계층 단위 테스트: 키 마스킹, 허용 목록, 압축 파일·XML, 요청 횟수 제한."""

from __future__ import annotations

import io
import logging
import zipfile

import pytest

from dart_guard_mcp.cache import open_db
from dart_guard_mcp.security import allowlist
from dart_guard_mcp.security.ratelimit import DailyBudget, DailyBudgetExceeded, RateLimiter
from dart_guard_mcp.security.safe_archive import ArchiveLimits, UnsafeArchive, parse_xml, read_zip
from dart_guard_mcp.security.secrets import MissingApiKey, SecretMaskingFilter, install_log_masking, load_api_key, mask

from .conftest import FAKE_KEY


# --- T3: API 키 유출 ---------------------------------------------------------

def test_mask_removes_query_key_and_raw_key():
    url = f"https://opendart.fss.or.kr/api/list.json?corp_code=1&crtfc_key={FAKE_KEY}"
    assert FAKE_KEY not in mask(url)
    assert FAKE_KEY not in mask(f"error near {FAKE_KEY}", FAKE_KEY)


def test_http_library_logs_cannot_leak_key(caplog):
    install_log_masking(FAKE_KEY)
    httpx_logger = logging.getLogger("httpx")
    # 1) INFO 요청 로그는 아예 만들어지지 않는다.
    with caplog.at_level(logging.DEBUG, logger="httpx"):
        httpx_logger.setLevel(logging.WARNING)
        httpx_logger.info("HTTP Request: GET https://x/?crtfc_key=%s", FAKE_KEY)
        # 2) WARNING 이상이 나가도 키는 가려진다.
        httpx_logger.warning("failed: https://x/?crtfc_key=%s", FAKE_KEY)
    assert all(FAKE_KEY not in r.getMessage() for r in caplog.records)
    assert any("***" in r.getMessage() for r in caplog.records)


def test_filter_masks_exception_text():
    flt = SecretMaskingFilter(FAKE_KEY)
    try:
        raise RuntimeError(f"boom crtfc_key={FAKE_KEY}")
    except RuntimeError:
        import sys

        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "oops", None, sys.exc_info())
    flt.filter(record)
    assert FAKE_KEY not in (record.exc_text or "")


def test_load_api_key_never_echoes_value(monkeypatch):
    monkeypatch.setenv("DART_API_KEY", "not-a-valid-key-but-secret")
    with pytest.raises(MissingApiKey) as exc:
        load_api_key()
    assert "not-a-valid-key-but-secret" not in str(exc.value)


# --- T5: 범위 일탈 -----------------------------------------------------------

def test_allowlist_rejects_unknown_endpoint_and_params():
    with pytest.raises(allowlist.NotAllowed):
        allowlist.check("company", {})
    with pytest.raises(allowlist.NotAllowed):
        allowlist.check("list", {"corp_code": "00126380", "crtfc_key": "override"})
    with pytest.raises(allowlist.NotAllowed):
        allowlist.check("list", {"corp_code": "x" * 100})
    assert allowlist.check("list", {"corp_code": "00126380"}).path == "list.json"


# --- T6: 악성 파일 -----------------------------------------------------------

def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_zip_bomb_rejected():
    bomb = _zip({"a.xml": b"0" * (5 * 1024 * 1024)})  # 압축률이 매우 높음
    with pytest.raises(UnsafeArchive):
        read_zip(bomb, ArchiveLimits(max_ratio=100))


def test_zip_size_and_count_limits():
    with pytest.raises(UnsafeArchive):
        read_zip(_zip({f"{i}.xml": b"x" for i in range(5)}), ArchiveLimits(max_files=3))
    with pytest.raises(UnsafeArchive):
        read_zip(_zip({"a.xml": bytes(range(256)) * 100}), ArchiveLimits(max_total_bytes=1000))


def test_zip_path_traversal_names_are_flattened():
    out = read_zip(_zip({"../../evil.xml": b"<a/>"}))
    assert list(out) == ["evil.xml"]  # 경로로 쓰지 않고, 디스크에 쓰지도 않음


def test_xxe_and_dtd_rejected():
    xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>'
    with pytest.raises(UnsafeArchive):
        parse_xml(xxe)
    assert parse_xml(b"<r><a>1</a></r>").findtext("a") == "1"


# --- T2: 과도한 호출 ---------------------------------------------------------

def test_rate_limiter_blocks_then_reports_retry():
    limiter = RateLimiter(per_minute=3)
    assert all(limiter.acquire("t")[0] for _ in range(3))
    allowed, retry = limiter.acquire("t")
    assert not allowed and retry > 0


def test_daily_budget_persists(tmp_path):
    conn, lock = open_db(tmp_path / "b.sqlite3")
    budget = DailyBudget(conn, lock, limit=2)
    budget.consume()
    budget.consume()
    with pytest.raises(DailyBudgetExceeded):
        budget.consume()
    # 재시작(새 객체)해도 사용량이 유지된다.
    assert DailyBudget(conn, lock, limit=2).used_today() == 2
