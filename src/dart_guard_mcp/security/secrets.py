"""API 키 로딩과 마스킹.

DART는 인증키를 URL 쿼리(crtfc_key=...)로 받는다. httpx는 INFO 레벨에서 요청 URL을
그대로 로그에 남기므로, 아무 조치가 없으면 키가 로그 파일로 새어 나간다.
여기서는 (1) httpx/httpcore 로거를 WARNING으로 올리고 (2) 모든 로그 레코드와
에러 메시지에서 키를 지우는 필터를 건다.
"""

from __future__ import annotations

import logging
import os
import re

ENV_NAME = "DART_API_KEY"
_KEY_FORMAT = re.compile(r"^[0-9a-fA-F]{40}$")
_QUERY_KEY = re.compile(r"(crtfc_key=)[^&\s'\"]+", re.IGNORECASE)
MASK = "***"


class MissingApiKey(RuntimeError):
    pass


def load_api_key() -> str:
    key = os.environ.get(ENV_NAME, "").strip()
    if not key:
        raise MissingApiKey(f"{ENV_NAME} 환경변수(.env)가 설정되지 않았습니다.")
    if not _KEY_FORMAT.match(key):
        # 값 자체는 절대 메시지에 넣지 않는다.
        raise MissingApiKey(f"{ENV_NAME} 형식이 올바르지 않습니다 (40자리 16진수여야 함).")
    return key


def mask(text: str, secret: str | None = None) -> str:
    """문자열에서 crtfc_key 쿼리값과 (알고 있다면) 키 원문을 지운다."""
    if not text:
        return text
    out = _QUERY_KEY.sub(rf"\g<1>{MASK}", text)
    if secret:
        out = out.replace(secret, MASK)
    return out


class SecretMaskingFilter(logging.Filter):
    def __init__(self, secret: str | None = None) -> None:
        super().__init__()
        self._secret = secret

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # 포맷 실패 시에도 레코드는 남긴다
            message = str(record.msg)
        masked = mask(message, self._secret)
        if masked != message:
            record.msg, record.args = masked, None
        if record.exc_info and record.exc_info[1] is not None:
            # 예외 텍스트에도 URL이 들어갈 수 있으므로 미리 포맷해서 마스킹한다.
            record.exc_text = mask(logging.Formatter().formatException(record.exc_info), self._secret)
            record.exc_info = None
        return True


HTTP_LOGGERS = ("httpx", "httpcore", "httpx2")


def install_log_masking(secret: str | None) -> None:
    """어디서 호출되든(서버 main, 테스트, 스크립트) 키가 로그로 나가지 않게 한다.

    로거 필터는 '그 로거에서 만들어진 레코드'에만 적용되고, 핸들러 필터는 나중에 추가된
    핸들러(예: MCP SDK의 rich 핸들러)에는 적용되지 않는다. 그래서 세 겹으로 건다.
    1) HTTP 라이브러리 로거를 WARNING으로 올려 요청 URL 로그 자체를 만들지 않음
    2) HTTP 라이브러리 로거에 직접 마스킹 필터
    3) 현재 루트 핸들러들에도 마스킹 필터
    """
    flt = SecretMaskingFilter(secret)
    for name in HTTP_LOGGERS:
        lg = logging.getLogger(name)
        lg.setLevel(logging.WARNING)
        if not any(isinstance(f, SecretMaskingFilter) for f in lg.filters):
            lg.addFilter(flt)
    for handler in logging.getLogger().handlers:
        if not any(isinstance(f, SecretMaskingFilter) for f in handler.filters):
            handler.addFilter(flt)
