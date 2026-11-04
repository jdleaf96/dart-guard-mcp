"""설정 로딩. 비밀값은 환경변수 또는 프로젝트 루트의 .env에서만 읽는다."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _default_home() -> Path:
    env = os.environ.get("DART_MCP_HOME")
    if env:
        return Path(env).expanduser().resolve()
    # src 레이아웃에서 개발 설치(editable)로 실행 중이면 프로젝트 루트를 쓴다.
    project_root = Path(__file__).resolve().parents[2]
    if (project_root / "pyproject.toml").exists():
        return project_root
    return Path.home() / ".dart-guard-mcp"


def _load_dotenv(path: Path) -> None:
    """아주 단순한 .env 파서. 이미 설정된 환경변수는 덮어쓰지 않는다."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    home: Path
    data_dir: Path
    log_dir: Path
    daily_budget: int          # 서버 자체 DART 일일 호출 한도 (공식 한도보다 낮게)
    calls_per_minute: int      # 전체 도구 호출 분당 한도
    http_timeout_sec: float

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cache.sqlite3"

    @property
    def audit_path(self) -> Path:
        return self.log_dir / "audit.jsonl"


def load_settings() -> Settings:
    home = _default_home()
    _load_dotenv(home / ".env")
    settings = Settings(
        home=home,
        data_dir=home / "data",
        log_dir=home / "logs",
        daily_budget=_int_env("DART_DAILY_BUDGET", 2000),
        calls_per_minute=_int_env("DART_CALLS_PER_MINUTE", 30),
        http_timeout_sec=float(os.environ.get("DART_HTTP_TIMEOUT", "15")),
    )
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    return settings
