"""DART가 주는 zip·XML을 안전하게 다룬다.

- zip은 디스크에 풀지 않고 메모리에서 읽는다 (경로 순회 파일명이 있어도 영향 없음).
- 파일 수·압축 해제 크기·압축률 상한으로 압축 폭탄을 막는다.
- XML은 defusedxml로 파싱해 외부 엔티티(XXE)·엔티티 폭탄을 막는다.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

from defusedxml import ElementTree as SafeET


class UnsafeArchive(ValueError):
    pass


@dataclass(frozen=True)
class ArchiveLimits:
    max_files: int = 50
    max_total_bytes: int = 30 * 1024 * 1024
    max_ratio: int = 200  # 압축 해제 크기 / 압축 크기


def read_zip(data: bytes, limits: ArchiveLimits = ArchiveLimits()) -> dict[str, bytes]:
    """zip을 {파일명: 내용}으로 돌려준다. 파일명은 식별용일 뿐 경로로 쓰지 않는다."""
    if len(data) > limits.max_total_bytes:
        raise UnsafeArchive("압축 파일이 너무 큽니다.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsafeArchive("올바른 zip 파일이 아닙니다.") from exc

    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > limits.max_files:
        raise UnsafeArchive(f"파일 수가 상한({limits.max_files})을 넘습니다.")

    declared = sum(i.file_size for i in infos)
    if declared > limits.max_total_bytes:
        raise UnsafeArchive("압축 해제 크기가 상한을 넘습니다.")

    out: dict[str, bytes] = {}
    total = 0
    for info in infos:
        if info.compress_size and info.file_size / info.compress_size > limits.max_ratio:
            raise UnsafeArchive("압축률이 비정상적으로 높습니다 (압축 폭탄 의심).")
        # 헤더에 적힌 크기를 믿지 않고 실제로 읽으면서도 상한을 확인한다.
        with zf.open(info) as fh:
            chunk = fh.read(limits.max_total_bytes - total + 1)
        total += len(chunk)
        if total > limits.max_total_bytes:
            raise UnsafeArchive("압축 해제 크기가 상한을 넘습니다.")
        name = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
        out[name] = chunk
    return out


def parse_xml(data: bytes):
    """defusedxml로 파싱. DTD·외부 엔티티가 있으면 예외."""
    try:
        return SafeET.fromstring(data, forbid_dtd=True)
    except Exception as exc:  # defusedxml 예외들과 ParseError
        raise UnsafeArchive(f"XML 파싱 거부: {type(exc).__name__}") from exc
