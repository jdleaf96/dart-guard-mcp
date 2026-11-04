"""공시 1건 단위 색인·검색·인용 검증.

- 수집: 원문 zip → 파싱 → 정제(sanitizer) → 청크 → SQLite 저장. 정제 전 텍스트는 저장하지 않는다.
- 임베딩: 처음 검색할 때만 계산 (get_disclosure·verify_quote는 임베딩 없이 동작)
- 검색: 벡터 유사도 + 글자 bigram 일치도를 RRF로 합친 하이브리드
  (한국어 공시는 "유상증자", "자금조달" 같은 정확한 용어 일치가 중요하다)
- 저장소: 공시 1건 안에서만 검색하므로 청크가 수천 개 수준이다. 전수 비교(numpy)로 충분해서
  별도 벡터 DB를 두지 않았다.

공시는 접수 후 바뀌지 않으므로(정정 공시는 새 rcept_no) rcept_no 기준 영구 캐시가 안전하다.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

import numpy as np

from ..security.sanitizer import sanitize
from .parser import parse_document

CHUNK_CHARS = 600
OVERLAP_CHARS = 100
MAX_INDEX_CHARS = 1_500_000
CANDIDATES = 60  # 키워드 단계에서 고르는 후보 수
MAX_SEQ_TOKENS = 256  # CPU 속도를 위해 줄임 (청크 600자 ≈ 280토큰, 뒤쪽 일부는 키워드 점수가 보완)
DEFAULT_MODEL = "intfloat/multilingual-e5-small"


@dataclass
class DocInfo:
    rcept_no: str
    name: str
    company: str
    files: list[str]
    outline: list[str]
    n_chunks: int
    total_chars: int
    truncated: bool
    flags: list[str]
    redactions: int
    hidden_removed: int


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", unicodedata.normalize("NFKC", text)).lower()


def _bigrams(text: str) -> set[str]:
    t = _norm(text)
    return {t[i : i + 2] for i in range(len(t) - 1)} if len(t) > 1 else {t}


def chunk_text(text: str, size: int = CHUNK_CHARS, overlap: int = OVERLAP_CHARS) -> list[str]:
    chunks: list[str] = []
    cur = ""
    for line in text.split("\n"):
        while len(line) > size:  # 아주 긴 한 줄은 강제로 자른다
            head, line = line[:size], line[size - overlap :]
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(head)
        if cur and len(cur) + 1 + len(line) > size:
            chunks.append(cur)
            tail = cur[-overlap:]
            cur = tail[tail.find("\n") + 1 :] if "\n" in tail else ""
        cur = f"{cur}\n{line}" if cur else line
    if cur.strip():
        chunks.append(cur)
    return [c.strip() for c in chunks if c.strip()]


class Embedder:
    """sentence-transformers 모델을 처음 쓸 때 한 번만 로딩한다."""

    _lock = threading.Lock()
    _model = None

    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or os.environ.get("EMBED_MODEL", DEFAULT_MODEL)
        self._e5 = "e5" in self.model_name.lower()

    def _load(self):
        with Embedder._lock:
            if Embedder._model is None:
                from sentence_transformers import SentenceTransformer

                model = SentenceTransformer(self.model_name, device="cpu")
                model.max_seq_length = MAX_SEQ_TOKENS
                Embedder._model = model
        return Embedder._model

    def warmup(self) -> None:
        try:
            self._load()
        except Exception:  # 실패해도 첫 검색 때 다시 시도한다
            pass

    def encode(self, texts: list[str], *, query: bool) -> np.ndarray:
        prefix = ("query: " if query else "passage: ") if self._e5 else ""
        model = self._load()
        vecs = model.encode([prefix + t for t in texts], batch_size=32, normalize_embeddings=True,
                            show_progress_bar=False, convert_to_numpy=True)
        return vecs.astype(np.float32)


class DocIndex:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock, embedder: Embedder | None = None) -> None:
        self._conn, self._lock = conn, lock
        self.embedder = embedder or Embedder()
        self._vec_cache: dict[str, dict[int, np.ndarray]] = {}
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS doc_meta (rcept_no TEXT PRIMARY KEY, info TEXT NOT NULL, indexed_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS doc_chunks (
                    rcept_no TEXT NOT NULL, idx INTEGER NOT NULL, section TEXT NOT NULL, text TEXT NOT NULL,
                    flagged INTEGER NOT NULL DEFAULT 0, emb BLOB, PRIMARY KEY (rcept_no, idx));
                """
            )
            self._conn.commit()

    # --- 수집 ---------------------------------------------------------------
    def get_info(self, rcept_no: str) -> DocInfo | None:
        with self._lock:
            row = self._conn.execute("SELECT info FROM doc_meta WHERE rcept_no=?", (rcept_no,)).fetchone()
        return DocInfo(**json.loads(row[0])) if row else None

    def ingest(self, rcept_no: str, files: dict[str, bytes]) -> DocInfo:
        # 본문(rcept_no.xml)을 먼저, 첨부(감사보고서 등)를 뒤에
        names = sorted(files, key=lambda n: (not n.startswith(f"{rcept_no}.") , n))
        rows: list[tuple[Any, ...]] = []
        outline: list[str] = []
        flags: set[str] = set()
        redactions = hidden = total = 0
        truncated = False
        doc_name = company = ""
        for fname in names:
            doc = parse_document(files[fname])
            hidden += doc.hidden_removed
            doc_name = doc_name or doc.name
            company = company or doc.company
            prefix = "" if fname.startswith(f"{rcept_no}.") else f"[첨부: {doc.name or fname}] "
            for sec in doc.sections:
                if total >= MAX_INDEX_CHARS:
                    truncated = True
                    break
                clean = sanitize(sec.text)
                flags |= clean.flags
                redactions += clean.redactions
                path = prefix + sec.path
                if path not in outline:
                    outline.append(path)
                for chunk in chunk_text(clean.text):
                    rows.append((rcept_no, len(rows), path, chunk, int("[차단됨:" in chunk)))
                    total += len(chunk)
        if hidden:
            flags.add("hidden_content_removed")
        info = DocInfo(rcept_no, doc_name, company, names, outline, len(rows), total, truncated,
                       sorted(flags), redactions, hidden)
        with self._lock:
            self._conn.execute("DELETE FROM doc_chunks WHERE rcept_no=?", (rcept_no,))
            self._conn.executemany("INSERT INTO doc_chunks(rcept_no, idx, section, text, flagged) VALUES (?,?,?,?,?)", rows)
            self._conn.execute("INSERT OR REPLACE INTO doc_meta VALUES (?,?,?)",
                               (rcept_no, json.dumps(info.__dict__, ensure_ascii=False), time.time()))
            self._conn.commit()
        self._vec_cache.pop(rcept_no, None)
        return info

    def chunks(self, rcept_no: str) -> list[tuple[int, str, str, int]]:
        with self._lock:
            return self._conn.execute(
                "SELECT idx, section, text, flagged FROM doc_chunks WHERE rcept_no=? ORDER BY idx", (rcept_no,)
            ).fetchall()

    # --- 임베딩 -------------------------------------------------------------
    def _vectors(self, rcept_no: str, rows: list[tuple[int, str, str, int]]) -> np.ndarray:
        """주어진 청크들의 벡터. 저장된 것은 재사용하고, 없는 것만 계산해서 저장한다."""
        cache = self._vec_cache.setdefault(rcept_no, {})
        need = [r for r in rows if r[0] not in cache]
        if need:
            ids = [r[0] for r in need]
            with self._lock:
                stored = self._conn.execute(
                    f"SELECT idx, emb FROM doc_chunks WHERE rcept_no=? AND emb IS NOT NULL AND idx IN ({','.join('?' * len(ids))})",
                    (rcept_no, *ids),
                ).fetchall()
            for i, e in stored:
                cache[i] = np.frombuffer(e, dtype=np.float32)
            missing = [r for r in need if r[0] not in cache]
            if missing:
                vecs = self.embedder.encode([f"{s}\n{t}" for _, s, t, _ in missing], query=False)
                with self._lock:
                    self._conn.executemany(
                        "UPDATE doc_chunks SET emb=? WHERE rcept_no=? AND idx=?",
                        [(v.tobytes(), rcept_no, r[0]) for r, v in zip(missing, vecs)],
                    )
                    self._conn.commit()
                for r, v in zip(missing, vecs):
                    cache[r[0]] = v
        if len(self._vec_cache) > 8:
            self._vec_cache = {rcept_no: cache}
        return np.vstack([cache[r[0]] for r in rows])

    # --- 검색 ---------------------------------------------------------------
    def search(self, rcept_no: str, query: str, top_k: int, candidates: int = CANDIDATES) -> list[dict[str, Any]]:
        """2단계 검색: 키워드 점수로 후보를 고른 뒤, 후보만 임베딩해서 의미 점수와 RRF로 합친다.

        CPU에서 사업보고서 1건(청크 약 2,000개)을 통째로 임베딩하면 1분 이상 걸려 도구 호출이
        타임아웃될 수 있다. 후보만 임베딩하면 첫 검색도 몇 초 안에 끝나고, 임베딩은 저장되어 재사용된다.
        한계: 키워드가 전혀 겹치지 않는 의미 검색은 후보에서 빠질 수 있다.
        """
        rows = self.chunks(rcept_no)
        if not rows:
            return []
        qb = _bigrams(query)
        lex_all = np.array([len(qb & _bigrams(f"{s} {t}")) / max(len(qb), 1) for _, s, t, _ in rows])
        cand_idx = np.argsort(-lex_all, kind="stable")[: max(candidates, top_k)]
        cand_rows = [rows[i] for i in cand_idx]
        lex = lex_all[cand_idx]

        vecs = self._vectors(rcept_no, cand_rows)
        qv = self.embedder.encode([query], query=True)[0]
        vec = vecs @ qv

        k = 60  # Reciprocal Rank Fusion
        n = len(cand_rows)
        fused = np.zeros(n)
        fused[np.argsort(-vec)] += 1 / (k + np.arange(1, n + 1))
        fused[np.argsort(-lex, kind="stable")] += 1 / (k + np.arange(1, n + 1))
        best = np.argsort(-fused)[:top_k]
        return [
            {
                "chunk_id": f"{rcept_no}:{cand_rows[i][0]}",
                "section": cand_rows[i][1],
                "text": cand_rows[i][2],
                "vector_score": round(float(vec[i]), 3),
                "keyword_score": round(float(lex[i]), 3),
                "flagged": bool(cand_rows[i][3]),
            }
            for i in best
        ]

    # --- 인용 검증 ----------------------------------------------------------
    def verify(self, rcept_no: str, quote: str) -> dict[str, Any]:
        rows = self.chunks(rcept_no)
        q = _norm(quote)
        for idx, section, text, _ in rows:
            if q in _norm(text):
                return {"found": True, "match": "exact", "coverage": 1.0, "section": section,
                        "chunk_id": f"{rcept_no}:{idx}", "matched_text": text}
        # 청크 경계에 걸친 경우: 인접 청크를 이어 붙여 다시 확인
        for (i1, s1, t1, _), (_, _, t2, _) in zip(rows, rows[1:]):
            if q in _norm(t1 + t2):
                return {"found": True, "match": "exact", "coverage": 1.0, "section": s1,
                        "chunk_id": f"{rcept_no}:{i1}", "matched_text": t1 + "\n" + t2}
        qb = _bigrams(quote)
        best = max(rows, key=lambda r: len(qb & _bigrams(r[2])), default=None)
        if best is None:
            return {"found": False, "match": "none", "coverage": 0.0}
        coverage = round(len(qb & _bigrams(best[2])) / max(len(qb), 1), 3)
        return {
            "found": False,
            "match": "similar" if coverage >= 0.8 else "none",
            "coverage": coverage,
            "section": best[1],
            "chunk_id": f"{rcept_no}:{best[0]}",
            "closest_text": best[2],
            "guidance": "원문에 그대로 있는 문장이 아닙니다. 인용하지 말고, 필요하면 closest_text를 근거로 다시 쓰세요.",
        }
