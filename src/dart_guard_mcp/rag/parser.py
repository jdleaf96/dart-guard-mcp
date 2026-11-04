"""DART 공시 원문 → 섹션 목록.

DART 원문은 두 형식이다.
- 정기보고서 등: dart4.xsd 형식의 XML. 하지만 본문에 이스케이프되지 않은 '&'(예: R&D)가 있어
  올바른 XML이 아니다. 엄격한 XML 파서는 첫 페이지에서 실패한다.
- 거래소 공시 등: HTML (meta는 euc-kr이라고 적혀 있어도 실제로는 UTF-8인 경우가 있음)

그래서 둘 다 표준 라이브러리 html.parser로 관대하게 읽는다. html.parser는 DTD·외부 엔티티를
처리하지 않으므로 XXE 위험이 없다. 화면에 보이지 않는 부분(주석, style/script, display:none)은
사람이 볼 수 없는 텍스트이므로 버리고, 버린 사실은 hidden_removed로 남긴다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_SKIP = {"style", "script", "head", "noscript", "template", "extraction", "summary", "formula-version", "colgroup", "col"}
_BLOCK = {"p", "br", "div", "tr", "table", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pgbrk", "cover-title",
          "section-1", "section-2", "section-3", "library", "table-group", "tbody", "thead", "img-caption"}
_CELL = {"td", "th", "te", "tu"}
_VOID = {"br", "img", "meta", "link", "input", "hr", "col", "pgbrk", "image"}
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(\D|$)", re.I)


@dataclass
class Section:
    path: str  # 예: "III. 재무에 관한 사항 > 2. 연결재무제표"
    text: str


@dataclass
class ParsedDocument:
    name: str
    company: str
    sections: list[Section]
    hidden_removed: int = 0
    files: list[str] = field(default_factory=list)


def decode(data: bytes) -> str:
    for enc in ("utf-8", "cp949"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


class _DartHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sections: list[Section] = []
        self.doc_name = ""
        self.company = ""
        self.html_title = ""
        self.hidden_removed = 0
        self._buf: list[str] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._skip_stack: list[str] = []
        self._capture: str | None = None  # title/document-name/company-name 캡처 중
        self._capture_buf: list[str] = []
        self._level = 0
        self._heads: list[str] = []
        self._title_level = 0

    # --- 섹션 관리 ---
    def _flush(self) -> None:
        text = "".join(self._buf)
        text = re.sub(r"[ \t 　]+", " ", text)
        text = "\n".join(l.strip() for l in text.split("\n"))
        text = re.sub(r"\n{2,}", "\n", text).strip()
        if text:
            self.sections.append(Section(" > ".join(self._heads) or (self.html_title or "본문"), text))
        self._buf = []

    def _emit(self, s: str) -> None:
        if self._cell is not None:
            self._cell.append(s)
        else:
            self._buf.append(s)

    # --- HTMLParser 콜백 ---
    def handle_starttag(self, tag: str, attrs) -> None:
        if self._skip_stack:
            if tag not in _VOID:
                self._skip_stack.append(tag)
            return
        style = dict(attrs).get("style") or ""
        if tag in _SKIP or (_HIDDEN_STYLE.search(style) and tag not in _VOID):
            if tag not in _SKIP:
                self.hidden_removed += 1
            if tag not in _VOID:
                self._skip_stack.append(tag)
            return
        if tag.startswith("section-") and tag[8:].isdigit():
            self._level = int(tag[8:])
        if tag in {"title", "document-name", "company-name"}:
            self._capture, self._capture_buf = tag, []
            return
        if tag == "tr":
            self._row = []
        elif tag in _CELL:
            self._cell = []
        elif tag in _BLOCK:
            self._emit("\n")

    def handle_endtag(self, tag: str) -> None:
        if self._skip_stack:
            if tag == self._skip_stack[-1]:
                self._skip_stack.pop()
            elif tag in self._skip_stack:  # 닫는 태그가 어긋난 경우 복구
                while self._skip_stack and self._skip_stack.pop() != tag:
                    pass
            return
        if self._capture == tag:
            value = re.sub(r"\s+", " ", "".join(self._capture_buf)).strip()
            self._capture = None
            if tag == "document-name":
                self.doc_name = value
            elif tag == "company-name":
                self.company = value
            elif tag == "title" and value:
                if not self.sections and not self._heads and self.html_title == "" and self._level == 0:
                    self.html_title = value  # HTML <head><title> 또는 최상위 제목
                self._flush()
                level = max(self._level, 1)
                self._heads = self._heads[: level - 1] + [value]
            return
        if tag in _CELL and self._cell is not None:
            cell = re.sub(r"\s+", " ", "".join(self._cell)).strip()
            self._cell = None
            if self._row is not None:
                self._row.append(cell)
            else:
                self._buf.append(cell + " ")
        elif tag == "tr" and self._row is not None:
            cells = [c for c in self._row if c]
            if cells:
                self._buf.append("\n" + " | ".join(cells) + "\n")
            self._row = None
        elif tag.startswith("section-") and tag[8:].isdigit():
            self._level = max(int(tag[8:]) - 1, 0)
        elif tag in _BLOCK:
            self._emit("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_stack:
            if data.strip():
                pass
            return
        if self._capture:
            self._capture_buf.append(data)
        else:
            self._emit(data)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.hidden_removed += 1  # 주석은 사람에게 보이지 않으므로 버린다

    def close(self) -> None:
        super().close()
        self._flush()


def parse_document(data: bytes) -> ParsedDocument:
    parser = _DartHTMLParser()
    parser.feed(decode(data))
    parser.close()
    # HTML 문서의 <head><title>은 head를 건너뛰므로 여기서 따로 찾는다.
    name = parser.doc_name or parser.html_title
    if not name:
        m = re.search(rb"<title[^>]*>(.*?)</title>", data[:5000], re.I | re.S)
        name = re.sub(r"\s+", " ", decode(m.group(1))).strip() if m else ""
    return ParsedDocument(name=name, company=parser.company, sections=parser.sections,
                          hidden_removed=parser.hidden_removed)
