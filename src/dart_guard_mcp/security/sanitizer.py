"""외부 텍스트(공시 원문 등)의 프롬프트 인젝션 탐지·무력화.

원칙: 이 정제기는 '보조 방어'다. 규칙 기반 탐지는 언제든 우회될 수 있으므로,
진짜 방어는 서버가 읽기 전용이라 인젝션이 성공해도 할 수 있는 일이 없다는 구조에 있다.

처리 순서
1. 보이지 않는 문자 제거 (zero-width, 양방향 제어, 유니코드 태그 문자)
   - 태그 문자(U+E0000~E007F)는 ASCII를 숨겨 넣는 데 쓰이므로 해독해서 탐지 대상에 포함
2. 줄 단위로 NFKC 정규화 + 소문자화한 사본에서 패턴 탐지
3. 걸린 줄은 통째로 '[차단됨: ...]' 표시로 교체 (부분 치환보다 우회가 어렵고 결과가 예측 가능)

오탐을 줄이기 위해 패턴은 'AI/모델에게 말을 거는 문장'에 맞춘다.
예) "이사회 결의로 이전 결정을 철회" 같은 정상 공시 문장은 걸리지 않아야 한다.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

_INVISIBLE = re.compile(
    "[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]"
)
_TAG_CHARS = re.compile("[\U000e0020-\U000e007e]+")

_AI = r"(ai|a\.i\.|assistant|어시스턴트|챗봇|언어\s*모델|llm|gpt|claude|클로드|모델|에이전트|agent)"

PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "instruction_override": [
        re.compile(r"(이전|위의|앞의|기존|모든)\s*(지시|명령|지침|프롬프트|규칙|instruction)\S{0,4}\s*(을|를|은|는)?\s*(모두\s*)?(무시|잊|따르지\s*마)"),
        re.compile(r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions?|prompts?|rules?|messages?|directions?)"),
        re.compile(r"(지시|명령|지침)\S{0,3}\s*(대신|말고)\s*(다음|아래|이것)"),
        re.compile(r"new\s+instructions?\s*:"),
    ],
    "role_injection": [
        re.compile(r"<\s*/?\s*(system|assistant|user|im_start|im_end)\s*>"),
        re.compile(r"\[\s*/?\s*(inst|system)\s*\]"),
        re.compile(r"^\s*#{2,}\s*(system|assistant|instruction)"),
        re.compile(r"(너는|당신은|넌)\s*이제(부터)?\s"),
        re.compile(r"you\s+are\s+now\s+"),
        re.compile(r"(act|behave|respond)\s+as\s+(an?\s+)?(unrestricted|jailbroken|different|new)"),
        re.compile(r"개발자\s*모드|developer\s+mode|jailbreak|탈옥"),
    ],
    "system_prompt_reference": [
        re.compile(r"(시스템|system)\s*(프롬프트|prompt|메시지|message)"),
    ],
    "ai_directed_command": [
        re.compile(_AI + r"\s*(은|는|이|가|에게|야|님)?\s*[,:]?\s*.{0,20}(반드시|무조건|지금\s*바로|즉시)\s*.{0,30}(하라|해라|하세요|하십시오|할\s*것|말할\s*것)"),
        re.compile(r"(이\s*문서|이\s*공시|본\s*문서)\S{0,3}\s*(를|을)?\s*(읽는|요약하는|분석하는)\s*" + _AI),
        re.compile(r"(to|dear|attention)\s+(the\s+)?(ai|assistant|llm|language\s+model|agent)\b"),
        re.compile(r"(when|if)\s+(you\s+are\s+)?(summariz|analyz|read)\w*\s+this"),
    ],
    "tool_invocation": [
        # 공시에 'AI 도구를 호출/실행하라'는 문장이 나올 이유가 없다 (활용형 호출하여·실행해 포함)
        re.compile(r"(도구|툴|tool|function)\S{0,3}\s*(을|를)?\s*.{0,10}(호출|실행)(하|해|시키|하여)"),
        re.compile(r"\b(call|invoke|execute|run)\s+(the\s+)?(tool|function)\b"),
    ],
    "exfiltration": [
        re.compile(r"(send|post|upload|forward|전송|보내|업로드)\S{0,6}\s*.{0,30}(https?://|www\.|@[a-z0-9-]+\.[a-z]{2,})"),
        # 어순이 반대인 경우: "대화 내용을 http://... 로 보내세요"
        re.compile(r"(https?://|www\.)\S+.{0,15}(보내|전송|업로드|send|post|upload)"),
        # 대화·사용자 정보를 내보내라는 문장
        re.compile(r"(대화|사용자|유저|conversation|chat|user)\S{0,3}\s*(내용|기록|정보|이력|history|data|log)\S{0,3}\s*.{0,20}(전송|보내|유출|업로드|send|upload|exfiltrat)"),
        re.compile(r"!\[[^\]]*\]\(\s*https?://"),  # 마크다운 이미지로 데이터 빼내기
    ],
    "encoded_blob": [
        re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
    ],
}


@dataclass
class SanitizeResult:
    text: str
    flags: set[str] = field(default_factory=set)
    redactions: int = 0
    invisible_removed: int = 0


def _detect(line: str) -> list[str]:
    norm = unicodedata.normalize("NFKC", line).lower()
    return [cat for cat, pats in PATTERNS.items() if any(p.search(norm) for p in pats)]


def _decode_tag_chars(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for m in _TAG_CHARS.finditer(text) for c in m.group(0))


def sanitize(text: str) -> SanitizeResult:
    result = SanitizeResult(text="")
    if not text:
        return result

    hidden = _decode_tag_chars(text)
    if hidden:
        result.flags.add("unicode_tag_smuggling")
        result.flags.update(_detect(hidden))

    cleaned, n = _INVISIBLE.subn("", text)
    if n:
        result.invisible_removed = n
        result.flags.add("invisible_unicode")

    out_lines = []
    for line in cleaned.split("\n"):
        cats = _detect(line)
        if cats:
            result.flags.update(cats)
            result.redactions += 1
            out_lines.append(f"[차단됨: 의심스러운 지시문 ({', '.join(cats)})]")
        else:
            out_lines.append(line)
    result.text = "\n".join(out_lines)
    return result
