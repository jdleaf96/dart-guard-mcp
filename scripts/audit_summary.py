"""감사 로그(logs/audit.jsonl) 요약: 도구별 호출 수, 상태, DART 호출 수, 캐시 적중, 인젝션 탐지."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "logs" / "audit.jsonl"
records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

by_tool: dict[str, Counter] = defaultdict(Counter)
flags: Counter = Counter()
for r in records:
    c = by_tool[r.get("tool", "?")]
    c["calls"] += 1
    c[r.get("status", "unknown")] += 1
    c["upstream"] += r.get("upstream_calls", 0) or 0
    c["cache"] += r.get("cache_hits", 0) or 0
    for f in r.get("injection_flags") or []:
        flags[f] += 1

cols = ["calls", "ok", "not_found", "rejected", "rate_limited", "upstream_error", "upstream", "cache"]
print(f"감사 로그: {path} ({len(records)}건, 세션 {len({r.get('session') for r in records})}개)\n")
print(f"{'tool':<22}" + "".join(f"{c:>15}" for c in cols))
for tool, c in sorted(by_tool.items()):
    print(f"{tool:<22}" + "".join(f"{c.get(k, 0):>15}" for k in cols))
if flags:
    print("\n인젝션 탐지 플래그:", dict(flags))
