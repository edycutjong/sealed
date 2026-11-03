#!/usr/bin/env python3
"""Performance gate over corpus/bench.json (the 29 recorded OutLayer runs).

Fails if any run used more than half of a worker-enforced limit (instructions, wall time, memory) or if the
request→verdict p95 exceeds the budget. Half is the day-0 headroom rule; the numbers are printed either way.
"""
import json, sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent / "corpus" / "bench.json"
MAX_PCT = 50.0
VERDICT_P95_S = 30.0

s = json.loads(BENCH.read_text())["summary"]
checks = [
    ("instructions max % of 2e9", s["instructions"]["max_pct_of_limit"], MAX_PCT),
    ("wall time max % of 120 s", s["time_ms"]["max_pct_of_limit"], MAX_PCT),
    ("peak memory max % of 512 MB", s["verifier_peak_mem_bytes"]["max_pct_of_limit"], MAX_PCT),
    ("request→verdict p95 (s)", s["verdict_s"]["p95"], VERDICT_P95_S),
]
bad = 0
for name, value, budget in checks:
    ok = value <= budget
    bad += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name:32s} {value:>8} ≤ {budget}")
print(f"perf: {len(checks) - bad}/{len(checks)} within budget over {s['runs']} runs")
sys.exit(1 if bad else 0)
