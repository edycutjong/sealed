"""Tests for scripts/perf_gate.py: the gate runs at import time, so each case executes it via runpy with
Path.read_text patched to return a synthetic bench summary."""
import json
import os
import runpy
from pathlib import Path

import pytest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                      "scripts", "perf_gate.py")


def summary(ins=10.0, tm=10.0, mem=10.0, p95=5.0, runs=29):
    return {"summary": {
        "runs": runs,
        "instructions": {"max_pct_of_limit": ins},
        "time_ms": {"max_pct_of_limit": tm},
        "verifier_peak_mem_bytes": {"max_pct_of_limit": mem},
        "verdict_s": {"p95": p95},
    }}


def run_gate(monkeypatch, data):
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: json.dumps(data))
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(SCRIPT, run_name="__main__")
    return exc.value.code


def test_all_within_budget_exits_zero(monkeypatch, capsys):
    assert run_gate(monkeypatch, summary()) == 0
    out = capsys.readouterr().out
    assert out.count("PASS") == 4
    assert "FAIL" not in out
    assert "perf: 4/4 within budget over 29 runs" in out


def test_boundary_values_pass(monkeypatch, capsys):
    assert run_gate(monkeypatch, summary(50.0, 50.0, 50.0, 30.0, runs=3)) == 0
    assert "perf: 4/4 within budget over 3 runs" in capsys.readouterr().out


@pytest.mark.parametrize("kwargs,label", [
    ({"ins": 50.1}, "instructions max % of 2e9"),
    ({"tm": 75}, "wall time max % of 120 s"),
    ({"mem": 99}, "peak memory max % of 512 MB"),
    ({"p95": 31.5}, "request→verdict p95 (s)"),
])
def test_single_breach_fails(monkeypatch, capsys, kwargs, label):
    assert run_gate(monkeypatch, summary(**kwargs)) == 1
    out = capsys.readouterr().out
    fail_lines = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
    assert len(fail_lines) == 1 and label in fail_lines[0]
    assert "perf: 3/4 within budget" in out


def test_all_breached(monkeypatch, capsys):
    assert run_gate(monkeypatch, summary(60, 60, 60, 60)) == 1
    assert "perf: 0/4 within budget" in capsys.readouterr().out


def test_real_bench_file_passes():
    """The committed corpus/bench.json must satisfy the gate (read-only)."""
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(SCRIPT, run_name="__main__")
    assert exc.value.code == 0
