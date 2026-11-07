"""Unit tests for scripts/bench.py: percentiles, row building, chain re-read and the main() check/write flow."""
import base64
import json
import os
import runpy

import pytest

import bench

URL = "http://rpc.invalid"


def make_ev(label="r1", paid=False, expired=False, dt=2_000_000_000, instr=100, ms=50, lim=None):
    lim = lim or {"mem": 1000, "i": 2000, "m": 1, "s": 10}
    ev = {
        "label": label,
        "execution_requested": {"timestamp": 5_000_000_000},
        "execution_completed": [{"data": [{"timestamp": 5_000_000_000 + dt}]}],
        "resolve": {"args": {"response": {"resources_used": {"instructions": instr, "time_ms": ms}}},
                    "tx": "TX", "signer": "worker", "method": "resolve_execution", "block_height": 77},
        "verdict_output": json.dumps({"lim": lim}),
        "deliver_logs": ["PAID 1 NEAR"] if paid else [],
        "commit_tx_status": {"transaction_outcome": {"block_hash": "BC"}},
    }
    if expired:
        ev["expire_tx"] = "EXP"
    if paid:
        ev["deliver_tx_status"] = {
            "transaction_outcome": {"block_hash": "BD"},
            "receipts_outcome": [{"block_hash": "BX", "outcome": {"logs": ["nothing"]}},
                                 {"block_hash": "BP", "outcome": {"logs": ["PAID 1 NEAR"]}}]}
    return ev


def tx_result(instr=100, ms=50, method="resolve_execution"):
    args = base64.b64encode(json.dumps({"response": {"resources_used": {"instructions": instr, "time_ms": ms}}}).encode()).decode()
    return {"result": {"transaction": {"actions": [{"Transfer": {}}, {"FunctionCall": {"method_name": method, "args": args}}]}}}


TS = {"BC": 10_000_000_000, 77: 13_000_000_000, "BP": 20_000_000_000, "BD": 15_000_000_000}


@pytest.fixture(autouse=True)
def _nosleep(monkeypatch):
    monkeypatch.setattr(bench.time, "sleep", lambda _s: None)


@pytest.fixture
def fake_rpc(monkeypatch):
    def rpc(method, params, url):
        if method == "status":
            return {"result": {}}
        return {"result": {"header": {"timestamp": TS[params["block_id"]]}}}
    monkeypatch.setattr(bench.near, "rpc", rpc)
    monkeypatch.setattr(bench.near, "tx", lambda tx, signer, url: tx_result())


def test_pct_and_stats():
    assert bench.pct(list(range(1, 30)), 95) == 28
    assert bench.pct([5], 50) == 5
    assert bench.pct([3, 1, 2], 0) == 1
    assert bench.stats([1, 2, 3]) == {"n": 3, "p50": 2, "p95": 3, "max": 3}
    assert bench.stats([50], 200)["max_pct_of_limit"] == 25.0


def test_kind():
    assert bench.kind({"deliver_logs": ["x", "PAID 2"]}) == "PAID"
    assert bench.kind({"deliver_logs": None, "expire_tx": "t"}) == "EXPIRED"
    assert bench.kind({}) == "REFUSED"


def test_offline_row():
    row = bench.offline_row(make_ev(paid=True, dt=2_345_000_000))
    assert row == {"label": "r1", "kind": "PAID", "verdict_s": 2.35, "instructions": 100, "time_ms": 50,
                   "mem_bytes": 1000, "lim": {"i": 2000, "m": 1, "s": 10}}


def test_block_ts(fake_rpc):
    assert bench.block_ts("BC", URL) == 10_000_000_000


def test_block_ts_missing_result(monkeypatch):
    monkeypatch.setattr(bench.near, "rpc", lambda *a: {"error": "boom"})
    with pytest.raises(RuntimeError, match="block BC"):
        bench.block_ts("BC", URL)


def test_chain_row_paid(fake_rpc):
    ev = make_ev(paid=True)
    out, bad = bench.chain_row(ev, bench.offline_row(ev), URL)
    assert bad == []
    assert out == {"label": "r1", "commit_to_verdict_s": 3.0, "commit_to_paid_s": 10.0, "deliver_to_paid_s": 5.0}


def test_chain_row_refused_no_paid_fields(fake_rpc):
    ev = make_ev()
    out, bad = bench.chain_row(ev, bench.offline_row(ev), URL)
    assert bad == [] and out == {"label": "r1", "commit_to_verdict_s": 3.0}


def test_chain_row_tx_not_found(monkeypatch):
    monkeypatch.setattr(bench.near, "tx", lambda *a: {"error": "x"})
    ev = make_ev()
    out, bad = bench.chain_row(ev, bench.offline_row(ev), URL)
    assert out == {} and bad == ["resolve tx TX not found"]


def test_chain_row_mismatch_and_no_method(fake_rpc, monkeypatch):
    ev = make_ev()
    row = bench.offline_row(ev)
    monkeypatch.setattr(bench.near, "tx", lambda *a: tx_result(instr=1))
    _, bad = bench.chain_row(ev, row, URL)
    assert len(bad) == 1 and "!= bundle 100/50" in bad[0]
    monkeypatch.setattr(bench.near, "tx", lambda *a: tx_result(method="other"))
    _, bad = bench.chain_row(ev, row, URL)
    assert len(bad) == 1 and "None" in bad[0]


def test_summarize_and_chain_summary():
    rows = [bench.offline_row(make_ev(label="a", dt=1_000_000_000)), bench.offline_row(make_ev(label="b", dt=3_000_000_000))]
    s = bench.summarize(rows)
    assert s["runs"] == 2 and s["enforced_limits"] == {"i": 2000, "m": 1, "s": 10}
    assert s["verdict_s"]["max"] == 3.0
    assert s["instructions"]["max_pct_of_limit"] == 5.0
    assert s["time_ms"]["max_pct_of_limit"] == 0.5
    assert s["verifier_peak_mem_bytes"]["max_pct_of_limit"] == round(100 * 1000 / (1 << 20), 2)
    rows[1]["lim"] = {"i": 1, "m": 1, "s": 1}
    with pytest.raises(SystemExit, match="different enforced limits"):
        bench.summarize(rows)
    cs = bench.chain_summary([{"commit_to_verdict_s": 1.0},
                              {"commit_to_verdict_s": 2.0, "commit_to_paid_s": 4.0, "deliver_to_paid_s": 1.0}])
    assert cs["runs"] == 2 and cs["commit_to_paid_s"]["n"] == 1 and cs["deliver_to_paid_s"]["max"] == 1.0
    assert "commit_to_paid_s" not in bench.chain_summary([{"commit_to_verdict_s": 1.0}])


def test_line():
    s = bench.stats([1, 2], 10)
    assert bench.line("x", s, " s").endswith("max 2 s · max 20.0% of limit")
    assert "% of limit" not in bench.line("x", bench.stats([1]))


@pytest.fixture
def env(tmp_path, monkeypatch):
    (tmp_path / "corpus" / "evidence").mkdir(parents=True)
    monkeypatch.setattr(bench, "ROOT", str(tmp_path))
    monkeypatch.setattr(bench, "OUT", str(tmp_path / "corpus" / "bench.json"))
    monkeypatch.setattr(bench.sys, "argv", ["bench"])

    def put(*evs):
        for ev in evs:
            (tmp_path / "corpus" / "evidence" / f"{ev['label']}.json").write_text(json.dumps(ev))
    return tmp_path, put


def argv(monkeypatch, *args):
    monkeypatch.setattr(bench.sys, "argv", ["bench", *args])


def test_main_empty(env, capsys):
    assert bench.main() == 1
    assert "empty bundle" in capsys.readouterr().out


def test_main_missing_record(env, capsys):
    _, put = env
    put(make_ev())
    assert bench.main() == 1
    out = capsys.readouterr().out
    assert "bench: 1 testnet runs · limits 2,000 instructions / 1 MB / 10 s" in out
    assert "FAIL corpus/bench.json missing" in out


def test_main_write_then_check(env, capsys, monkeypatch):
    tmp, put = env
    put(make_ev(label="a"), make_ev(label="b", paid=True))
    argv(monkeypatch, "--write")
    assert bench.main() == 0
    assert "wrote corpus/bench.json" in capsys.readouterr().out
    rec = json.loads((tmp / "corpus" / "bench.json").read_text())
    assert rec["summary"]["runs"] == 2 and [r["label"] for r in rec["rows"]] == ["a", "b"]
    argv(monkeypatch)
    assert bench.main() == 0
    assert "recomputed numbers = corpus/bench.json" in capsys.readouterr().out
    put(make_ev(label="c", dt=9_000_000_000))
    assert bench.main() == 1
    out = capsys.readouterr().out
    assert "FAIL summary differs" in out and "FAIL rows differs" in out


def test_main_chain_write_and_recorded(env, capsys, monkeypatch, fake_rpc):
    tmp, put = env
    put(make_ev(label="a"), make_ev(label="b", paid=True))
    argv(monkeypatch, "--chain", "--write", "--rpc", URL)
    assert bench.main() == 0
    out = capsys.readouterr().out
    assert "chain: 2 resolve txs re-read · resources_used match the bundle" in out
    assert "commit→verdict (blocks)" in out and "deliver→paid (blocks)" in out
    # offline check keeps the recorded chain section and prints it
    argv(monkeypatch)
    assert bench.main() == 0
    out = capsys.readouterr().out
    assert "recorded chain block-time" in out and "commit→paid (blocks)" in out
    # chain check against the committed record passes
    argv(monkeypatch, "--chain")
    assert bench.main() == 0
    assert "(incl. chain re-read)" in capsys.readouterr().out


def test_main_chain_mismatch(env, capsys, monkeypatch, fake_rpc):
    _, put = env
    put(make_ev())
    monkeypatch.setattr(bench.near, "tx", lambda *a: tx_result(instr=7))
    argv(monkeypatch, "--chain", "--write")
    assert bench.main() == 1
    out = capsys.readouterr().out
    assert "MISMATCH" in out and "FAIL r1: resources_used on chain" in out


def test_main_chain_rpc_unreachable(env, capsys, monkeypatch):
    _, put = env
    put(make_ev())

    def boom(*a):
        raise OSError("down")
    monkeypatch.setattr(bench.near, "rpc", boom)
    argv(monkeypatch, "--chain")
    assert bench.main() == 2
    assert "exit 2: archival RPC" in capsys.readouterr().out


def test_main_chain_rpc_fails_midway(env, capsys, monkeypatch):
    tmp, put = env
    put(make_ev())
    monkeypatch.setattr(bench.near, "rpc", lambda *a: {"result": {}})

    def boom(*a):
        raise OSError("429")
    monkeypatch.setattr(bench.near, "tx", boom)
    argv(monkeypatch, "--chain", "--write")
    assert bench.main() == 2
    assert "failed at r1 (429)" in capsys.readouterr().out
    assert not (tmp / "corpus" / "bench.json").exists()


def test_dunder_main(env, monkeypatch):
    monkeypatch.setattr(bench.sys, "argv", ["bench"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(bench.__file__, run_name="__main__")
    assert e.value.code in (0, 1)
    assert os.path.exists(bench.__file__)
